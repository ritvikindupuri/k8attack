import asyncio
import json
import os
import re
import subprocess
import time
import uuid
from typing import Dict, List, Optional, Callable

REMEDIATION_PROMPT = """You are a senior Kubernetes security engineer and incident responder. You are inside a live K8s attack platform and must autonomously remediate a security incident. Your thinking must be EXTREMELY DETAILED — walk through every consideration, every risk, every alternative, and justify every command.

## YOUR TASK
Analyze and remediate this incident. You have full `kubectl` access.

## THINKING REQUIREMENT — THIS IS CRITICAL
You MUST produce deep chain-of-thought reasoning before EVERY command. Each <thinking> block should cover:

1. **SITUATION ASSESSMENT**: What exactly happened? What vulnerability or misconfiguration was exploited? What is the blast radius?
2. **RISK ANALYSIS**: What resources are affected? What data or systems are at risk? What's the priority?
3. **REMEDIATION STRATEGY**: Why this particular approach? What are the alternatives considered and rejected? Why is this the best first step?
4. **COMMAND JUSTIFICATION**: Exactly what will this command do? What K8s API object does it target? What namespace? What are the side effects or risks of running it?
5. **VERIFICATION PLAN**: After executing, how will you confirm the remediation worked? What will you check next?

Be specific. Reference actual K8s resource names, namespaces, labels, and API groups. This thinking is displayed to security engineers in real-time — make it valuable for them to learn from.

## FORMAT — STRICTLY ENFORCED

<thinking>
## Situation Assessment
[Detailed analysis of the breach — what happened, entry point, exploited misconfiguration]

## Risk Analysis
[Blast radius, compromised resources, data exposure, priority assessment]

## Remediation Strategy
[Why this approach, alternatives considered, why this is the right first step]

## Command Justification
[What this kubectl command does, which API object it targets, side effects]

## Verification Plan
[How I'll confirm this step worked before proceeding]
</thinking>

<command>
kubectl [one exactly kubectl command — no shell pipes, no chaining]
</command>

<thinking>
## Situation Assessment
[Updated assessment after previous command — what changed?]

## Risk Analysis
[Re-evaluating risk — is the situation improving? what remains?]

## Remediation Strategy
[Why this next step, what it achieves, why now?]

## Command Justification
[Details about this specific command]
</thinking>

<command>
kubectl [next kubectl command]
</command>

Continue this pattern — think deeply before every single command.

Valid commands use only: kubectl with -n flags. Examples: kubectl delete pod X -n Y, kubectl delete clusterrolebinding X, kubectl delete serviceaccount X -n Y, kubectl label, kubectl annotate, kubectl rollout restart, kubectl delete deployment, kubectl delete rolebinding, kubectl delete role, kubectl delete configmap, kubectl delete secret.

## FINAL
After all remediation commands:

<summary>
## Remediation Complete
**Actions Taken**: [numbered list of every command executed and why]
**Current State**: [what is the security posture now?]
**Verification**: [how do we know this worked? what should be monitored going forward?]
**Recommendations**: [what configuration changes should be made to prevent this in the future?]
</summary>
"""


class RemediationStep:
    def __init__(self, thinking: str, command: Optional[str] = None):
        self.thinking = thinking
        self.command = command
        self.command_output: Optional[str] = None
        self.command_success: Optional[bool] = None
        self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "thinking": self.thinking,
            "command": self.command,
            "command_output": self.command_output,
            "command_success": self.command_success,
            "timestamp": self.timestamp,
        }


class RemediationSession:
    def __init__(self, incident: dict):
        self.session_id = str(uuid.uuid4())
        self.incident = incident
        self.steps: List[RemediationStep] = []
        self.status = "pending"  # pending, running, completed, failed
        self.summary: Optional[str] = None
        self.error: Optional[str] = None
        self.created_at = time.time()
        self.completed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "incident": self.incident,
            "steps": [s.to_dict() for s in self.steps],
            "status": self.status,
            "summary": self.summary,
            "error": self.error,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }

    def current_step_text(self) -> str:
        if self.steps:
            return self.steps[-1].thinking or ""
        return ""


class RemediationAgent:
    def __init__(self, websocket_manager, api_key: str):
        self.ws_manager = websocket_manager
        self.api_key = api_key
        self.sessions: Dict[str, RemediationSession] = {}
        self._client = None
        self._pending_approvals: Dict[str, asyncio.Event] = {}
        self._pending_exec_count: Dict[str, int] = {}
        self._session_done_events: Dict[str, asyncio.Event] = {}

    def signal_approval(self, session_id: str, step_index: int, approved: bool):
        """Called from WebSocket handler when user approves/rejects a command."""
        key = f"{session_id}:{step_index}"
        event = self._pending_approvals.pop(key, None)
        if event:
            event.approved = approved
            event.set()

    async def _request_approval(self, session: RemediationSession, step_index: int, command: str) -> bool:
        """Broadcast approval request and wait for user response with 60s timeout."""
        await self._broadcast({
            "type": "remediation_approval_required",
            "session_id": session.session_id,
            "step_index": step_index,
            "command": command,
        })

        key = f"{session.session_id}:{step_index}"
        event = asyncio.Event()
        event.approved = False
        self._pending_approvals[key] = event

        try:
            await asyncio.wait_for(event.wait(), timeout=60.0)
            return event.approved
        except asyncio.TimeoutError:
            self._pending_approvals.pop(key, None)
            return False

    @property
    def client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        return self._client

    async def trigger_remediation(self, incident: dict) -> str:
        session = RemediationSession(incident)
        self.sessions[session.session_id] = session
        session.status = "running"

        await self._broadcast({
            "type": "remediation_started",
            "session": session.to_dict(),
        })

        asyncio.create_task(self._run_remediation(session))
        return session.session_id

    async def _run_remediation(self, session: RemediationSession):
        try:
            incident = session.incident
            infrastructure_str = json.dumps(incident.get("infrastructure", []), indent=2)
            detection_str = json.dumps(incident.get("detection_events", [])[:5], indent=2)

            user_prompt = f"""## INCIDENT TO REMEDIATE

- **Incident Type**: {incident.get("type", incident.get("name", "Unknown"))}
- **Severity**: {incident.get("severity", "unknown")}
- **Description**: {incident.get("description", "")}

### Affected Infrastructure:
{infrastructure_str[:2000] if infrastructure_str else "None"}

### Recent Detection Events:
{detection_str[:2000] if detection_str else "None"}

Begin your analysis and remediation immediately."""

            await self._broadcast({
                "type": "remediation_agent_thinking",
                "session_id": session.session_id,
                "content": "🧠 Initializing Claude remediation agent...\n",
            })

            current_thinking = ""
            current_text = ""

            async with self.client.messages.stream(
                model="claude-sonnet-4-20250514",
                max_tokens=8192,
                system=REMEDIATION_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            ) as stream:
                async for text in stream.text_stream:
                    current_text += text
                    await self._process_stream_text(session, current_text, text)

            # Wait for all pending command approvals to finish
            sid = session.session_id
            if self._pending_exec_count.get(sid, 0) > 0:
                self._session_done_events[sid] = asyncio.Event()
                try:
                    await asyncio.wait_for(self._session_done_events[sid].wait(), timeout=300.0)
                except asyncio.TimeoutError:
                    pass

            await self._finalize_remediation(session, current_text)

        except Exception as e:
            session.status = "failed"
            session.error = str(e)
            await self._broadcast({
                "type": "remediation_failed",
                "session_id": session.session_id,
                "error": str(e),
            })

    async def _process_stream_text(self, session: RemediationSession, full_text: str, new_chunk: str):
        await self._broadcast({
            "type": "remediation_stream",
            "session_id": session.session_id,
            "chunk": new_chunk,
        })

        command_matches = list(re.finditer(r'<command>\s*\n?(.*?)\n?\s*</command>', full_text, re.DOTALL))
        thinking_matches = list(re.finditer(r'<thinking>\s*\n?(.*?)\n?\s*</thinking>', full_text, re.DOTALL))

        parsed_commands = len([s for s in session.steps if s.command is not None])

        if len(command_matches) > parsed_commands:
            for i in range(parsed_commands, len(command_matches)):
                cmd = command_matches[i].group(1).strip()
                thinking = ""
                # Find the thinking that preceded this command
                for tm in thinking_matches:
                    if tm.end() < command_matches[i].start():
                        thinking = tm.group(1).strip()

                step = RemediationStep(thinking=thinking, command=cmd)
                step_index = len(session.steps)
                session.steps.append(step)

                await self._broadcast({
                    "type": "remediation_command_found",
                    "session_id": session.session_id,
                    "step_index": step_index,
                    "thinking": thinking,
                    "command": cmd,
                })

                sid = session.session_id
                self._pending_exec_count[sid] = self._pending_exec_count.get(sid, 0) + 1
                asyncio.create_task(self._execute_command_with_approval(session, step, step_index))

        summary_match = re.search(r'<summary>\s*\n?(.*?)\n?\s*</summary>', full_text, re.DOTALL)
        if summary_match and session.summary is None:
            session.summary = summary_match.group(1).strip()

    async def _execute_command_with_approval(self, session: RemediationSession, step: RemediationStep, step_index: int):
        try:
            approved = await self._request_approval(session, step_index, step.command)
            if approved:
                await self._broadcast({
                    "type": "remediation_command_approved",
                    "session_id": session.session_id,
                    "step_index": step_index,
                    "command": step.command,
                })
                await self._execute_command(session, step)
            else:
                step.command_output = "Command rejected by human operator"
                step.command_success = False
                await self._broadcast({
                    "type": "remediation_command_result",
                    "session_id": session.session_id,
                    "step_index": step_index,
                    "command": step.command,
                    "output": step.command_output,
                    "success": False,
                })
        finally:
            sid = session.session_id
            self._pending_exec_count[sid] = self._pending_exec_count.get(sid, 0) - 1
            if self._pending_exec_count[sid] <= 0 and sid in self._session_done_events:
                self._session_done_events[sid].set()

    async def _execute_command(self, session: RemediationSession, step: RemediationStep):
        await self._broadcast({
            "type": "remediation_executing",
            "session_id": session.session_id,
            "step_index": len(session.steps) - 1,
            "command": step.command,
        })

        try:
            cmd_parts = step.command.strip().split()
            if cmd_parts[0] == "kubectl":
                result = await asyncio.to_thread(
                    subprocess.run, cmd_parts,
                    capture_output=True, text=True, timeout=30,
                )
                output = result.stdout or result.stderr
                success = result.returncode == 0
                step.command_output = output
                step.command_success = success
            else:
                step.command_output = "Error: Only kubectl commands are supported"
                step.command_success = False

            await self._broadcast({
                "type": "remediation_command_result",
                "session_id": session.session_id,
                "step_index": len(session.steps) - 1,
                "command": step.command,
                "output": step.command_output,
                "success": step.command_success,
            })

        except subprocess.TimeoutExpired:
            step.command_output = "Command timed out after 30s"
            step.command_success = False
            await self._broadcast({
                "type": "remediation_command_result",
                "session_id": session.session_id,
                "step_index": len(session.steps) - 1,
                "command": step.command,
                "output": step.command_output,
                "success": False,
            })
        except Exception as e:
            step.command_output = f"Error: {str(e)}"
            step.command_success = False
            await self._broadcast({
                "type": "remediation_command_result",
                "session_id": session.session_id,
                "step_index": len(session.steps) - 1,
                "command": step.command,
                "output": step.command_output,
                "success": False,
            })

    async def _finalize_remediation(self, session: RemediationSession, full_text: str):
        # Check for final summary
        summary_match = re.search(r'<summary>\s*\n?(.*?)\n?\s*</summary>', full_text, re.DOTALL)
        if summary_match and session.summary is None:
            session.summary = summary_match.group(1).strip()

        session.status = "completed"
        session.completed_at = time.time()

        await self._broadcast({
            "type": "remediation_completed",
            "session_id": session.session_id,
            "summary": session.summary or "Remediation completed",
            "steps": [s.to_dict() for s in session.steps],
        })

    async def _broadcast(self, message: dict):
        if self.ws_manager:
            await self.ws_manager.broadcast(message)

    def get_session(self, session_id: str) -> Optional[dict]:
        session = self.sessions.get(session_id)
        return session.to_dict() if session else None

    def get_sessions(self, limit: int = 20) -> List[dict]:
        sessions = sorted(
            self.sessions.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )
        return [s.to_dict() for s in sessions[:limit]]
