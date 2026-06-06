import os
import json
from typing import Dict, Any, List

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are a Kubernetes security analyst assistant for the K8s Attack & Remediation Platform. Your role is to help users understand the security assessment data from their cluster.

You will receive current platform data (attacks, detections, remediation, cluster info, MITRE coverage) and a user question. Answer based ONLY on the data provided — do not make up information.

CRITICAL: Respond using ONLY plain text with the following formatting conventions:
- For headers/sections, use ALL CAPS on a line by itself (e.g. "ATTACK SUMMARY")
- For bold/emphasis, wrap with <b> and </b> (e.g. "<b>critical severity</b>")
- For bullet lists, start each line with "• "
- For numbered lists, use "1. " "2. " etc.
- For tables, render them using <table>, <tr>, <td> HTML tags
- For code/commands, wrap with <code> and </code>
- Use blank lines between sections for spacing
- NEVER use markdown syntax like ##, **, ```, or ---
- NEVER use markdown-style tables with pipes

Be concise but thorough. If data is missing or no attacks have been run yet, say so clearly and suggest the user deploy the cluster first."""


def build_context(platform_data: Dict[str, Any]) -> str:
    attacks = platform_data.get("attacks", [])
    alerts = platform_data.get("alerts", [])
    cluster = platform_data.get("cluster", {})
    remediation = platform_data.get("remediation", {})
    mitre_tactics = platform_data.get("mitre_tactics", [])
    infrastructure = platform_data.get("infrastructure", [])

    lines = ["## Current Platform State"]
    lines.append("")
    lines.append(f"**Cluster Ready:** {cluster.get('ready', False)}")
    lines.append(f"**Nodes:** {cluster.get('node_count', 0)}")
    lines.append(f"**Pods:** {cluster.get('pod_count', 0)}")
    lines.append("")

    if attacks:
        lines.append(f"**Total Attacks:** {len(attacks)}")
        completed = sum(1 for a in attacks if a.get('status') == 'completed')
        running = sum(1 for a in attacks if a.get('status') == 'running')
        failed = sum(1 for a in attacks if a.get('status') == 'failed')
        critical = sum(1 for a in attacks if a.get('severity') == 'critical')
        high = sum(1 for a in attacks if a.get('severity') == 'high')
        lines.append(f"**Completed:** {completed} | **Running:** {running} | **Failed:** {failed}")
        lines.append(f"**Critical:** {critical} | **High:** {high}")
        lines.append("")
        lines.append("### Attack Details")
        for a in attacks:
            sev = a.get('severity', 'unknown')
            status = a.get('status', 'pending')
            name = a.get('name', a.get('attack_id', 'Unknown'))
            lines.append(f"• **{name}** — Severity: {sev}, Status: {status}")
            if a.get('description'):
                lines.append(f"  {a['description']}")
    else:
        lines.append("**No attacks have been run yet.**")
    lines.append("")

    if alerts:
        lines.append(f"### Detection Alerts ({len(alerts)})")
        for al in alerts:
            lines.append(f"• **{al.get('rule_name', 'Unknown')}** — Severity: {al.get('severity', 'unknown')}, Resource: {al.get('resource', 'N/A')}")
        lines.append("")
    else:
        lines.append("**No detection alerts triggered.**")
        lines.append("")

    if mitre_tactics:
        lines.append("### MITRE ATT&CK Coverage")
        for t in mitre_tactics:
            covered = t.get('covered_count', 0)
            total = len(t.get('techniques', []))
            marker = "✅" if covered > 0 else "⬜"
            lines.append(f"{marker} **{t.get('id', '')}** {t.get('name', '')} — {covered}/{total} techniques")
        lines.append("")

    if remediation:
        sessions = remediation if isinstance(remediation, list) else remediation.get('sessions', [])
        if sessions:
            lines.append(f"### Remediation Sessions ({len(sessions)})")
            for s in sessions:
                status = s.get('status', 'unknown')
                incident = s.get('incident', {})
                lines.append(f"• **Session {s.get('session_id', '')[:8]}** — Status: {status}, Triggered by: {incident.get('attack_name', incident.get('name', 'Unknown'))}")
                steps = s.get('steps', [])
                if steps:
                    for step in steps:
                        if step.get('thinking'):
                            lines.append(f"  - Reasoning: {step['thinking'][:150]}...")
                        if step.get('command'):
                            lines.append(f"  - Command: `{step['command']}`")
            lines.append("")

    if infrastructure:
        lines.append(f"### Infrastructure Affected ({len(infrastructure)})")
        for item in infrastructure[:10]:
            lines.append(f"• **{item.get('resource_type', 'resource')}** — {item.get('name', '')} ({item.get('namespace', '')})")
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


async def chat_with_claude(
    message: str,
    history: List[Dict[str, str]],
    platform_data: Dict[str, Any],
) -> str:
    if not ANTHROPIC_API_KEY:
        return "Anthropic API key is not configured. Set the `ANTHROPIC_API_KEY` environment variable to enable the chatbot."

    from anthropic import AsyncAnthropic
    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    context = build_context(platform_data)

    messages = []
    for h in history:
        messages.append({"role": h.get("role", "user"), "content": h.get("content", "")})
    messages.append({"role": "user", "content": f"Here is the current platform data:\n\n{context}\n\nUser question: {message}"})

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        return response.content[0].text if response.content else "No response generated."
    except Exception as e:
        return f"Error communicating with Claude: {str(e)}"
