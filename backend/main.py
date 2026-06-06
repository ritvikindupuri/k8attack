import asyncio
import json
import os
import time
from typing import Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from report.generator import generate_report
from chat.handler import chat_with_claude, ANTHROPIC_API_KEY as CHAT_API_KEY

from cluster_manager.manager import ClusterManager
from attack_engine.engine import AttackEngine
from attack_engine.mitre import MITRE_ATTACK
from attack_engine.orchestrator import AttackOrchestrator
from detection.monitor import DetectionMonitor
from ws_manager.handler import WebSocketManager
from remediation.agent import RemediationAgent


ws_manager = WebSocketManager()
cluster_manager = ClusterManager(ws_manager)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
remediation_agent = RemediationAgent(ws_manager, ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None

def on_attack_complete(attack_data: dict):
    if remediation_agent and attack_data.get("severity") in ("high", "critical"):
        queue_remediation({
            **attack_data,
            "detection_events": detection_monitor.get_events(5),
        })

attack_engine = AttackEngine(cluster_manager, ws_manager, on_complete=on_attack_complete)
detection_monitor = DetectionMonitor(cluster_manager, ws_manager, on_alert=None)
orchestrator = AttackOrchestrator(attack_engine)

pending_remediation = asyncio.Queue()


async def remediation_worker():
    while True:
        try:
            incident = await asyncio.wait_for(pending_remediation.get(), timeout=300)
            if remediation_agent and incident:
                await remediation_agent.trigger_remediation(incident)
                await asyncio.sleep(5)
        except asyncio.TimeoutError:
            continue
        except Exception as e:
            print(f"[remediation worker] {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    worker = asyncio.create_task(remediation_worker())
    yield
    worker.cancel()
    await detection_monitor.stop_monitoring()


app = FastAPI(
    title="K8s Attack Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def queue_remediation(incident: dict):
    if remediation_agent:
        asyncio.ensure_future(pending_remediation.put(incident))
        asyncio.ensure_future(ws_manager.broadcast({
            "type": "remediation_queued",
            "incident": incident,
        }))


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "cluster_ready": cluster_manager.is_ready(),
        "ws_connections": ws_manager.connection_count,
        "remediation_ready": remediation_agent is not None,
        "timestamp": time.time(),
    }


@app.get("/api/prerequisites")
async def prerequisites():
    return await cluster_manager.check_prerequisites()


@app.post("/api/cluster/create")
async def create_cluster():
    result = await cluster_manager.create_cluster()
    return result


@app.post("/api/cluster/create-and-attack")
async def create_cluster_and_attack():
    result = await cluster_manager.create_cluster()
    if result.get("success"):
        await detection_monitor.start_monitoring()
        asyncio.create_task(orchestrator.run_all_attacks())
        result["orchestrator"] = "started"
    return result


@app.post("/api/cluster/delete")
async def delete_cluster():
    result = await cluster_manager.delete_cluster()
    return result


@app.get("/api/cluster/info")
async def cluster_info():
    info = await cluster_manager.get_cluster_info()
    return info


@app.get("/api/attacks")
async def list_attacks():
    return {"attacks": attack_engine.get_available_attacks()}


@app.get("/api/attacks/mitre")
async def mitre_mapping():
    return {"mitre_attack": MITRE_ATTACK}


@app.post("/api/attacks/run/{attack_id}")
async def run_attack(attack_id: str):
    try:
        execution_id = await attack_engine.run_attack(attack_id)
        return {"execution_id": execution_id, "status": "started"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/attacks/active")
async def active_attacks():
    return {"active": attack_engine.get_active_attacks()}


@app.get("/api/attacks/history")
async def attack_history(limit: int = Query(20, ge=1, le=100)):
    return {"history": attack_engine.get_history(limit)}


@app.post("/api/attacks/run-all")
async def run_all_attacks():
    result = await orchestrator.run_all_attacks()
    return result


@app.get("/api/attacks/orchestrator")
async def orchestrator_status():
    return orchestrator.get_status()


@app.get("/api/attacks/result/{execution_id}")
async def attack_result(execution_id: str):
    result = attack_engine.get_attack_result(execution_id)
    if not result:
        stored = attack_engine.get_attack_by_name(execution_id)
        if stored:
            return {"result": stored}
        raise HTTPException(status_code=404, detail="Attack result not found")
    return {"result": result}


@app.get("/api/detection/events")
async def detection_events(limit: int = Query(50, ge=1, le=200)):
    return {"events": detection_monitor.get_events(limit)}


@app.get("/api/detection/summary")
async def detection_summary():
    return {
        "alert_counts": detection_monitor.get_alert_summary(),
        "severity_summary": detection_monitor.get_alerts_by_severity(),
    }


@app.post("/api/detection/start")
async def start_detection():
    await detection_monitor.start_monitoring()
    return {"status": "monitoring_started"}


@app.post("/api/detection/stop")
async def stop_detection():
    await detection_monitor.stop_monitoring()
    return {"status": "monitoring_stopped"}


@app.post("/api/cluster/setup-scenarios")
async def setup_scenarios():
    await cluster_manager._setup_vulnerable_configs()
    return {"status": "scenarios_configured"}


@app.post("/api/remediation/trigger")
async def trigger_remediation(incident: dict):
    if not remediation_agent:
        raise HTTPException(status_code=503, detail="Remediation agent not configured (set ANTHROPIC_API_KEY)")
    session_id = await remediation_agent.trigger_remediation(incident)
    return {"session_id": session_id, "status": "started"}


@app.get("/api/remediation/sessions")
async def remediation_sessions(limit: int = Query(20, ge=1, le=50)):
    if not remediation_agent:
        return {"sessions": []}
    return {"sessions": remediation_agent.get_sessions(limit)}


@app.get("/api/remediation/sessions/{session_id}")
async def remediation_session(session_id: str):
    if not remediation_agent:
        raise HTTPException(status_code=503, detail="Remediation agent not configured")
    session = remediation_agent.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session": session}


@app.post("/api/remediation/auto-trigger/{execution_id}")
async def auto_trigger_remediation(execution_id: str):
    result = attack_engine.get_attack_result(execution_id)
    if not result:
        stored = attack_engine.get_attack_by_name(execution_id)
        if stored:
            result = {"result": stored}
        else:
            raise HTTPException(status_code=404, detail="Attack result not found")

    incident = {
        "type": "attack_completed",
        "name": result.get("name", "Unknown Attack"),
        "severity": result.get("severity", "unknown"),
        "description": result.get("description", ""),
        "infrastructure": result.get("infrastructure_affected", []),
        "detection_events": detection_monitor.get_events(5),
        "attack_result": result,
    }
    queue_remediation(incident)
    return {"status": "remediation_queued", "incident_type": "attack"}


class ChatRequest(BaseModel):
    message: str
    history: list = []


@app.post("/api/chat")
async def chat_endpoint(req: ChatRequest):
    if not CHAT_API_KEY:
        raise HTTPException(status_code=503, detail="Anthropic API key not configured")

    attacks = attack_engine.get_history(100)
    alerts = detection_monitor.get_events(50)
    cluster_raw = await cluster_manager.get_cluster_info()
    remediation_sessions_raw = remediation_agent.get_sessions(20) if remediation_agent else []
    infrastructure = []
    for a in attacks:
        for item in a.get("infrastructure_affected", []):
            infrastructure.append(item)

    mitre_tactics = []
    for tactic_key, tactic in MITRE_ATTACK.items():
        covered = sum(1 for a in attacks if a.get("mitre_tactic") == tactic_key)
        mitre_tactics.append({
            "id": tactic.get("id", ""),
            "name": tactic.get("name", tactic_key),
            "techniques": tactic.get("techniques", []),
            "covered_count": covered,
        })

    platform_data = {
        "attacks": attacks,
        "alerts": alerts,
        "cluster": {
            "ready": cluster_raw.get("ready", False),
            "node_count": len(cluster_raw.get("nodes", [])),
            "pod_count": len(cluster_raw.get("pods", [])),
        },
        "remediation": {"sessions": remediation_sessions_raw},
        "mitre_tactics": mitre_tactics,
        "infrastructure": infrastructure,
    }

    response = await chat_with_claude(req.message, req.history, platform_data)
    return {"response": response}


@app.get("/api/report")
async def generate_security_report():
    attacks = attack_engine.get_history(100)
    alerts = detection_monitor.get_events(100)
    alert_summary = detection_monitor.get_alert_summary()
    remediation_sessions_raw = remediation_agent.get_sessions(50) if remediation_agent else []
    orchestrator_status = orchestrator.get_status()
    cluster_info = await cluster_manager.get_cluster_info()

    mitre_tactics = []
    covered_techniques = set()
    for attack in attacks:
        if attack.get("technique"):
            covered_techniques.add(attack["technique"].lower())

    for tactic_key, tactic in MITRE_ATTACK.items():
        covered = []
        for tech in tactic.get("techniques", []):
            if tech.get("name", "").lower() in covered_techniques:
                covered.append(tech)
        mitre_tactics.append({
            "id": tactic.get("id", ""),
            "name": tactic.get("name", tactic_key),
            "techniques": tactic.get("techniques", []),
            "covered_count": len(covered),
        })

    critical_count = sum(1 for a in attacks if a.get("severity", "").lower() == "critical")
    high_count = sum(1 for a in attacks if a.get("severity", "").lower() == "high")
    completed_count = sum(1 for a in attacks if a.get("status", "").lower() in ("completed", "success"))
    failed_count = sum(1 for a in attacks if a.get("status", "").lower() == "failed")

    data = {
        "generated_at": time.time(),
        "executive_summary": {
            "summary": (
                f"This security assessment report documents the execution of {len(attacks)} real-world "
                f"Kubernetes attack techniques against a dedicated attack cluster. The assessment was "
                f"conducted using the K8s Attack & Remediation Platform, which combines automated attack "
                f"execution with real-time detection monitoring and AI-powered remediation via Claude Sonnet 4. "
                f"The goal was to evaluate the cluster's security posture by simulating adversarial behaviors "
                f"mapped to the MITRE ATT&CK for Containers framework."
            ),
            "key_findings": {
                "critical": f"{critical_count} critical-severity security issues identified, requiring immediate remediation.",
                "high": f"{high_count} high-severity issues identified, posing significant risk to cluster security.",
                "coverage": f"{len(mitre_tactics)} MITRE ATT&CK tactics covered across {len(attacks)} distinct attack techniques.",
                "remediation": f"{len(remediation_sessions_raw)} automated remediation actions executed via AI agent with step-by-step reasoning.",
            },
            "risk_score": "CRITICAL" if critical_count > 0 else ("HIGH" if high_count > 0 else "MEDIUM"),
        },
        "attacks": attacks,
        "mitre": {"tactics": mitre_tactics},
        "detection": {
            "events": alerts,
            "summary": alert_summary,
        },
        "remediation": {
            "sessions": remediation_sessions_raw,
        },
        "cluster": {
            "name": cluster_info.get("cluster_name", "k8s-attack-lab"),
            "nodes": cluster_info.get("nodes", []),
        },
        "conclusion": {
            "text": (
                f"This assessment successfully demonstrated {len(attacks)} Kubernetes attack techniques "
                f"across {len(mitre_tactics)} MITRE ATT&CK tactics. "
            ) + (
                f"The identification of {critical_count} critical and {high_count} high-severity vulnerabilities "
                f"indicates that the cluster configuration requires immediate hardening. "
                if critical_count > 0 or high_count > 0
                else "No critical or high-severity vulnerabilities were identified in this assessment. "
            ) + (
                f"AI-powered remediation was triggered for {len(remediation_sessions_raw)} incidents, "
                f"with the agent executing targeted commands to mitigate the identified threats."
                if remediation_sessions_raw
                else ""
            ),
            "recommendations": [
                "Enforce Pod Security Standards (restricted profile) to prevent privileged container deployment.",
                "Implement RBAC least-privilege policies — avoid cluster-admin bindings for service accounts.",
                "Disable hostPath volume mounts unless absolutely necessary; use CSI drivers with appropriate policies.",
                "Store secrets in external secrets management (HashiCorp Vault, AWS Secrets Manager) with automatic rotation.",
                "Enable audit logging and implement real-time threat detection for rapid incident response.",
                "Conduct regular security assessments to identify and remediate configuration drift.",
                "Implement network policies to enforce micro-segmentation and restrict east-west traffic.",
            ],
        },
    }

    pdf_buf = generate_report(data)
    return StreamingResponse(
        pdf_buf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=k8s-security-report-{int(time.time())}.pdf",
            "Content-Type": "application/pdf",
        },
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                await handle_ws_message(websocket, msg)
            except json.JSONDecodeError:
                await ws_manager.send_to(websocket, {
                    "type": "error",
                    "message": "Invalid JSON",
                })
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)


async def handle_ws_message(websocket: WebSocket, msg: Dict[str, Any]):
    msg_type = msg.get("type", "")
    if msg_type == "ping":
        await ws_manager.send_to(websocket, {"type": "pong", "timestamp": time.time()})
    elif msg_type == "subscribe_attacks":
        await ws_manager.send_to(websocket, {
            "type": "subscribed", "channel": "attacks",
            "available": attack_engine.get_available_attacks(),
        })
    elif msg_type == "get_cluster_info":
        info = await cluster_manager.get_cluster_info()
        await ws_manager.send_to(websocket, {"type": "cluster_info", "data": info})
    elif msg_type == "remediation_execute_all":
        session_id = msg.get("session_id")
        if remediation_agent and session_id:
            remediation_agent.signal_execute_all(session_id)
            await ws_manager.send_to(websocket, {
                "type": "remediation_execute_all_received",
                "session_id": session_id,
            })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
