#!/usr/bin/env python3
"""
KARMA — Kubernetes Attack & Remediation Mapping Agent

Interactive CLI tool for executing real K8s attacks with autonomous
AI-driven remediation. Each attack streams agent thinking, commands,
and live output to the terminal in real-time.

Usage:
    python3 cli.py
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

# ── Load .env file ──────────────────────────────────────────
env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.isfile(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip("\"'")
                os.environ[k] = v

from cluster_manager.manager import ClusterManager, CLUSTER_NAME
from attack_engine.mitre import MITRE_ATTACK
from attack_engine.attacks.privilege_escalation import PrivilegeEscalationHostPath, RBACPrivilegeEscalation
from attack_engine.attacks.container_escape import ContainerEscapePrivileged, SidecarInjection
from attack_engine.attacks.secrets_access import SecretsExfiltration, ConfigMapExfiltration
from attack_engine.attacks.network_scan import InternalNetworkScan, KubeletAPIAbuse
from attack_engine.attacks.resource_hijack import ResourceHijacking
from attack_engine.attacks.dns_exfiltration import DNSExfiltration
from detection.monitor import DetectionMonitor
from remediation.agent import RemediationAgent

# ── Terminal setup ───────────────────────────────────────────

USE_COLOR = sys.stdout.isatty()
TERM_W = min(shutil.get_terminal_size().columns - 2, 88)
if TERM_W < 60:
    TERM_W = 60


class C:
    if USE_COLOR:
        cyan    = '\033[0;36m'
        b_cyan  = '\033[1;36m'
        green   = '\033[0;32m'
        b_green = '\033[1;32m'
        yellow  = '\033[0;33m'
        b_yellow= '\033[1;33m'
        red     = '\033[0;31m'
        b_red   = '\033[1;31m'
        blue    = '\033[0;34m'
        b_blue  = '\033[1;34m'
        magenta = '\033[0;35m'
        white   = '\033[1;37m'
        b_white = '\033[1;37m'
        dim     = '\033[2m'
        bold    = '\033[1m'
        reset   = '\033[0m'
    else:
        cyan = b_cyan = green = b_green = ''
        yellow = b_yellow = red = b_red = ''
        blue = b_blue = magenta = white = b_white = ''
        dim = bold = reset = ''


# ── Attack registry ──────────────────────────────────────────

ATTACKS = [
    ("privilege-escalation-hostpath", PrivilegeEscalationHostPath, "CRITICAL"),
    ("rbac-privilege-escalation", RBACPrivilegeEscalation, "CRITICAL"),
    ("container-escape-privileged", ContainerEscapePrivileged, "CRITICAL"),
    ("sidecar-injection", SidecarInjection, "HIGH"),
    ("secrets-exfiltration", SecretsExfiltration, "CRITICAL"),
    ("configmap-exfiltration", ConfigMapExfiltration, "MEDIUM"),
    ("network-scan-internal", InternalNetworkScan, "HIGH"),
    ("kubelet-api-abuse", KubeletAPIAbuse, "CRITICAL"),
    ("resource-hijacking", ResourceHijacking, "HIGH"),
    ("dns-exfiltration", DNSExfiltration, "HIGH"),
]

SEV_COLORS = {"CRITICAL": C.b_red, "HIGH": C.b_yellow, "MEDIUM": C.b_blue, "LOW": C.dim}
SEV_TAGS = {k: f"{v}{k}{C.reset}" for k, v in SEV_COLORS.items()}

W = TERM_W


# ── Drawing helpers ──────────────────────────────────────────

def esc(t):
    return str(t) if t else ""


def thin():
    print(f"  {C.dim}{'─' * (W - 2)}{C.reset}")


def section(title, color=C.b_cyan):
    print(f"\n  {color}╔{'═' * (W - 2)}╗{C.reset}")
    for line in title.split('\n'):
        print(f"  {color}║{C.reset}{' ' + line + ' ' * (W - 4 - len(line))}{color}║{C.reset}")
    print(f"  {color}╚{'═' * (W - 2)}╝{C.reset}")


def box(title, color=C.cyan):
    pad = W - len(title) - 8
    if pad < 2:
        pad = 2
    print(f"  {color}┌─ {C.bold}{title}{C.reset} {color}{'─' * pad}┐{C.reset}")


def box_end(color=C.cyan):
    print(f"  {color}└{'─' * (W - 4)}┘{C.reset}")


def subtitle(text, color=C.white):
    print(f"  {color}◆ {C.reset}{text}")


def cmd_block(command):
    c = command.strip()
    max_w = W - 10
    print(f"  {C.b_cyan}┌─ Command {'─' * (W - 19)}┐{C.reset}")
    for chunk in wrap_line(f"$ {c}", max_w):
        print(f"  {C.b_cyan}│{C.reset} {C.cyan}{chunk}{C.reset} {' ' * (W - 9 - len(chunk))}{C.b_cyan}│{C.reset}")
    print(f"  {C.b_cyan}└{'─' * (W - 4)}┘{C.reset}")


def output_block(text):
    if not text or not text.strip():
        return
    lines = text.rstrip().split('\n')
    truncated = False
    max_w = W - 8
    print(f"  {C.green}┌─ Output {'─' * (W - 17)}┐{C.reset}")
    for line in lines:
        l = line.rstrip()
        for chunk in wrap_line(l, max_w):
            print(f"  {C.green}│{C.reset} {C.green}{chunk}{C.reset} {' ' * (W - 9 - len(chunk))}{C.green}│{C.reset}")
    print(f"  {C.green}└{'─' * (W - 4)}┘{C.reset}")


def wrap_line(line, width):
    """Yield chunks of line that fit within width."""
    while len(line) > width:
        yield line[:width]
        line = line[width:]
    if line:
        yield line


def thinking_block(text):
    if not text or not text.strip():
        return
    lines = text.strip().split('\n')
    max_w = W - 8
    print(f"  {C.yellow}┌─ Agent Thinking {'─' * (W - 26)}┐{C.reset}")
    for line in lines:
        l = line.rstrip()
        for chunk in wrap_line(l, max_w):
            print(f"  {C.yellow}│{C.reset} {C.yellow}{chunk}{C.reset} {' ' * (W - 9 - len(chunk))}{C.yellow}│{C.reset}")
    print(f"  {C.yellow}└{'─' * (W - 4)}┘{C.reset}")


def ok(text):
    print(f"  {C.b_green}✔{C.reset} {text}")


def fail(text):
    print(f"  {C.b_red}✘{C.reset} {text}")


def warn(text):
    print(f"  {C.b_yellow}⚠{C.reset} {text}")


def info(text):
    print(f"  {C.blue}ℹ{C.reset} {text}")


def mitre_tag(tactic):
    return f"{C.dim}{tactic.replace('_', ' ').title()}{C.reset}"


def sev_tag(sev):
    return SEV_TAGS.get(sev.upper(), sev.upper())


# ── Console WS (prints everything in real-time) ─────────────

class LiveWS:
    connection_count = 0

    async def broadcast(self, msg):
        t = msg.get("type", "")

        if t == "attack_event":
            ev = msg.get("event", {})
            et = ev.get("event_type", "")
            data = ev.get("data", {})
            if et == "cmd":
                cmd = data.get("command", "")
                out = data.get("output", "")
                thin()
                cmd_block(cmd)
                if out:
                    output_block(out)
            elif et == "info":
                subtitle(ev.get("message", ""))
            elif et == "start":
                subtitle(ev.get("message", ""))
            elif et == "complete":
                ok(ev.get("message", ""))
            elif et == "error":
                fail(ev.get("message", ""))

        elif t == "detection_alert":
            sev = msg.get("severity", "info")
            name = msg.get("rule", msg.get("message", ""))
            col = C.red if sev == "critical" else C.yellow if sev == "high" else C.dim
            icon = "!" if sev == "critical" else "*" if sev == "high" else "."
            if sev in ("critical", "high"):
                print(f"  {col}[{icon}] {name}{C.reset}")

        elif t == "remediation_started":
            inc = msg.get("session", {}).get("incident", {})
            s = inc.get("severity", "")
            print()
            section(f" Auto-Remediation — {inc.get('name', '')} ", C.b_red if s == "critical" else C.b_yellow)
            thin()

        elif t == "remediation_command_found":
            tk = msg.get("thinking", "")
            cmd = msg.get("command", "")
            if tk.strip():
                thinking_block(tk)
            cmd_block(cmd)

        elif t == "remediation_command_result":
            out = msg.get("output", "")
            ok_ = msg.get("success", False)
            if out:
                output_block(out)
            if ok_:
                ok("Command succeeded")
            else:
                fail("Command failed")

        elif t == "remediation_completed":
            summary = msg.get("summary", "")
            if summary:
                lines = summary.strip().split('\n')
                print(f"  {C.green}┌─ Summary {'─' * (W - 20)}┐{C.reset}")
                for line in lines:
                    l = line.rstrip()
                    for chunk in wrap_line(l, W - 8):
                        print(f"  {C.green}│{C.reset} {C.green}{chunk}{C.reset} {' ' * (W - 9 - len(chunk))}{C.green}│{C.reset}")
                print(f"  {C.green}└{'─' * (W - 4)}┘{C.reset}")
            ok("Remediation complete")

        elif t == "remediation_failed":
            err = msg.get("error", "Unknown")
            fail(f"Remediation failed: {err}")

    async def connect(self, _): pass
    async def disconnect(self, _): pass
    async def send_to(self, _, __): pass


# ── Core: build agent step list from attack result ──────────

def build_attack_steps(result):
    steps = []
    for ev in result.get("events", []):
        et = ev.get("event_type", "")
        data = ev.get("data", {})
        if et == "cmd":
            steps.append({"type": "command", "command": data.get("command", ""), "output": data.get("output", "")})
        elif et in ("start", "info", "complete"):
            steps.append({"type": "thinking", "content": ev.get("message", "")})
        elif et == "error":
            steps.append({"type": "thinking", "content": f"[Error] {ev.get('message', '')}"})
    return steps


# ── Run single attack (returns result dict) ─────────────────

async def run_attack_instance(idx, total, aid, aclass, cm, loop, ws):
    instance = aclass(cm, ws)
    instance.set_main_loop(loop)

    print()
    section(f" [{idx}/{total}] {instance.name} ", C.b_white)
    print(f"  {C.dim}  {instance.description}{C.reset}")
    print(f"  {' ' * 2}Severity: {sev_tag(instance.severity.value)}  |  MITRE: {mitre_tag(instance.mitre_tactic)}")
    thin()
    print()

    eid = str(uuid.uuid4())
    try:
        result = await asyncio.to_thread(lambda: asyncio.run(instance.execute_with_id(eid)))
        s = result.get("status", "unknown")
        dur = ""
        if result.get("start_time") and result.get("end_time"):
            dur = f" ({result['end_time'] - result['start_time']:.1f}s)"
        if s in ("completed", "success"):
            ok(f"Completed{dur}")
        else:
            fail(f"Status: {s}")
    except Exception as ex:
        fail(f"Error: {ex}")
        result = {"attack_id": eid, "name": instance.name, "status": "failed",
                   "error": str(ex), "severity": instance.severity.value,
                   "mitre_tactic": instance.mitre_tactic}

    steps = build_attack_steps(result)
    return {
        "type": "attack",
        "agent_name": instance.name,
        "description": instance.description,
        "severity": instance.severity.value,
        "mitre_tactic": instance.mitre_tactic,
        "mitre_techniques": instance.mitre_techniques,
        "status": result.get("status", "unknown"),
        "steps": steps,
        "infrastructure": result.get("infrastructure_affected", []),
        "duration": round(result.get("end_time", 0) - result.get("start_time", 0), 1)
        if result.get("start_time") and result.get("end_time") else None,
        "_raw": result,
    }


# ── Run remediation for an incident ─────────────────────────

async def run_remediation(ra, incident, dm):
    sid = await ra.trigger_remediation({
        "type": "attack_completed",
        "name": incident.get("agent_name", incident.get("name", "")),
        "severity": incident.get("severity", ""),
        "description": incident.get("description", ""),
        "infrastructure": incident.get("infrastructure", []),
        "detection_events": dm.get_events(5),
    })
    while True:
        s = ra.get_session(sid)
        if not s or s.get("status") in ("completed", "failed"):
            break
        await asyncio.sleep(1)
    final = ra.get_session(sid)
    if not final:
        return None
    remed_steps = []
    for step in final.get("steps", []):
        if step.get("thinking", "").strip():
            remed_steps.append({"type": "thinking", "content": step["thinking"]})
        if step.get("command"):
            remed_steps.append({"type": "command", "command": step["command"],
                                 "output": step.get("command_output", ""),
                                 "success": step.get("command_success", False)})
    return {
        "type": "remediation",
        "agent_name": f"Remediation — {incident.get('name', '')}",
        "severity": incident.get("severity", ""),
        "status": final.get("status", "unknown"),
        "steps": remed_steps,
        "summary": final.get("summary", ""),
        "infrastructure": [],
    }


# ── Save results ────────────────────────────────────────────

def save_results(agent_workflow, attacks_res, alerts, dm, cm, ra):
    sessions = ra.get_sessions(50) if ra else []

    mitre_tactics = []
    for key, tactic in MITRE_ATTACK.items():
        covered = sum(1 for a in attacks_res
                      if a.get("mitre_tactic") == key
                      and a.get("status") in ("completed", "success"))
        mitre_tactics.append({
            "id": tactic.get("id", ""), "name": tactic.get("name", key),
            "key": key, "techniques": tactic.get("techniques", []),
            "covered_count": covered,
        })

    summary = {
        "total_attacks": len(attacks_res),
        "successful": sum(1 for a in attacks_res if a.get("status") in ("completed", "success")),
        "failed": sum(1 for a in attacks_res if a.get("status") == "failed"),
        "critical": sum(1 for a in attacks_res if a.get("severity", "").lower() == "critical"),
        "high": sum(1 for a in attacks_res if a.get("severity", "").lower() == "high"),
        "medium": sum(1 for a in attacks_res if a.get("severity", "").lower() == "medium"),
        "detection_alerts": len(alerts),
        "remediation_sessions": len(sessions),
    }

    data = {
        "timestamp": time.time(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "attacks": attacks_res,
        "alerts": alerts,
        "remediation": {"sessions": sessions},
        "mitre": {"tactics": mitre_tactics},
        "cluster": {"name": CLUSTER_NAME, "ready": cm.is_ready()},
        "agent_workflow": agent_workflow,
    }

    os.makedirs("results", exist_ok=True)
    path = f"results/findings_{int(time.time())}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path, data


# ── Display results in terminal ─────────────────────────────

def display_results(results_path, data):
    s = data["summary"]
    wf = data.get("agent_workflow", [])
    mitre = data["mitre"]["tactics"]

    section(" Engagement Results ", C.b_green)

    # Summary
    box("Summary", C.b_white)
    print(f"  {' ' * 2}{C.b_white}Attacks:{C.reset}           {s['successful']} succeeded, {s['failed']} failed / {s['total_attacks']} total")
    print(f"  {' ' * 2}{C.b_white}Severity:{C.reset}          {C.b_red}{s['critical']} critical{C.reset}  {C.b_yellow}{s['high']} high{C.reset}  {C.b_blue}{s['medium']} medium{C.reset}")
    print(f"  {' ' * 2}{C.b_white}Detection alerts:{C.reset}  {s['detection_alerts']}")
    print(f"  {' ' * 2}{C.b_white}Remediation:{C.reset}       {s['remediation_sessions']} sessions")
    print(f"  {' ' * 2}{C.b_white}Results:{C.reset}           {results_path}")
    box_end()
    print()

    # MITRE
    mt = sum(1 for m in mitre if m["covered_count"] > 0)
    box(f"MITRE ATT&CK Coverage ({mt}/{len(mitre)} tactics)", C.b_white)
    for t in mitre:
        covered = t["covered_count"] > 0
        techs = t.get("techniques", [])
        dots = ""
        for i in range(max(len(techs), 2)):
            if i < t["covered_count"]:
                dots += f"{C.green}●{C.reset}"
            else:
                dots += f"{C.dim}○{C.reset}"
        status = f"{C.green}✓{C.reset}" if covered else f"{C.dim}—{C.reset}"
        cnt = f"({t['covered_count']}/{len(techs)})" if techs else ""
        print(f"  {' ' * 2}{status} {C.dim}{t['id']}{C.reset}  {t['name']:<22} {dots}  {C.dim}{cnt}{C.reset}")
    print()
    box_end()
    print()

    # Agent workflow timeline
    box(f"Agent Execution Timeline ({len(wf)} agents)", C.b_white)
    for i, agent in enumerate(wf):
        icon = f"{C.green}●{C.reset}" if agent["status"] in ("completed", "success") else f"{C.red}●{C.reset}"
        dur = f"  {C.dim}{agent.get('duration', '')}s{C.reset}" if agent.get("duration") else ""
        st = len(agent["steps"]) if agent.get("steps") else 0
        sev = agent.get("severity", "")
        sev_display = sev_tag(sev) if sev else ""
        agent_type = f"{C.red}A{C.reset}" if agent["type"] == "attack" else f"{C.blue}R{C.reset}"
        print(f"  {' ' * 2}{agent_type} {icon} {agent['agent_name']:<48} {sev_display}  {C.dim}{st} steps{dur}{C.reset}")
    box_end()
    print()

    # Attack details
    box("Attack Details", C.b_white)
    for i, agent in enumerate(wf):
        if agent["type"] != "attack":
            continue
        icon = f"{C.green}✓{C.reset}" if agent["status"] in ("completed", "success") else f"{C.red}✘{C.reset}"
        sev = sev_tag(agent.get("severity", ""))
        print(f"  {' ' * 2}{icon} [{i + 1}] {agent['agent_name']:<46} {sev}")
        if agent.get("infrastructure"):
            for inf in agent["infrastructure"]:
                print(f"  {' ' * 6}{C.dim}⚑ {inf.get('resource_type', '')}/{inf.get('name', '')} ({inf.get('namespace', '')}){C.reset}")
    box_end()
    print()


# ── Pause helper ────────────────────────────────────────────

def pause():
    print()
    input(f"  {C.dim}Press Enter to continue...{C.reset}")
    print()


# ── KARMA header ────────────────────────────────────────────

def show_header(cinfo=None):
    lines = [
        f"{C.b_white}{' ' * 4}██╗  ██╗ █████╗ ██████╗ ███╗   ███╗ █████╗{C.reset}",
        f"{C.b_white}{' ' * 4}██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║██╔══██╗{C.reset}",
        f"{C.b_white}{' ' * 4}█████╔╝ ███████║██████╔╝██╔████╔██║███████║{C.reset}",
        f"{C.b_white}{' ' * 4}██╔═██╗ ██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║{C.reset}",
        f"{C.b_white}{' ' * 4}██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║{C.reset}",
        f"{C.b_white}{' ' * 4}╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝{C.reset}",
    ]
    print(f"\n  {C.b_cyan}╔{'═' * (W - 2)}╗{C.reset}")
    for line in lines:
        print(f"  {C.b_cyan}║{C.reset}{line}{' ' * (W - 6 - len(line))}{C.b_cyan}║{C.reset}")
    tag = "Kubernetes Attack & Remediation Mapping Agent"
    ver = "v1.0.0"
    print(f"  {C.b_cyan}║{C.reset}{' ' * (W - 2)}{C.b_cyan}║{C.reset}")
    print(f"  {C.b_cyan}║{C.reset}  {C.dim}{tag}{C.reset}{' ' * (W - 6 - len(tag))}{C.dim}{ver}{C.reset}  {C.b_cyan}║{C.reset}")
    print(f"  {C.b_cyan}╚{'═' * (W - 2)}╝{C.reset}")

    if cinfo:
        ready = cinfo.get("ready", False)
        status = f"{C.green}●{C.reset} Ready" if ready else f"{C.red}●{C.reset} Offline"
        nodes = cinfo.get("node_count", "?")
        pods = cinfo.get("pod_count", "?")
        print(f"\n  {' ' * 2}{C.dim}Cluster:{C.reset} {CLUSTER_NAME}  |  {status}  |  {C.dim}{nodes} nodes{C.reset}  |  {C.dim}{pods} pods{C.reset}")


# ── Menu ─────────────────────────────────────────────────────

def show_menu(last_results=None):
    print()
    thin()
    print()

    def label(num, text, extra=""):
        print(f"  {' ' * 2}{C.b_cyan}{num:>2}{C.reset})  {text}{' ' * (46 - len(text))}{C.dim}{extra}{C.reset}")

    print(f"  {C.b_white}Attack Modules{C.reset}")
    for i, (_, _, _) in enumerate(ATTACKS, 1):
        label(i, ATTACKS[i - 1][1](None, None).name)

    print()
    print(f"  {C.b_white}Campaigns{C.reset}")
    label(11, "Run All Attacks (sequential)")
    label(12, "Full Engagement (attacks + auto-remediation)")

    print()
    print(f"  {C.b_white}Intelligence{C.reset}")
    label(13, "View Last Results")
    label(14, "Cluster Status")

    print()
    print(f"  {' ' * 2}{C.dim}[{C.reset}{C.b_red}0{C.reset}{C.dim}]  Exit{C.reset}")
    print()
    thin()

    try:
        choice = input(f"\n  {C.b_cyan}Select option [0-14]{C.reset} ")
    except (EOFError, KeyboardInterrupt):
        print()
        return "0"
    return choice.strip()


# ── Setup ───────────────────────────────────────────────────

async def ensure_ready(with_remediation=False):
    ws = LiveWS()
    cm = ClusterManager(ws)

    section(" System Check ", C.b_blue)
    prereqs = await cm.check_prerequisites()
    for c in prereqs.get("checks", []):
        icon = f"{C.green}✔{C.reset}" if c.get("passed") else f"{C.red}✘{C.reset}"
        print(f"  {' ' * 2}{icon} {c.get('name', '')} — {c.get('message', '')}")
    if not prereqs.get("ready"):
        print()
        fail("Prerequisites not met. Run scripts/setup.sh first.")
        return None, None, None, None

    if cm.is_ready():
        info("Cluster ready — reusing existing cluster")
    else:
        print()
        r = await cm.create_cluster()
        if not r.get("success"):
            fail(f"Cluster creation: {r.get('error', '')}")
        return None, None, None, None, None
        ok("Cluster created")

    print()
    dm = DetectionMonitor(cm, ws)
    await dm.start_monitoring()
    ok("Detection monitor running")

    # Label namespace to allow privileged pods (bypass PodSecurity)
    try:
        subprocess.run(
            ["kubectl", "label", "namespace", "default",
             "pod-security.kubernetes.io/enforce=privileged",
             "--overwrite"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        pass

    ra = None
    if with_remediation:
        ak = os.environ.get("ANTHROPIC_API_KEY", "")
        if ak:
            ra = RemediationAgent(ws, ak)
            ok("Remediation agent ready")
        else:
            warn("ANTHROPIC_API_KEY not set — remediation disabled")

    loop = asyncio.get_event_loop()
    return ws, cm, dm, ra, loop


# ── Single attack mode ──────────────────────────────────────

async def cmd_single_attack(idx):
    aid, aclass, sev = ATTACKS[idx - 1]
    ws, cm, dm, ra, loop = await ensure_ready()
    if not cm:
        pause()
        return

    agent = await run_attack_instance(idx, len(ATTACKS), aid, aclass, cm, loop, ws)
    results = [agent["_raw"]]
    path, data = save_results([agent], results, dm.get_events(200), dm, cm, ra or RemediationAgent(LiveWS(), ""))

    print()
    thin()
    info(f"Results saved to {path}")
    pause()


# ── Run all (no remediation) ────────────────────────────────

async def cmd_run_all():
    ws, cm, dm, ra, loop = await ensure_ready(with_remediation=False)
    if not cm:
        pause()
        return

    section(" Running All Attacks ", C.b_red)

    agents = []
    raw_results = []

    for idx, (aid, aclass, sev) in enumerate(ATTACKS, 1):
        agent = await run_attack_instance(idx, len(ATTACKS), aid, aclass, cm, loop, ws)
        agents.append(agent)
        raw_results.append(agent["_raw"])

    path, data = save_results(agents, raw_results, dm.get_events(200), dm, cm, ra or RemediationAgent(LiveWS(), ""))
    print()
    display_results(path, data)
    pause()


# ── Full engagement (with remediation) ─────────────────────

async def cmd_full_engagement():
    ws, cm, dm, ra, loop = await ensure_ready(with_remediation=True)
    if not cm:
        pause()
        return

    section(" Full Engagement — Attacks + Auto-Remediation ", C.b_red)

    agents = []
    raw_results = []

    for idx, (aid, aclass, sev) in enumerate(ATTACKS, 1):
        agent = await run_attack_instance(idx, len(ATTACKS), aid, aclass, cm, loop, ws)
        agents.append(agent)
        raw_results.append(agent["_raw"])

        sev_lower = agent.get("severity", "")
        if ra and sev_lower in ("high", "critical"):
            print()
            info(f"Auto-remediation triggered ({sev_tag(sev_lower)})...")
            remed = await run_remediation(ra, agent, dm)
            if remed:
                agents.append(remed)

    path, data = save_results(agents, raw_results, dm.get_events(200), dm, cm, ra or RemediationAgent(LiveWS(), ""))
    print()
    display_results(path, data)
    pause()


# ── View last results ───────────────────────────────────────

def cmd_view_results():
    results_dir = "results"
    if not os.path.exists(results_dir):
        warn("No results directory found.")
        pause()
        return
    files = sorted(os.listdir(results_dir), reverse=True)
    if not files:
        warn("No results yet. Run an attack first.")
        pause()
        return
    latest = os.path.join(results_dir, files[0])
    try:
        with open(latest) as f:
            data = json.load(f)
    except Exception as e:
        fail(f"Error reading results: {e}")
        pause()
        return
    display_results(latest, data)
    pause()


# ── Cluster status ──────────────────────────────────────────

async def cmd_cluster_status():
    ws = LiveWS()
    cm = ClusterManager(ws)

    section(" Cluster Status ", C.b_blue)
    if not cm.is_ready():
        warn("Cluster not ready")
        pause()
        return

    info = await cm.get_cluster_info()
    if not info.get("ready"):
        fail(f"Cluster error: {info.get('error', 'unknown')}")
        pause()
        return

    print(f"  {' ' * 2}{C.b_white}Name:{C.reset}       {info.get('name', 'N/A')}")
    print(f"  {' ' * 2}{C.b_white}Nodes:{C.reset}       {info.get('node_count', 0)}")
    print(f"  {' ' * 2}{C.b_white}Pods:{C.reset}        {info.get('pod_count', 0)}")
    print(f"  {' ' * 2}{C.b_white}Services:{C.reset}    {info.get('service_count', 0)}")
    print(f"  {' ' * 2}{C.b_white}Namespaces:{C.reset}  {info.get('namespace_count', 0)}")
    print()

    for node in info.get("nodes", []):
        cap = node.get("capacity", {})
        print(f"  {' ' * 2}{C.dim}⚙{C.reset} {node['name']:<30} {C.dim}{node.get('status', '')}{C.reset}")
        print(f"  {' ' * 6}{C.dim}{node.get('os', '')}  |  {cap.get('cpu', '?')} CPU  |  {cap.get('memory', '?')} mem{C.reset}")

    print()
    print(f"  {' ' * 2}{C.b_white}Pods:{C.reset}")
    for pod in info.get("pods", [])[:15]:
        col = C.green if pod.get("status") == "Running" else C.yellow
        print(f"  {' ' * 4}{col}●{C.reset} {pod['name'][:40]:<42} {C.dim}{pod.get('namespace', '')}{C.reset}")
    if len(info.get("pods", [])) > 15:
        print(f"  {' ' * 4}{C.dim}... and {len(info['pods']) - 15} more{C.reset}")

    pause()


# ── Main loop ───────────────────────────────────────────────

async def main_async():
    show_header()
    info("Type a number and press Enter to select")

    while True:
        choice = show_menu()

        if choice == "0":
            section(" Goodbye ", C.b_cyan)
            print(f"  {' ' * 2}{C.dim}KARMA v1.0.0 — what you deploy comes around{C.reset}")
            print()
            break

        elif choice in [str(i) for i in range(1, 11)]:
            await cmd_single_attack(int(choice))

        elif choice == "11":
            await cmd_run_all()

        elif choice == "12":
            await cmd_full_engagement()

        elif choice == "13":
            cmd_view_results()

        elif choice == "14":
            await cmd_cluster_status()

        else:
            warn(f"Unknown option: {choice}")


def main():
    parser = argparse.ArgumentParser(description="KARMA — Kubernetes Attack & Remediation Mapping Agent")
    parser.add_argument("--check", action="store_true", help="Quick cluster health check")
    args = parser.parse_args()

    if args.check:
        async def quick_check():
            ws = LiveWS()
            cm = ClusterManager(ws)
            r = await cm.get_cluster_info()
            ready = r.get("ready", False)
            print(f"Cluster: {'OK' if ready else 'FAIL'}")
            if ready:
                print(f"  Nodes: {r.get('node_count', 0)}, Pods: {r.get('pod_count', 0)}")
        asyncio.run(quick_check())
        return

    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print()
        section(" Interrupted ", C.b_yellow)
        print(f"  {' ' * 2}{C.dim}Exiting KARMA{C.reset}")
        print()


if __name__ == "__main__":
    main()
