# KARMA — Technical Documentation

**Kubernetes Attack & Remediation Mapping Agent**

Version 1.0.0

---

- [1. Executive Summary](#1-executive-summary)
- [2. System Architecture](#2-system-architecture)
- [3. Attack Engine](#3-attack-engine)
- [4. Attack Modules](#4-attack-modules)
  - [4.1 Privilege Escalation via HostPath Mount](#41-privilege-escalation-via-hostpath-mount)
  - [4.2 RBAC Privilege Escalation](#42-rbac-privilege-escalation)
  - [4.3 Container Escape via Privileged Mode](#43-container-escape-via-privileged-mode)
  - [4.4 Sidecar Proxy Injection](#44-sidecar-proxy-injection)
  - [4.5 Kubernetes Secrets Exfiltration](#45-kubernetes-secrets-exfiltration)
  - [4.6 ConfigMap Data Collection](#46-configmap-data-collection)
  - [4.7 Internal Cluster Network Scan](#47-internal-cluster-network-scan)
  - [4.8 Kubelet API Abuse](#48-kubelet-api-abuse)
  - [4.9 Cluster Resource Hijacking](#49-cluster-resource-hijacking)
  - [4.10 DNS-Based Data Exfiltration](#410-dns-based-data-exfiltration)
- [5. Detection Monitor](#5-detection-monitor)
- [6. Remediation Agent](#6-remediation-agent)
- [7. WebSocket Manager](#7-websocket-manager)
- [8. CLI Tool](#8-cli-tool)
- [9. API Reference](#9-api-reference)
- [10. Chat Handler](#10-chat-handler)
- [11. Report Generator](#11-report-generator)
- [12. MITRE ATT&CK Coverage](#12-mitre-attck-coverage)
- [13. Data Model](#13-data-model)
- [14. Dependencies & Setup](#14-dependencies--setup)
- [15. Conclusion](#15-conclusion)

---

## 1. Executive Summary

KARMA is a pure CLI-based Kubernetes security platform that deploys a real Kind cluster, executes 10 real-world attack techniques mapped to MITRE ATT&CK for Containers, and autonomously remediates them using Claude Sonnet 4. Every agent displays its full chain-of-thought reasoning alongside every command and its exact output, providing complete transparency into the security assessment workflow.

The platform covers 8 MITRE ATT&CK tactics across 10 attack scenarios, 7 detection alert rules, and 28 API endpoints. Attacks range from container escape and privilege escalation to DNS-based data exfiltration and resource hijacking.

---

## 2. System Architecture

KARMA follows a layered architecture with five main components:

**CLI Layer** (`cli.py`) — Interactive terminal menu with ANSI-themed branding. Manages user input, orchestrates attack/remediation workflows, and streams live agent output. Imports backend components directly in-process and uses a mock WebSocket (`LiveWS`) for local real-time display — no HTTP calls needed for local operation.

**API Layer** (`backend/main.py`) — FastAPI server on port 8000. Provides REST endpoints and WebSocket connections for live streaming, and hosts the remediation worker loop that queues incidents for Claude. The CLI runs standalone and imports components in-process, but the API layer can also drive the same attacks independently.

**Attack Engine** (`backend/attack_engine/`) — Orchestrates 10 attack modules. Each module extends `BaseAttack` and uses the Kubernetes Python client to create/delete resources. The engine tracks status, events, and affected infrastructure per attack.

**Detection & Remediation** —
  - `backend/detection/monitor.py`: Kubernetes watch-based monitor that detects privileged pods, hostPath mounts, cluster-admin bindings, secret access, API discovery, host network, and host PID events across 7 alert rules.
  - `backend/remediation/agent.py`: Claude Sonnet 4 agent that receives incident data, generates structured chain-of-thought remediation plans, and executes kubectl commands autonomously.

**Cluster Layer** (`backend/cluster_manager/`) — Kind-based 3-node cluster named `k8s-attack-lab` (1 control-plane, 2 workers) with intentionally vulnerable configurations (pod security policies, RBAC bindings, default service account permissions). Uses `CLUSTER_NAME = "k8s-attack-lab"` (manager.py:40).

Data flows: CLI → Attack Engine → Cluster → Detection Monitor → (if high/critical) Remediation Agent → Cluster → Results → CLI display + PDF report.

---

## 3. Attack Engine

**File:** `backend/attack_engine/engine.py`
**Base class:** `backend/attack_engine/attacks/base.py`

The `AttackEngine` class manages attack lifecycle. It maintains an `AVAILABLE_ATTACKS` registry mapping string IDs (e.g. `"privilege-escalation-hostpath"`) to attack classes. When `run_attack()` is called, it generates a UUID `execution_id`, instantiates the attack class with the cluster manager and WebSocket manager, and spawns the execution in a background `asyncio.create_task`.

The engine tracks:
- **Active attacks** (`self.active_attacks`): dict keyed by `execution_id` with status, start time, MITRE tactic, severity
- **Attack history** (`self.attack_history`): list of completed attack result dicts (capped at 100)
- **Completion callback** (`self.on_complete`): called for high/critical attacks to queue remediation

Each attack runs via `asyncio.to_thread` wrapping `attack_instance.execute_with_id()`, broadcasting `attack_started`/`attack_completed`/`attack_failed` events over WebSocket.

**File:** `backend/attack_engine/orchestrator.py`

The `AttackOrchestrator` runs all 10 attacks sequentially via `run_all_attacks()`. It iterates `AVAILABLE_ATTACKS`, calls `engine.run_attack()` for each with a 2-second delay between launches, and broadcasts `orchestrator_started`/`orchestrator_completed` events. It also supports `stop()` to abort a running orchestration and `get_status()` to return progress.

## 4. Attack Modules

### 4.1 Privilege Escalation via HostPath Mount

**File:** `backend/attack_engine/attacks/privilege_escalation.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1611 (Escape to Host), T1548.003 (Abuse Elevation Control Mechanism)

Creates a pod (`hostpath-exploit`) in the `default` namespace that mounts the host filesystem at `/host` via a `hostPath` volume. Once the pod is running, it reads `/host/etc/shadow` to prove host-level access and extracts the shadow file contents as evidence of node compromise.

**Pod manifest:** `alpine:3.19`, container `exploit-container`, command `sleep 3600`, labels `app=exploit, attack=privilege-escalation`. **securityContext:** `privileged: true`, capabilities `SYS_ADMIN, DAC_OVERRIDE`. **hostNetwork:** not set (false). **hostPID:** not set (false). **Volumes:** `hostPath` type `Directory` mapping host `/` to `/host`. **Resource limits:** not set (unrestricted). **Restart policy:** `Never`.

### 4.2 RBAC Privilege Escalation

**File:** `backend/attack_engine/attacks/privilege_escalation.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1611 (Escape to Host), T1548.003 (Abuse Elevation Control Mechanism)

Creates a service account (`malicious-admin`) in the `default` namespace, then binds it to the `cluster-admin` ClusterRole via a ClusterRoleBinding (`malicious-admin-binding`). Uses the Kubernetes Python API client directly to create the SA and binding — no pod is deployed. The binding grants the service account full admin privileges across all namespaces.

### 4.3 Container Escape via Privileged Mode

**File:** `backend/attack_engine/attacks/container_escape.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1611 (Container Escape), T1548.003 (Abuse Elevation Control Mechanism)

Deploys a privileged container (`container-escape-pod`) with `hostPID: true` and `hostNetwork: true`. These settings break container isolation by sharing the host's process namespace and network stack. The pod uses `nsenter` to execute host-namespace commands (hostname read), attempts `chroot` escape, queries host iptables rules, and reads host filesystem via `/proc/1/root`.

**Pod manifest:** `alpine:3.19`, container `escape-container`, `privileged: true`, `hostPID: true`, `hostNetwork: true`, capabilities `SYS_ADMIN, SYS_PTRACE, SYS_CHROOT, DAC_OVERRIDE, NET_ADMIN, SYS_RAWIO`. **Volumes:** `hostPath` type `Directory` mapping `/sys/fs/cgroup`. **Command:** `sleep 3600`. **Resource limits:** not set (unrestricted). **Restart policy:** `Never`. Labels `app=escape, attack=container-escape`.

### 4.4 Sidecar Proxy Injection

**File:** `backend/attack_engine/attacks/container_escape.py`

**Severity:** High
**MITRE Tactic:** Collection (TA0009)
**MITRE Techniques:** T1613 (Access K8s API), T1021.006 (Kubernetes API lateral movement)

Discovers target pods in the `default` namespace and attempts to inject a malicious sidecar container. Since Kubernetes pod specs are immutable after creation, the attack deploys a separate proxy pod (`traffic-proxy`) with `NET_ADMIN` and `NET_RAW` capabilities that captures network traffic via `tcpdump`. If no suitable pods exist, it first creates an nginx target deployment.

**Pod manifest (proxy):** `alpine:3.19`, container `proxy`, `hostNetwork: true`, **securityContext:** capabilities `NET_ADMIN, NET_RAW` (not privileged), command `apk add tcpdump; tcpdump -i any -c 50 -nn; sleep 3600`. **hostPID:** not set (false). **Volumes:** none. **Resource limits:** not set (unrestricted). **Restart policy:** not set (defaults to `Always`). Labels `app=proxy, attack=sidecar`.
**Target deployment:** `nginx:1.25-alpine`, port 80, 1 replica, labels `app=target-app`. No securityContext, no resource limits, no hostNetwork, no volumes.

### 4.5 Kubernetes Secrets Exfiltration

**File:** `backend/attack_engine/attacks/secrets_access.py`

**Severity:** Critical
**MITRE Tactic:** Credential Access (TA0006)
**MITRE Techniques:** T1552.007 (Container Secrets), T1613 (Access K8s API)

Enumerates all secrets across all namespaces using the Kubernetes Python API directly (`api.list_namespaced_secret`). No pod is created — the attack runs in-process. Uses the Python client's built-in authentication (kubeconfig or in-cluster config) to query the API for secrets across every namespace. Found secrets are base64-decoded and logged.

### 4.6 ConfigMap Data Collection

**File:** `backend/attack_engine/attacks/secrets_access.py`

**Severity:** Medium
**MITRE Tactic:** Collection (TA0009)
**MITRE Techniques:** T1113 (Screen Capture / Data from ConfigMap), T1613 (Access K8s API)

Enumerates all ConfigMaps across all namespaces using the Kubernetes Python API directly (`api.list_namespaced_config_map`). No pod is created — the attack runs in-process. Extracts data fields from every ConfigMap found, logs key-value previews, and reports the collected configuration data as intelligence.

### 4.7 Internal Cluster Network Scan

**File:** `backend/attack_engine/attacks/network_scan.py`

**Severity:** High
**MITRE Tactic:** Discovery (TA0007)
**MITRE Techniques:** T1046 (Network Service Scanning), T1613 (K8s API Discovery)

Deploys a pod (`network-scanner`) that discovers the cluster's service CIDR and scans internal IP ranges for open ports and live services. After deploying, it installs `nmap`, `ncat`, and `bind-tools` via `apk`, then probes services using `nc -zv` across the cluster IP range. Identifies open ports on the Kubernetes API server, DNS service, and other internal endpoints.

**Pod manifest:** `alpine:3.19`, container `scanner`, command `sleep 300`. **securityContext:** not set (defaults to unprivileged). **hostNetwork:** not set (false). **hostPID:** not set (false). **Capabilities:** not set (default). **Volumes:** none. **Resource limits:** not set (unrestricted). **Restart policy:** `Never`. Labels `app=scanner, attack=network-scan`. Tools installed post-deploy via `apk`: `nmap`, `nmap-ncat`, `bind-tools`.

### 4.8 Kubelet API Abuse

**File:** `backend/attack_engine/attacks/network_scan.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1611 (Escape to Host), T1609 (Container Administration Command)

Deploys a pod (`kubelet-scanner`) with `hostNetwork: true` to bypass network policies. Discovers node internal IPs via the Kubernetes API, then probes each node's kubelet API ports (10250 with auth, 10255 without auth) using `curl`. Attempts to access pod lists and exec endpoints via the kubelet API, demonstrating node-level access without API server authentication.

**Pod manifest:** `alpine:3.19`, container `scanner`, `hostNetwork: true`, command `apk add --no-cache curl && sleep 300`. **securityContext:** not set (defaults to unprivileged). **hostPID:** not set (false). **Capabilities:** not set (default). **Volumes:** none. **Resource limits:** not set (unrestricted). **Restart policy:** `Never`. Labels `app=kubelet-scan, attack=kubelet-abuse`.

### 4.9 Cluster Resource Hijacking

**File:** `backend/attack_engine/attacks/resource_hijack.py`

**Severity:** High
**MITRE Tactic:** Impact (TA0040)
**MITRE Techniques:** T1496 (Resource Hijacking), T1499 (Endpoint Denial of Service)

Deploys resource-intensive pods (`resource-hijacker-0` through `resource-hijacker-N`) across available nodes, where N is determined by the number of available nodes (`max(len(available_nodes) * 2, 2)`). Each pod runs a CPU-intensive loop with `dd if=/dev/zero of=/dev/null` to simulate cryptominer-style resource exhaustion. The attack reports the total deployed compute load but does not actively re-check node conditions after deployment.

**Pod manifest:** `alpine:3.19`, container `loader`, command `dd if=/dev/zero of=/dev/null bs=1M count=100` in infinite loop. **Resource requests:** `cpu: 500m, memory: 256Mi`. **Resource limits:** `cpu: 1000m, memory: 512Mi`. **securityContext:** not set (defaults to unprivileged). **hostNetwork:** not set (false). **hostPID:** not set (false). **Capabilities:** not set (default). **Volumes:** none. **Restart policy:** `Always`. `nodeAffinity` pins each pod to a specific node. Labels `app=resource-hijacker, attack=resource-hijack`. Pod count = `max(len(available_nodes) * 2, 2)`.

### 4.10 DNS-Based Data Exfiltration

**File:** `backend/attack_engine/attacks/dns_exfiltration.py`

**Severity:** High
**MITRE Tactic:** Collection (TA0009)
**MITRE Techniques:** T1048 (Exfiltration Over Alternative Protocol), T1572 (Protocol Tunneling)

Creates a pod (`dns-exfil-pod`) that encodes simulated stolen data (service account tokens, secret data) into DNS queries to a controlled domain (`c2-dns.exfil.com`). Uses `nslookup` and `dig` to transmit base64-encoded payloads as DNS subdomains, bypassing HTTP/HTTPS monitoring. Demonstrates data exfiltration over DNS protocol tunneling.

**Pod manifest:** `alpine:3.19`, container `exfil-container`, command `sleep 3600`. **securityContext:** not set (defaults to unprivileged). **hostNetwork:** not set (false). **hostPID:** not set (false). **Capabilities:** not set (default). **Volumes:** none. **Resource limits:** not set (unrestricted). **Restart policy:** `Never`. Labels `app=exfil, attack=dns-exfiltration`. Exfil domain: `c2-dns.exfil.com`.

---

## 5. Detection Monitor

**File:** `backend/detection/monitor.py`

The detection monitor uses Kubernetes watch APIs (`watch.Watch()`) to monitor pod creation and RBAC changes in real-time. It maintains two concurrent watch tasks:

- `_watch_pods()`: Watches for new pods and checks against rules for privileged mode, hostPath volumes, host network, and host PID.
- `_watch_rbac()`: Watches for new ClusterRoleBindings and checks for cluster-admin escalation.

### Alert Rules (7)

| ID | Name | Severity | MITRE Tactic | MITRE Technique | Detection Logic |
|----|------|----------|-------------|----------------|----------------|
| `privileged-pod-creation` | Privileged Pod Created | Critical | Privilege Escalation | T1611 | Pod with `securityContext.privileged: true` |
| `hostpath-mount` | HostPath Volume Mount Detected | High | Privilege Escalation | T1611 | Pod with `hostPath` volume type |
| `cluster-admin-binding` | Cluster Admin Role Binding | Critical | Privilege Escalation | T1548.003 | New `cluster-admin` ClusterRoleBinding |
| `secret-access` | Secrets Access Detected | High | Credential Access | T1552.007 | Pod accessing multiple secrets in short time |
| `api-discovery` | API Resource Discovery | Medium | Discovery | T1613 | Multiple API resource enumerations |
| `host-network` | Host Network Pod | High | Defense Evasion | T1612 | Pod with `hostNetwork: true` |
| `host-pid` | Host PID Namespace | High | Privilege Escalation | T1611 | Pod with `hostPID: true` |

Events are broadcast via WebSocket to connected clients and stored in `detection_events` for retrieval via `/api/detection/events`.

---

## 6. Remediation Agent

**File:** `backend/remediation/agent.py`

### Model
Claude Sonnet 4 (`claude-sonnet-4-20250514`) via Anthropic API
**Environment variable:** `ANTHROPIC_API_KEY`

### Workflow

1. **Trigger:** Called by the remediation worker loop (`backend/main.py:52-62`) when an attack with `severity` of `high` or `critical` completes.
2. **Context building:** Incident data includes attack name, description, severity, MITRE tactic, detection events, and affected infrastructure.
3. **Prompt structure:** A detailed system prompt instructs Claude to produce structured `<thinking>` blocks (situation assessment, risk analysis, remediation strategy, command justification, verification plan) followed by `<command>` blocks with exactly one kubectl command each.
4. **Execution loop:** The agent streams response tokens. For each `<command>` block detected, the command is extracted and executed via `subprocess.run()`. Output is captured, stored, and streamed to the WebSocket. The agent continues until a `<summary>` block concludes the session.
5. **Session tracking:** Each remediation creates a `RemediationSession` with `session_id`, steps, status, and summary. Sessions are stored in memory and retrievable via `/api/remediation/sessions`.

### Prompt Keys
- Structured XML tags: `<thinking>`, `<command>`, `<summary>`
- Thinking requires: situation assessment, risk analysis, remediation strategy, command justification, verification plan
- Command patterns allowed: `kubectl delete pod`, `kubectl delete deployment`, `kubectl delete clusterrolebinding`, `kubectl delete rolebinding`, `kubectl delete role`, `kubectl delete serviceaccount`, `kubectl delete configmap`, `kubectl delete secret`, `kubectl label`, `kubectl annotate`, `kubectl rollout restart`
- Final summary: actions taken, current state, verification, recommendations

---

## 7. WebSocket Manager

**File:** `backend/ws_manager/handler.py`

The `WebSocketManager` class manages all WebSocket connections to the FastAPI backend. It maintains a set of active connections and metadata (connection time, client IP) for each.

**Key methods:**
- `connect(websocket)` — Accepts a new WebSocket connection, stores it, sends a `connected` confirmation message.
- `disconnect(websocket)` — Removes a connection from the set.
- `broadcast(message)` — Sends a JSON message to all connected clients. Dead connections are automatically cleaned up on failure.
- `send_to(websocket, message)` — Sends a JSON message to a specific client.

All components (attack engine, detection monitor, remediation agent, cluster manager) use the WebSocket manager to stream real-time events to the CLI. Event types include: `attack_started`, `attack_event`, `attack_completed`, `attack_failed`, `detection_alert`, `remediation_started`, `remediation_command_found`, `remediation_command_result`, `remediation_completed`, `remediation_failed`, `orchestrator_started`, `orchestrator_completed`, `monitor_started`, `monitor_stopped`.

The WebSocket endpoint is at `/ws` (see API reference).

---

## 8. CLI Tool

**File:** `cli.py`

The CLI is the primary user interface. It connects to backend components directly (in-process, not via HTTP when running locally) and renders all output with ANSI colors and Unicode box-drawing characters.

### Terminal Formatting
- `C` class — Defines ANSI color constants (cyan, green, yellow, red, blue, magenta, white, dim, bold). Falls back to empty strings when stdout is not a TTY.
- `section()`, `box()`, `box_end()` — Draw bordered section headers and info boxes.
- `cmd_block()` — Renders a kubectl command in a cyan-bordered box with `$` prefix.
 - `output_block()` — Renders command output in a green-bordered box with line wrapping to fit terminal width.
- `thinking_block()` — Renders agent reasoning in a yellow-bordered box.
- `ok()`, `fail()`, `warn()`, `info()` — Status icons (✔, ✘, ⚠, ℹ) with color.

### LiveWS Class (line 205)
A mock WebSocket manager that prints events directly to the terminal in real-time. Implements the same interface as the real `WebSocketManager` but renders formatted output instead of sending over the wire. Handles event types: `attack_event` (cmd/info/start/complete/error), `detection_alert`, `remediation_started`, `remediation_command_found`, `remediation_command_result`, `remediation_completed`, `remediation_failed`.

### Attack Registry (line 83)
`ATTACKS` — A list of 10 tuples mapping string IDs to attack classes and severity labels. Used by the menu system and command execution.

### Menu System (line 535)
`show_menu()` renders an interactive terminal menu with 14 options grouped into Attack Modules (1–10), Campaigns (11–12), Intelligence (13–14), and Exit (0). Input is read via `input()` and routed in the `main_async()` event loop.

### Execution Flow
1. `ensure_ready()` — Checks prerequisites, creates/reuses Kind cluster, labels default namespace with `pod-security.kubernetes.io/enforce=privileged`, starts detection monitor, optionally initializes remediation agent.
2. `run_attack_instance()` — Creates attack instance, displays header with name/severity/MITRE, executes via `asyncio.to_thread`, builds structured step list from raw events.
3. `run_remediation()` — Calls `remediation_agent.trigger_remediation()`, polls until completion, builds structured step list.
4. `save_results()` — Compiles all attack results, alerts, remediation sessions, MITRE coverage into a JSON file saved to `results/findings_{timestamp}.json`.
5. `display_results()` — Renders summary stats, MITRE coverage grid (●/○ per tactic), agent execution timeline, and per-attack infrastructure details.

### Command-line Arguments
- `python3 cli.py` — Launch interactive menu.
- `python3 cli.py --check` — Quick cluster health check (ready, node count, pod count).

---

## 9. API Reference

**Base URL:** `http://localhost:8000`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root HTML page |
| `/api/health` | GET | Health check returning status and uptime |
| `/api/prerequisites` | GET | Check if prerequisites (kubectl, kind, Docker) are installed |
| `/api/cluster/info` | GET | Cluster information (nodes, pods, namespaces) |
| `/api/cluster/create` | POST | Create the Kind cluster with vulnerable configs |
| `/api/cluster/create-and-attack` | POST | Create cluster and immediately run specified attack |
| `/api/cluster/delete` | POST | Delete the Kind cluster |
| `/api/cluster/setup-scenarios` | POST | Deploy vulnerable scenario configurations |
| `/api/attacks` | GET | List all available attacks with metadata |
| `/api/attacks/mitre` | GET | MITRE ATT&CK mapping for all attacks |
| `/api/attacks/active` | GET | Currently active attack (if any) |
| `/api/attacks/run/{attack_id}` | POST | Execute a specific attack by ID (1-10) |
| `/api/attacks/run-all` | POST | Execute all 10 attacks sequentially |
| `/api/attacks/history` | GET | Retrieve attack execution history (query: `limit`, default 20, max 100) |
| `/api/attacks/orchestrator` | GET | Get orchestrator status |
| `/api/attacks/result/{execution_id}` | GET | Get result for a specific execution |
| `/api/detection/events` | GET | Get detection events (query: `limit`, default 50, max 200) |
| `/api/detection/summary` | GET | Get alert count summary by rule |
| `/api/detection/start` | POST | Start the detection monitor watch |
| `/api/detection/stop` | POST | Stop the detection monitor |
| `/api/remediation/trigger` | POST | Trigger remediation for a specific attack result |
| `/api/remediation/sessions` | GET | List all remediation sessions (query: `limit`, default 20, max 50) |
| `/api/remediation/sessions/{session_id}` | GET | Get details for a specific remediation session |
| `/api/remediation/auto-trigger/{execution_id}` | POST | Auto-trigger remediation for an execution |
| `/api/results` | GET | Get the latest engagement results as JSON |
| `/api/report` | GET | Download a PDF security assessment report |
| `/api/chat` | POST | Send a natural language query about platform data |
| `/ws` | WebSocket | Real-time event stream for CLI live updates |

---

## 10. Chat Handler

**File:** `backend/chat/handler.py`

Provides a natural language interface to platform data via Claude Sonnet 4. The handler:

1. Builds a context string from current platform state (attacks, alerts, cluster info, remediation, MITRE tactics, infrastructure).
2. Sends user query + context to Claude with a system prompt that enforces plain-text formatting (no markdown).
3. Returns Claude's response as structured plain text.

The system prompt restricts output formatting to ALL CAPS headers, `<b>` tags for bold, `•` for bullet lists, and `<table>` HTML tags for tables.

---

## 11. Report Generator

**File:** `backend/report/generator.py`

Generates professional PDF security assessment reports using ReportLab. The report includes:

- Cover page with title, date, and severity summary
- Attack table with severities, statuses, and MITRE mappings
- Per-attack detail sections with infrastructure affected
- Detection alerts section with timeline
- MITRE ATT&CK coverage grid
- Remediation summary (if applicable)
- Cluster configuration details
- Footer with page numbers

Color-coded severity indicators: critical (red), high (orange), medium (amber), low (yellow).

---

## 12. MITRE ATT&CK Coverage

| Tactic | ID | Techniques Covered | Attack Modules |
|--------|----|-------------------|----------------|
| Privilege Escalation | TA0004 | T1611, T1548.003 | 1, 2, 3, 8 |
| Credential Access | TA0006 | T1552.007, T1613 | 5 |
| Discovery | TA0007 | T1046, T1613 | 7 |
| Collection | TA0009 | T1113, T1613, T1021.006, T1048, T1572 | 4, 6, 10 |
| Impact | TA0040 | T1496, T1499 | 9 |
| Defense Evasion | TA0005 | T1612 | (monitored via host-network detection rule) |
| Lateral Movement | TA0008 | T1021.006, T1610 | (cross-namespace techniques) |
| Execution | TA0002 | T1609, T1610 | (underlying capability) |

---

## 13. Data Model

### Attack
```python
{
    "attack_id": str,
    "name": str,
    "description": str,
    "severity": "low" | "medium" | "high" | "critical",
    "status": "pending" | "running" | "completed" | "failed" | "detected",
    "mitre_tactic": str,
    "mitre_techniques": [{"id": str, "name": str}],
    "infrastructure_affected": [{"resource_type": str, "name": str, "namespace": str, "details": dict, "timestamp": float}],
    "events": [{"event_type": str, "attack_id": str, "message": str, "data": dict, "timestamp": float}],
    "start_time": float,
    "end_time": float,
}
```

### Alert
```python
{
    "id": str,                          # e.g. "privileged-pod-creation-1234567890"
    "alert_id": str,                    # rule ID
    "name": str,                        # rule name (e.g. "Privileged Pod Created")
    "severity": str,                    # "critical" | "high" | "medium"
    "description": str,                 # rule description
    "mitre": {"tactic": str, "technique": str},
    "details": dict,                    # event-specific details (pod name, namespace, etc.)
    "timestamp": float,
    "count": int,                       # running count of this alert type
}
```

### Remediation Session
```python
{
    "session_id": str,
    "incident": dict,
    "steps": [{"thinking": str, "command": str | None, "command_output": str | None, "command_success": bool | None, "timestamp": float}],
    "status": "pending" | "running" | "completed" | "failed",
    "summary": str | None,
    "error": str | None,
    "created_at": float,
    "completed_at": float | None,
}
```

### Cluster Info
```python
{
    "ready": bool,
    "name": str,                          # "k8s-attack-lab"
    "node_count": int,
    "pod_count": int,
    "namespace_count": int,
    "service_count": int,
    "nodes": [
        {
            "name": str,
            "status": str,
            "kubelet": str,                # kubelet version string
            "os": str,
            "arch": str,
            "ip": str,
            "capacity": {"cpu": str, "memory": str, "pods": str},
        }
    ],
    "pods": [
        {
            "name": str,
            "namespace": str,
            "node": str | None,
            "status": str,
            "ip": str | None,
            "containers": int,
        }
    ],
    "namespaces": [str],
    "services": [
        {
            "name": str,
            "namespace": str,
            "cluster_ip": str,
            "type": str,
            "ports": [{"port": int, "target_port": int | str | None, "protocol": str}],
        }
    ],
}
```

---

## 14. Dependencies & Setup

**File:** `backend/requirements.txt`

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | >=0.100.0 | REST API framework |
| `uvicorn[standard]` | >=0.20.0 | ASGI server |
| `websockets` | >=10.0 | WebSocket support |
| `kubernetes` | >=25.0.0 | Kubernetes Python client |
| `pyyaml` | >=6.0.0 | YAML parsing |
| `httpx` | >=0.24.0 | Async HTTP client |
| `anthropic` | >=0.30.0 | Claude API client |
| `reportlab` | >=4.0.0 | PDF report generation |

**File:** `scripts/setup.sh`

A bash script that checks for prerequisites (`python3`, `kind`, `kubectl`, `docker`), installs kind if missing (via brew on macOS, direct binary download on Linux), installs kubectl v1.30.0 if missing, creates a Python virtual environment, installs pip dependencies, and prints a success message with the `ANTHROPIC_API_KEY` setup instruction.

---

## 15. Conclusion

KARMA provides a complete, transparent Kubernetes security assessment platform with real attacks, real detection, and real AI-powered remediation — all from a single terminal. The platform covers critical attack paths including container escape, privilege escalation, secrets exfiltration, network scanning, and resource hijacking, mapped to 8 MITRE ATT&CK tactics. The detection monitor catches all 10 attacks across 7 alert rules, the Claude-powered remediation agent can autonomously clean up and harden the cluster after high and critical severity incidents, and the full REST API exposes 28 endpoints for programmatic access.
