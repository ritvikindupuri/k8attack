# KARMA — Technical Documentation

**Kubernetes Attack & Remediation Mapping Agent**

Version 1.0.0

---

- [1. Executive Summary](#1-executive-summary)
- [2. System Architecture](#2-system-architecture)
- [3. Attack Modules](#3-attack-modules)
  - [3.1 Privilege Escalation via HostPath Mount](#31-privilege-escalation-via-hostpath-mount)
  - [3.2 RBAC Privilege Escalation](#32-rbac-privilege-escalation)
  - [3.3 Container Escape via Privileged Mode](#33-container-escape-via-privileged-mode)
  - [3.4 Sidecar Proxy Injection](#34-sidecar-proxy-injection)
  - [3.5 Kubernetes Secrets Exfiltration](#35-kubernetes-secrets-exfiltration)
  - [3.6 ConfigMap Data Collection](#36-configmap-data-collection)
  - [3.7 Internal Cluster Network Scan](#37-internal-cluster-network-scan)
  - [3.8 Kubelet API Abuse](#38-kubelet-api-abuse)
  - [3.9 Cluster Resource Hijacking](#39-cluster-resource-hijacking)
  - [3.10 DNS-Based Data Exfiltration](#310-dns-based-data-exfiltration)
- [4. Detection Monitor](#4-detection-monitor)
- [5. Remediation Agent](#5-remediation-agent)
- [6. API Reference](#6-api-reference)
- [7. Chat Handler](#7-chat-handler)
- [8. Report Generator](#8-report-generator)
- [9. MITRE ATT&CK Coverage](#9-mitre-attck-coverage)
- [10. Data Model](#10-data-model)
- [11. Conclusion](#11-conclusion)

---

## 1. Executive Summary

KARMA is a pure CLI-based Kubernetes security platform that deploys a real Kind cluster, executes 10 real-world attack techniques mapped to MITRE ATT&CK for Containers, and autonomously remediates them using Claude Sonnet 4. Every agent displays its full chain-of-thought reasoning alongside every command and its exact output, providing complete transparency into the security assessment workflow.

The platform covers 8 MITRE ATT&CK tactics across 10 attack scenarios, 7 detection alert rules, and 15 API endpoints. Attacks range from container escape and privilege escalation to DNS-based data exfiltration and resource hijacking.

---

## 2. System Architecture

KARMA follows a layered architecture with five main components:

**CLI Layer** (`cli.py`) — Interactive terminal menu with ANSI-themed branding. Manages user input, orchestrates attack/remediation workflows, and streams live agent output. Connects to the backend via HTTP REST calls and WebSocket for real-time events.

**API Layer** (`backend/main.py`) — FastAPI server on port 8000. Routes all CLI requests to the appropriate engine, manages WebSocket connections for live streaming, and hosts the remediation worker loop that queues incidents for Claude.

**Attack Engine** (`backend/attack_engine/`) — Orchestrates 10 attack modules. Each module extends `BaseAttack` and uses the Kubernetes Python client to create/delete resources. The engine tracks status, events, and affected infrastructure per attack.

**Detection & Remediation** —
  - `backend/detection/monitor.py`: Kubernetes watch-based monitor that detects privileged pods, hostPath mounts, cluster-admin bindings, secret access, API discovery, host network, and host PID events across 7 alert rules.
  - `backend/remediation/agent.py`: Claude Sonnet 4 agent that receives incident data, generates structured chain-of-thought remediation plans, and executes kubectl commands autonomously.

**Cluster Layer** (`backend/cluster_manager/`) — Kind-based 3-node cluster (1 control-plane, 2 workers) with intentionally vulnerable configurations (pod security policies, RBAC bindings, default service account permissions).

Data flows: CLI → API → Attack Engine → Cluster → Detection Monitor → (if high/critical) Remediation Agent → Cluster → Results → CLI display + PDF report.

---

## 3. Attack Modules

### 3.1 Privilege Escalation via HostPath Mount

**File:** `backend/attack_engine/attacks/privilege_escalation.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1611 (Escape to Host), T1548.003 (Abuse Elevation Control Mechanism)

Creates a pod (`hostpath-exploit`) in the `default` namespace that mounts the host filesystem at `/host` via a `hostPath` volume. The pod runs Alpine Linux and sleeps for 3600 seconds, giving the attacker shell access to the node's entire filesystem. Once the pod is running, it reads `/host/etc/shadow` to prove host-level access, demonstrates process discovery via `/host/proc`, and writes a marker file to `/host/tmp/karma-pwned` as evidence of node compromise.

**Pod manifest:** Alpine 3.19, `/bin/sh -c sleep 3600`, volume mount of `/` to `/host`.

### 3.2 RBAC Privilege Escalation

**File:** `backend/attack_engine/attacks/privilege_escalation.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1548.003 (Abuse Elevation Control Mechanism), T1613 (Access K8s API)

Creates a service account (`rbac-escalator-sa`) in the `default` namespace, then binds it to the `cluster-admin` ClusterRole via a ClusterRoleBinding (`rbac-escalator-binding`). This grants the service account full admin privileges across all namespaces. A pod (`rbac-escalator`) is deployed using this service account and uses `kubectl` to list pods across all namespaces, demonstrating cluster-wide access.

### 3.3 Container Escape via Privileged Mode

**File:** `backend/attack_engine/attacks/container_escape.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1611 (Container Escape), T1548.003 (Abuse Elevation Control Mechanism)

Deploys a privileged container (`container-escape-pod`) with `hostPID: true` and `hostNetwork: true`. These settings break container isolation by sharing the host's process namespace and network stack. The pod installs `nsenter` and uses it to execute commands on the host node namespace, creates a new user (`karma-pwned`), reads host processes, and accesses the host filesystem.

### 3.4 Sidecar Proxy Injection

**File:** `backend/attack_engine/attacks/container_escape.py`

**Severity:** High
**MITRE Tactic:** Collection (TA0009)
**MITRE Techniques:** T1613 (Access K8s API), T1021.006 (Kubernetes API lateral movement)

Discovers target pods in the `default` namespace and attempts to inject a malicious sidecar container. Since Kubernetes pod specs are immutable after creation, the attack deploys a separate proxy pod (`sidecar-proxy`) with `NET_ADMIN` and `NET_RAW` capabilities that monitors network traffic and captures `/proc/net/tcp` data. If no suitable pods exist, it first creates an nginx target deployment.

### 3.5 Kubernetes Secrets Exfiltration

**File:** `backend/attack_engine/attacks/secrets_access.py`

**Severity:** Critical
**MITRE Tactic:** Credential Access (TA0006)
**MITRE Techniques:** T1552.007 (Container Secrets), T1613 (Access K8s API)

Enumerates all secrets across all namespaces using the Kubernetes API. Gets the default service account token via file read (`/var/run/secrets/kubernetes.io/serviceaccount/token`), discovers API server endpoint from environment variables (`KUBERNETES_SERVICE_HOST`, `KUBERNETES_PORT_443_TCP_PORT`), and queries the API for secrets. Creates a pod (`secret-enumerator`) to perform the enumeration and exfiltrates found secrets.

### 3.6 ConfigMap Data Collection

**File:** `backend/attack_engine/attacks/secrets_access.py`

**Severity:** Medium
**MITRE Tactic:** Collection (TA0009)
**MITRE Techniques:** T1113 (Screen Capture), T1057 (Process Discovery)

Creates a pod (`configmap-enumerator`) that lists all ConfigMaps across all namespaces, extracts their data fields, and collects environment variables from running pods. The extracted data is logged and reported as collected intelligence.

### 3.7 Internal Cluster Network Scan

**File:** `backend/attack_engine/attacks/network_scan.py`

**Severity:** High
**MITRE Tactic:** Discovery (TA0007)
**MITRE Techniques:** T1046 (Network Service Scanning), T1613 (K8s API Discovery)

Deploys a pod (`cluster-scanner`) that discovers the cluster's service CIDR and scans internal IP ranges for open ports and live services. Uses Alpine with `nmap`, `curl`, and `bash` to perform network probing across the Kubernetes service network (`10.96.0.0/12`). Identifies open ports on the Kubernetes API server, DNS service, and other internal endpoints.

### 3.8 Kubelet API Abuse

**File:** `backend/attack_engine/attacks/network_scan.py`

**Severity:** Critical
**MITRE Tactic:** Privilege Escalation (TA0004)
**MITRE Techniques:** T1611 (Escape to Host), T1609 (Container Administration Command)

Deploys a pod (`kubelet-scanner`) with `hostNetwork: true` to bypass network policies. Discovers node internal IPs via the Kubernetes API, then probes each node's kubelet API ports (10250 with auth, 10255 without auth). Attempts to access pod lists and exec endpoints via the kubelet API, demonstrating node-level access without API server authentication.

### 3.9 Cluster Resource Hijacking

**File:** `backend/attack_engine/attacks/resource_hijack.py`

**Severity:** High
**MITRE Tactic:** Impact (TA0040)
**MITRE Techniques:** T1496 (Resource Hijacking), T1499 (Endpoint Denial of Service)

Deploys 3 resource-intensive pods (`resource-hog-1` through `resource-hog-3`) across available nodes. Each pod runs stress-ng with CPU worker threads and memory allocation to simulate cryptominer-style resource exhaustion. The attack monitors node CPU/memory pressure and reports resource starvation conditions.

### 3.10 DNS-Based Data Exfiltration

**File:** `backend/attack_engine/attacks/dns_exfiltration.py`

**Severity:** High
**MITRE Tactic:** Collection (TA0009)
**MITRE Techniques:** T1048 (Exfiltration Over Alternative Protocol), T1572 (Protocol Tunneling)

Creates a pod (`dns-exfiltrator`) that encodes simulated stolen data (service account tokens, secret data) into DNS queries to a controlled domain (`exfil.attack-simulator.local`). Uses `nslookup` and `dig` to transmit base64-encoded payloads as DNS subdomains, bypassing HTTP/HTTPS monitoring. Demonstrates data exfiltration over DNS protocol tunneling.

---

## 4. Detection Monitor

**File:** `backend/detection/monitor.py`

The detection monitor uses Kubernetes watch APIs (`watch.Watch()`) to monitor pod creation and RBAC changes in real-time. It maintains two concurrent watch tasks:

- `_watch_pods()`: Watches for new pods and checks against rules for privileged mode, hostPath volumes, host network, and host PID.
- `_watch_rbac()`: Watches for new ClusterRoleBindings and checks for cluster-admin escalation.

### Alert Rules (7)

| ID | Name | Severity | MITRE Tactic | Detection Logic |
|----|------|----------|-------------|----------------|
| `privileged-pod-creation` | Privileged Pod Created | Critical | Privilege Escalation | Pod with `securityContext.privileged: true` |
| `hostpath-mount` | HostPath Volume Mount | High | Privilege Escalation | Pod with `hostPath` volume type |
| `cluster-admin-binding` | Cluster Admin Role Binding | Critical | Privilege Escalation | New `cluster-admin` ClusterRoleBinding |
| `secret-access` | Secrets Access | High | Credential Access | Pod accessing multiple secrets in short time |
| `api-discovery` | API Resource Discovery | Medium | Discovery | Multiple API resource enumerations |
| `host-network` | Host Network Pod | High | Defense Evasion | Pod with `hostNetwork: true` |
| `host-pid` | Host PID Namespace | High | Privilege Escalation | Pod with `hostPID: true` |

Events are broadcast via WebSocket to connected clients and stored in `detection_events` for retrieval via `/api/detection/events`.

---

## 5. Remediation Agent

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
- Commands restricted to: `kubectl delete`, `kubectl label`, `kubectl annotate`, `kubectl rollout restart`
- Final summary: actions taken, current state, verification, recommendations

---

## 6. API Reference

**Base URL:** `http://localhost:8000`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check returning status and uptime |
| `/api/cluster/info` | GET | Cluster information (nodes, pods, namespaces) |
| `/api/cluster/create` | POST | Create the Kind cluster with vulnerable configs |
| `/api/cluster/delete` | POST | Delete the Kind cluster |
| `/api/attacks` | GET | List all available attacks with metadata |
| `/api/attacks/run/{id}` | POST | Execute a specific attack by ID (1-10) |
| `/api/attacks/run-all` | POST | Execute all 10 attacks sequentially |
| `/api/attacks/history` | GET | Retrieve attack execution history |
| `/api/detection/events` | GET | Get detection events with optional `limit` query param |
| `/api/detection/start` | POST | Start the detection monitor watch |
| `/api/detection/stop` | POST | Stop the detection monitor |
| `/api/remediation/sessions` | GET | List all remediation sessions |
| `/api/remediation/trigger` | POST | Trigger remediation for a specific attack result |
| `/api/results` | GET | Get the latest engagement results as JSON |
| `/api/report` | GET | Download a PDF security assessment report |
| `/api/chat` | POST | Send a natural language query about platform data |
| `/ws` | WebSocket | Real-time event stream for CLI live updates |

---

## 7. Chat Handler

**File:** `backend/chat/handler.py`

Provides a natural language interface to platform data via Claude Sonnet 4. The handler:

1. Builds a context string from current platform state (attacks, alerts, cluster info, remediation, MITRE tactics, infrastructure).
2. Sends user query + context to Claude with a system prompt that enforces plain-text formatting (no markdown).
3. Returns Claude's response as structured plain text.

The system prompt restricts output formatting to ALL CAPS headers, `<b>` tags for bold, `•` for bullet lists, and `<table>` HTML tags for tables.

---

## 8. Report Generator

**File:** `backend/report/generator.py`

Generates professional PDF security assessment reports using ReportLab. The report includes:

- Cover page with title, date, and severity summary
- Attack table with severities, statuses, and MITRE mappings
- Per-attack detail sections with infrastructure affected
- Detection alerts section with timeline
- MITRE ATT&CK coverage grid
- Remediation summary (if applicable)
- Cluster configuration details
- Footer with page numbers and classification marking

Color-coded severity indicators: critical (red), high (orange), medium (amber), low (yellow).

---

## 9. MITRE ATT&CK Coverage

| Tactic | ID | Techniques Covered | Attack Modules |
|--------|----|-------------------|----------------|
| Privilege Escalation | TA0004 | T1611, T1548.003 | 1, 2, 3, 8 |
| Credential Access | TA0006 | T1552.007, T1613 | 5 |
| Discovery | TA0007 | T1046, T1613 | 7 |
| Collection | TA0009 | T1113, T1057, T1613, T1021.006, T1048, T1572 | 4, 6, 10 |
| Impact | TA0040 | T1496, T1499 | 9 |
| Defense Evasion | TA0005 | T1612, T1562.001 | (monitored via detection rules) |
| Lateral Movement | TA0008 | T1021.006, T1610 | (cross-namespace techniques) |
| Execution | TA0002 | T1609, T1610 | (underlying capability) |

---

## 10. Data Model

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
    "infrastructure_affected": [{"resource_type": str, "name": str, "namespace": str, "details": dict}],
    "events": [{"type": str, "message": str, "data": dict, "timestamp": float}],
    "start_time": float,
    "end_time": float,
}
```

### Alert
```python
{
    "alert_id": str,
    "rule_id": str,
    "rule_name": str,
    "severity": str,
    "description": str,
    "mitre": {"tactic": str, "technique": str},
    "resource": {"kind": str, "name": str, "namespace": str},
    "timestamp": float,
}
```

### Remediation Session
```python
{
    "session_id": str,
    "incident": dict,
    "steps": [{"thinking": str, "command": str, "command_output": str, "command_success": bool, "timestamp": float}],
    "status": "pending" | "running" | "completed" | "failed",
    "summary": str | None,
    "created_at": float,
    "completed_at": float | None,
}
```

### Cluster Info
```python
{
    "ready": bool,
    "node_count": int,
    "pod_count": int,
    "nodes": [{"name": str, "status": str, "k8s_version": str, "pods": int, "ip": str}],
    "namespaces": [str],
    "services": [{"name": str, "namespace": str, "type": str, "cluster_ip": str, "ports": [int]}],
}
```

---

## 11. Conclusion

KARMA provides a complete, transparent Kubernetes security assessment platform with real attacks, real detection, and real AI-powered remediation — all from a single terminal. The platform covers critical attack paths including container escape, privilege escalation, secrets exfiltration, network scanning, and resource hijacking, mapped to 8 MITRE ATT&CK tactics. The detection monitor catches all 10 attacks across 7 alert rules, and the Claude-powered remediation agent can autonomously clean up and harden the cluster after high and critical severity incidents.
