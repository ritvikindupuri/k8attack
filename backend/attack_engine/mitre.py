MITRE_ATTACK = {
    "initial_access": {
        "id": "TA0001",
        "name": "Initial Access",
        "techniques": [
            {
                "id": "T1613",
                "name": "Container and Resource Discovery",
                "description": "Adversaries may discover container management systems and resources.",
                "k8s_technique": "API Discovery via Service Account",
            },
            {
                "id": "T1525",
                "name": "Implant Internal Image",
                "description": "Adversaries may implant images into a container registry.",
                "k8s_technique": "Compromised Container Image Registry",
            },
        ],
    },
    "execution": {
        "id": "TA0002",
        "name": "Execution",
        "techniques": [
            {
                "id": "T1609",
                "name": "Container Administration Command",
                "description": "Execute commands within a running container.",
                "k8s_technique": "kubectl exec into container",
            },
            {
                "id": "T1610",
                "name": "Deploy Container",
                "description": "Adversaries may deploy new containers in the cluster.",
                "k8s_technique": "Create pods with malicious intent",
            },
        ],
    },
    "persistence": {
        "id": "TA0003",
        "name": "Persistence",
        "techniques": [
            {
                "id": "T1505.003",
                "name": "Web Shell",
                "description": "Adversaries may deploy web shells into containers.",
                "k8s_technique": "Deploy backdoor container with reverse shell",
            },
            {
                "id": "T1611",
                "name": "Container Escape",
                "description": "Adversaries may escape container to host access.",
                "k8s_technique": "Privileged container host access",
            },
        ],
    },
    "privilege_escalation": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "techniques": [
            {
                "id": "T1611",
                "name": "Escape to Host",
                "description": "Container breakouts to gain node-level access.",
                "k8s_technique": "hostPath mount /var/log or /host",
            },
            {
                "id": "T1548.003",
                "name": "Sudo and Sudo Caching",
                "description": "Abuse elevated privileges via misconfigurations.",
                "k8s_technique": "Privileged container creation with elevated caps",
            },
        ],
    },
    "defense_evasion": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "techniques": [
            {
                "id": "T1612",
                "name": "Build Image on Host",
                "description": "Build container images directly on hosts to avoid registry scrutiny.",
                "k8s_technique": "Build and deploy malicious images",
            },
            {
                "id": "T1562.001",
                "name": "Disable or Modify Tools",
                "description": "Disable security monitoring agents.",
                "k8s_technique": "Disable audit logging in pods",
            },
        ],
    },
    "credential_access": {
        "id": "TA0006",
        "name": "Credential Access",
        "techniques": [
            {
                "id": "T1552.007",
                "name": "Container Secrets",
                "description": "Access secrets stored in container environments.",
                "k8s_technique": "List and export Kubernetes secrets via API",
            },
            {
                "id": "T1613",
                "name": "Access K8s API",
                "description": "Query the Kubernetes API for secrets and configurations.",
                "k8s_technique": "K8s API secret enumeration",
            },
        ],
    },
    "discovery": {
        "id": "TA0007",
        "name": "Discovery",
        "techniques": [
            {
                "id": "T1046",
                "name": "Network Service Scanning",
                "description": "Scan internal cluster CIDR for services.",
                "k8s_technique": "Scan service IPs and ports from compromised pod",
            },
            {
                "id": "T1613",
                "name": "K8s API Discovery",
                "description": "Enumerate cluster resources via API.",
                "k8s_technique": "API resource enumeration via service account token",
            },
        ],
    },
    "lateral_movement": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "techniques": [
            {
                "id": "T1021.006",
                "name": "Kubernetes API",
                "description": "Use K8s API to move between containers/pods.",
                "k8s_technique": "Use stolen service account to access other namespaces",
            },
            {
                "id": "T1610",
                "name": "Deploy Container",
                "description": "Deploy containers in other namespaces for lateral access.",
                "k8s_technique": "Cross-namespace pod creation",
            },
        ],
    },
    "collection": {
        "id": "TA0009",
        "name": "Collection",
        "techniques": [
            {
                "id": "T1113",
                "name": "Screen Capture",
                "description": "Capture screenshots for data from running processes.",
                "k8s_technique": "Collect environment variables and configmaps",
            },
            {
                "id": "T1057",
                "name": "Process Discovery",
                "description": "Discover running processes within the cluster.",
                "k8s_technique": "Pod process enumeration from host",
            },
        ],
    },
    "impact": {
        "id": "TA0040",
        "name": "Impact",
        "techniques": [
            {
                "id": "T1496",
                "name": "Resource Hijacking",
                "description": "Use compute resources for unauthorized purposes.",
                "k8s_technique": "Deploy resource-intensive pods (crypto mining)",
            },
            {
                "id": "T1499",
                "name": "Endpoint Denial of Service",
                "description": "Disrupt service availability within the cluster.",
                "k8s_technique": "Resource exhaustion via pod flood",
            },
        ],
    },
}


def get_mitre_mapping():
    return MITRE_ATTACK


def get_tactic_by_name(name):
    for tactic_id, tactic_data in MITRE_ATTACK.items():
        if tactic_data["name"].lower() == name.lower():
            return tactic_data
    return None


def get_techniques_for_tactic(tactic_name):
    tactic = MITRE_ATTACK.get(tactic_name)
    if tactic:
        return tactic["techniques"]
    return []
