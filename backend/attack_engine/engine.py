import asyncio
import uuid
import time
from typing import Dict, List, Optional
from .attacks.privilege_escalation import PrivilegeEscalationHostPath, RBACPrivilegeEscalation
from .attacks.container_escape import ContainerEscapePrivileged, SidecarInjection
from .attacks.secrets_access import SecretsExfiltration, ConfigMapExfiltration
from .attacks.network_scan import InternalNetworkScan, KubeletAPIAbuse
from .attacks.resource_hijack import ResourceHijacking
from .attacks.dns_exfiltration import DNSExfiltration
from .attacks.base import BaseAttack, AttackStatus


AVAILABLE_ATTACKS = {
    "privilege-escalation-hostpath": PrivilegeEscalationHostPath,
    "rbac-privilege-escalation": RBACPrivilegeEscalation,
    "container-escape-privileged": ContainerEscapePrivileged,
    "sidecar-injection": SidecarInjection,
    "secrets-exfiltration": SecretsExfiltration,
    "configmap-exfiltration": ConfigMapExfiltration,
    "network-scan-internal": InternalNetworkScan,
    "kubelet-api-abuse": KubeletAPIAbuse,
    "resource-hijacking": ResourceHijacking,
    "dns-exfiltration": DNSExfiltration,
}


class AttackEngine:
    def __init__(self, cluster_manager, websocket_manager, on_complete=None):
        self.cluster_manager = cluster_manager
        self.ws_manager = websocket_manager
        self.active_attacks: Dict[str, Dict] = {}
        self.attack_history: List[Dict] = []
        self.on_complete = on_complete

    def get_available_attacks(self):
        attacks_info = []
        for attack_id, attack_class in AVAILABLE_ATTACKS.items():
            instance = attack_class(self.cluster_manager, self.ws_manager)
            attacks_info.append({
                "id": attack_id,
                "name": instance.name,
                "description": instance.description,
                "severity": instance.severity.value,
                "mitre_tactic": instance.mitre_tactic,
                "mitre_techniques": instance.mitre_techniques,
            })
        return attacks_info

    async def run_attack(self, attack_id: str, target: Optional[str] = None) -> str:
        if attack_id not in AVAILABLE_ATTACKS:
            raise ValueError(f"Unknown attack: {attack_id}. Available: {list(AVAILABLE_ATTACKS.keys())}")

        execution_id = str(uuid.uuid4())
        attack_class = AVAILABLE_ATTACKS[attack_id]
        attack_instance = attack_class(self.cluster_manager, self.ws_manager)

        asyncio.create_task(self._execute_attack(execution_id, attack_id, attack_instance))
        return execution_id

    async def _execute_attack(self, execution_id: str, attack_id: str, attack_instance: BaseAttack):
        self.active_attacks[execution_id] = {
            "id": execution_id,
            "attack_id": attack_id,
            "name": attack_instance.name,
            "status": AttackStatus.RUNNING.value,
            "start_time": time.time(),
        }

        if self.ws_manager:
            await self.ws_manager.broadcast({
                "type": "attack_started",
                "attack": self.active_attacks[execution_id],
            })

        loop = asyncio.get_event_loop()
        attack_instance.set_main_loop(loop)

        def run_attack_inner():
            return asyncio.run(attack_instance.execute_with_id(execution_id))

        try:
            result = await loop.run_in_executor(None, run_attack_inner)
            self.active_attacks[execution_id] = {
                "id": execution_id,
                "attack_id": attack_id,
                "name": attack_instance.name,
                "status": result["status"],
                "start_time": result.get("start_time"),
                "end_time": result.get("end_time"),
                "result": result,
            }
            self.attack_history.append(result)

            if self.ws_manager:
                await self.ws_manager.broadcast({
                    "type": "attack_completed",
                    "attack": self.active_attacks[execution_id],
                })

            if self.on_complete:
                self.on_complete({
                    "type": "attack_completed",
                    "name": result.get("name", ""),
                    "severity": result.get("severity", "unknown"),
                    "description": result.get("description", ""),
                    "infrastructure": result.get("infrastructure_affected", []),
                    "execution_id": execution_id,
                })
        except Exception as e:
            self.active_attacks[execution_id] = {
                "id": execution_id,
                "attack_id": attack_id,
                "name": attack_instance.name,
                "status": AttackStatus.FAILED.value,
                "error": str(e),
            }
            if self.ws_manager:
                await self.ws_manager.broadcast({
                    "type": "attack_failed",
                    "attack": self.active_attacks[execution_id],
                })

        if len(self.attack_history) > 100:
            self.attack_history = self.attack_history[-100:]

    def get_active_attacks(self):
        return list(self.active_attacks.values())

    def get_attack_result(self, execution_id: str):
        return self.active_attacks.get(execution_id)

    def get_history(self, limit: int = 20):
        return self.attack_history[-limit:]

    def get_attack_by_name(self, execution_id: str):
        for entry in reversed(self.attack_history):
            if entry.get("attack_id") == execution_id:
                return entry
        return None
