import asyncio
import json
import subprocess
import time
from abc import ABC, abstractmethod
from enum import Enum


class AttackSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DETECTED = "detected"


class AttackEvent:
    def __init__(self, attack_id, event_type, message, data=None):
        self.attack_id = attack_id
        self.event_type = event_type
        self.message = message
        self.data = data or {}
        self.timestamp = time.time()

    def to_dict(self):
        return {
            "attack_id": self.attack_id,
            "event_type": self.event_type,
            "message": self.message,
            "data": self.data,
            "timestamp": self.timestamp,
        }


class BaseAttack(ABC):
    def __init__(self, cluster_manager, websocket_manager):
        self.cluster_manager = cluster_manager
        self.ws_manager = websocket_manager
        self._main_loop = None
        self.attack_id = None
        self.status = AttackStatus.PENDING
        self.events = []
        self.infrastructure_affected = []
        self.start_time = None
        self.end_time = None

    def set_main_loop(self, loop):
        self._main_loop = loop

    @property
    @abstractmethod
    def name(self):
        pass

    @property
    @abstractmethod
    def description(self):
        pass

    @property
    @abstractmethod
    def severity(self):
        pass

    @property
    @abstractmethod
    def mitre_tactic(self):
        pass

    @property
    @abstractmethod
    def mitre_techniques(self):
        pass

    async def _broadcast(self, msg):
        """Send a broadcast, dispatching to the main event loop if needed."""
        if not self.ws_manager:
            return
        if self._main_loop and asyncio.get_event_loop() is not self._main_loop:
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast(msg), self._main_loop
            )
        else:
            await self.ws_manager.broadcast(msg)

    def emit_event_sync(self, event_type, message, data=None):
        """Sync version of emit_event for use when attack runs in a thread."""
        if not self.attack_id:
            return
        event = AttackEvent(self.attack_id, event_type, message, data)
        self.events.append(event)
        if self.ws_manager and self._main_loop:
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast({
                    "type": "attack_event",
                    "attack_id": self.attack_id,
                    "attack_name": self.name,
                    "event": event.to_dict(),
                }), self._main_loop,
            )

    async def emit_event(self, event_type, message, data=None):
        if not self.attack_id:
            return
        event = AttackEvent(self.attack_id, event_type, message, data)
        self.events.append(event)
        await self._broadcast({
            "type": "attack_event",
            "attack_id": self.attack_id,
            "attack_name": self.name,
            "event": event.to_dict(),
        })

    def add_infrastructure_sync(self, resource_type, name, namespace, details=None):
        """Sync version of add_infrastructure for use when attack runs in a thread."""
        entry = {
            "resource_type": resource_type,
            "name": name,
            "namespace": namespace,
            "details": details or {},
            "timestamp": time.time(),
        }
        self.infrastructure_affected.append(entry)
        if self.ws_manager and self._main_loop:
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast({
                    "type": "infrastructure_affected",
                    "attack_id": self.attack_id,
                    "attack_name": self.name,
                    "infrastructure": entry,
                }), self._main_loop,
            )

    async def add_infrastructure(self, resource_type, name, namespace, details=None):
        entry = {
            "resource_type": resource_type,
            "name": name,
            "namespace": namespace,
            "details": details or {},
            "timestamp": time.time(),
        }
        self.infrastructure_affected.append(entry)
        await self._broadcast({
            "type": "infrastructure_affected",
            "attack_id": self.attack_id,
            "attack_name": self.name,
            "infrastructure": entry,
        })

    def cmd_event_sync(self, command: str, output: str, summary: str = ""):
        """Log a kubectl command and its raw output as a structured event."""
        if not self.attack_id:
            return
        event = AttackEvent(self.attack_id, "cmd", summary or command, {
            "command": command,
            "output": output[:2000],
        })
        self.events.append(event)
        if self.ws_manager and self._main_loop:
            asyncio.run_coroutine_threadsafe(
                self.ws_manager.broadcast({
                    "type": "attack_event",
                    "attack_id": self.attack_id,
                    "attack_name": self.name,
                    "event": event.to_dict(),
                }), self._main_loop,
            )

    def kubectl_sync(self, cmd: str, summary: str = "") -> str:
        """Run a kubectl command synchronously (call from within a thread), log cmd+output, return stdout."""
        full_cmd = cmd.split()
        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout or result.stderr
            self.cmd_event_sync(cmd, output, summary or f"kubectl {cmd}")
            return output
        except subprocess.TimeoutExpired:
            self.cmd_event_sync(cmd, "[TIMEOUT]", "Command timed out")
            return ""
        except FileNotFoundError:
            self.cmd_event_sync(cmd, "[kubectl not found]", "kubectl binary missing")
            return ""
        except Exception as e:
            self.cmd_event_sync(cmd, f"[ERROR: {e}]", "Command failed")
            return ""

    async def execute_with_id(self, attack_id):
        self.attack_id = attack_id
        self.status = AttackStatus.RUNNING
        self.start_time = time.time()
        await self.emit_event("start", f"Starting attack: {self.name}", {"severity": self.severity.value})
        try:
            await self.execute()
            self.status = AttackStatus.COMPLETED
            self.end_time = time.time()
            duration = round(self.end_time - self.start_time, 2)
            await self.emit_event("complete", f"Attack completed in {duration}s", {
                "duration": duration,
                "infrastructure_count": len(self.infrastructure_affected),
            })
        except Exception as e:
            self.status = AttackStatus.FAILED
            self.end_time = time.time()
            await self.emit_event("error", f"Attack failed: {str(e)}", {"error": str(e)})
        return self.get_result()

    @abstractmethod
    async def execute(self):
        pass

    def get_result(self):
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "mitre_tactic": self.mitre_tactic,
            "mitre_techniques": self.mitre_techniques,
            "infrastructure_affected": self.infrastructure_affected,
            "events": [e.to_dict() for e in self.events],
            "start_time": self.start_time,
            "end_time": self.end_time,
        }

    def _get_api_client(self):
        return self.cluster_manager.get_api_client()

    def _get_core_api(self):
        return self.cluster_manager.get_core_api()

    def _get_rbac_api(self):
        return self.cluster_manager.get_rbac_api()

    def _get_apps_api(self):
        return self.cluster_manager.get_apps_api()
