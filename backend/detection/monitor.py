import asyncio
import time
from kubernetes import client, watch
from kubernetes.client.rest import ApiException


class DetectionMonitor:
    def __init__(self, cluster_manager, websocket_manager, on_alert=None):
        self.cluster_manager = cluster_manager
        self.ws_manager = websocket_manager
        self.running = False
        self.detection_events = []
        self.on_alert = on_alert
        self.alert_rules = [
            {
                "id": "privileged-pod-creation",
                "name": "Privileged Pod Created",
                "severity": "critical",
                "description": "A pod with privileged security context was created",
                "mitre": {"tactic": "privilege_escalation", "technique": "T1611"},
            },
            {
                "id": "hostpath-mount",
                "name": "HostPath Volume Mount Detected",
                "severity": "high",
                "description": "A pod with hostPath volume was created, potential container escape",
                "mitre": {"tactic": "privilege_escalation", "technique": "T1611"},
            },
            {
                "id": "cluster-admin-binding",
                "name": "Cluster Admin Role Binding",
                "severity": "critical",
                "description": "A new ClusterRoleBinding to cluster-admin was created",
                "mitre": {"tactic": "privilege_escalation", "technique": "T1548.003"},
            },
            {
                "id": "secret-access",
                "name": "Secrets Access Detected",
                "severity": "high",
                "description": "Multiple secrets being accessed in short time",
                "mitre": {"tactic": "credential_access", "technique": "T1552.007"},
            },
            {
                "id": "api-discovery",
                "name": "API Resource Discovery",
                "severity": "medium",
                "description": "Multiple API resource types being enumerated",
                "mitre": {"tactic": "discovery", "technique": "T1613"},
            },
            {
                "id": "host-network",
                "name": "Host Network Pod",
                "severity": "high",
                "description": "Pod with hostNetwork:true detected",
                "mitre": {"tactic": "defense_evasion", "technique": "T1612"},
            },
            {
                "id": "host-pid",
                "name": "Host PID Namespace",
                "severity": "high",
                "description": "Pod with hostPID:true detected, potential container escape",
                "mitre": {"tactic": "privilege_escalation", "technique": "T1611"},
            },
        ]
        self.alert_counts = {rule["id"]: 0 for rule in self.alert_rules}
        self._watch_tasks = []

    async def start_monitoring(self):
        if self.running:
            return
        self.running = True
        await self.emit("monitor_started", "Detection monitoring started")

        self._watch_tasks = [
            asyncio.create_task(self._watch_pods()),
            asyncio.create_task(self._watch_rbac()),
        ]

    async def stop_monitoring(self):
        self.running = False
        for task in self._watch_tasks:
            task.cancel()
        self._watch_tasks = []
        await self.emit("monitor_stopped", "Detection monitoring stopped")

    async def _watch_pods(self):
        loop = asyncio.get_event_loop()
        while self.running:
            try:
                core = self.cluster_manager.get_core_api()
                w = watch.Watch()

                def _sync_pod_watch():
                    for event in w.stream(core.list_pod_for_all_namespaces, timeout_seconds=30):
                        if not self.running:
                            break
                        asyncio.run_coroutine_threadsafe(
                            self._analyze_pod_event(event), loop
                        )
                    w.stop()

                await asyncio.to_thread(_sync_pod_watch)
            except ApiException:
                if self.running:
                    await asyncio.sleep(5)
            except Exception:
                if self.running:
                    await asyncio.sleep(5)

    async def _watch_rbac(self):
        loop = asyncio.get_event_loop()
        while self.running:
            try:
                rbac = self.cluster_manager.get_rbac_api()
                w = watch.Watch()

                def _sync_rbac_watch():
                    for event in w.stream(rbac.list_cluster_role_binding, timeout_seconds=30):
                        if not self.running:
                            break
                        asyncio.run_coroutine_threadsafe(
                            self._analyze_rbac_event(event), loop
                        )
                    w.stop()

                await asyncio.to_thread(_sync_rbac_watch)
            except ApiException:
                if self.running:
                    await asyncio.sleep(5)
            except Exception:
                if self.running:
                    await asyncio.sleep(5)

    async def _analyze_pod_event(self, event):
        obj = event.get("object")
        event_type = event.get("type", "")
        if not obj or not hasattr(obj, "spec") or not obj.spec:
            return

        security_context = obj.spec.containers[0].security_context if obj.spec.containers else None
        pod_name = obj.metadata.name
        namespace = obj.metadata.namespace

        findings = []

        if event_type == "ADDED" or event_type == "MODIFIED":
            if security_context and security_context.privileged:
                findings.append(("critical", "privileged-pod-creation", {
                    "pod": pod_name,
                    "namespace": namespace,
                }))

            if obj.spec.volumes:
                for vol in obj.spec.volumes:
                    if vol.host_path:
                        findings.append(("high", "hostpath-mount", {
                            "pod": pod_name,
                            "namespace": namespace,
                            "host_path": vol.host_path.path,
                        }))
                        break

            if obj.spec.host_network:
                findings.append(("high", "host-network", {
                    "pod": pod_name,
                    "namespace": namespace,
                }))

            if obj.spec.host_pid:
                findings.append(("high", "host-pid", {
                    "pod": pod_name,
                    "namespace": namespace,
                }))

        for severity, alert_id, details in findings:
            await self._trigger_alert(alert_id, severity, details)

    async def _analyze_rbac_event(self, event):
        obj = event.get("object")
        event_type = event.get("type", "")
        if not obj or not hasattr(obj, "role_ref"):
            return

        if event_type == "ADDED":
            if obj.role_ref and obj.role_ref.name == "cluster-admin":
                await self._trigger_alert("cluster-admin-binding", "critical", {
                    "binding_name": obj.metadata.name,
                    "subjects": [
                        {"kind": s.kind, "name": s.name, "namespace": s.namespace}
                        for s in (obj.subjects or [])
                    ],
                })

    async def _trigger_alert(self, alert_id, severity, details):
        alert_rule = next((r for r in self.alert_rules if r["id"] == alert_id), None)
        if not alert_rule:
            return

        self.alert_counts[alert_id] += 1
        event = {
            "id": f"{alert_id}-{int(time.time())}",
            "alert_id": alert_id,
            "name": alert_rule["name"],
            "severity": severity,
            "description": alert_rule["description"],
            "mitre": alert_rule["mitre"],
            "details": details,
            "timestamp": time.time(),
            "count": self.alert_counts[alert_id],
        }
        self.detection_events.append(event)

        if len(self.detection_events) > 500:
            self.detection_events = self.detection_events[-500:]

        await self.emit("detection_alert", f"Alert: {alert_rule['name']}", event)

        if self.on_alert and severity in ("critical", "high"):
            self.on_alert({
                "type": "detection_alert",
                "name": alert_rule["name"],
                "severity": severity,
                "description": alert_rule["description"],
                "infrastructure": [details],
                "detection_events": [event],
            })

    async def emit(self, event_type, message, data=None):
        if self.ws_manager:
            await self.ws_manager.broadcast({
                "type": event_type,
                "message": message,
                "data": data or {},
                "source": "detection",
            })

    def get_events(self, limit=50):
        return self.detection_events[-limit:]

    def get_alert_summary(self):
        return {
            rule["id"]: {
                "name": rule["name"],
                "severity": rule["severity"],
                "count": self.alert_counts[rule["id"]],
                "mitre": rule["mitre"],
            }
            for rule in self.alert_rules
        }

    def get_alerts_by_severity(self):
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for rule in self.alert_rules:
            summary[rule["severity"]] += self.alert_counts[rule["id"]]
        return summary
