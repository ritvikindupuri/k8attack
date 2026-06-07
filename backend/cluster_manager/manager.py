import asyncio
import json
import os
import subprocess
import tempfile
import yaml
from typing import Optional
from kubernetes import client, config
from kubernetes.client.rest import ApiException


def _new_core_api():
    """Create a fresh CoreV1Api client (thread-safe)."""
    try:
        config.load_kubeconfig()
        return client.CoreV1Api()
    except Exception:
        config.load_kube_config(config_file=os.path.expanduser("~/.kube/config"))
        return client.CoreV1Api()


def _new_rbac_api():
    try:
        config.load_kubeconfig()
        return client.RbacAuthorizationV1Api()
    except Exception:
        config.load_kube_config(config_file=os.path.expanduser("~/.kube/config"))
        return client.RbacAuthorizationV1Api()


def _new_apps_api():
    try:
        config.load_kubeconfig()
        return client.AppsV1Api()
    except Exception:
        config.load_kube_config(config_file=os.path.expanduser("~/.kube/config"))
        return client.AppsV1Api()


CLUSTER_NAME = "k8s-attack-lab"


class ClusterManager:
    def __init__(self, websocket_manager=None):
        self.ws_manager = websocket_manager
        self.cluster_name = CLUSTER_NAME
        self._core_api = None
        self._rbac_api = None
        self._apps_api = None
        self._ready = False
        self._namespace = "default"

    async def emit(self, event_type, message, data=None):
        if self.ws_manager:
            await self.ws_manager.broadcast({
                "type": event_type,
                "message": message,
                "data": data or {},
                "source": "cluster_manager",
            })

    async def check_prerequisites(self) -> dict:
        missing = []
        for cmd in ["kind", "kubectl", "docker"]:
            result = await asyncio.to_thread(
                subprocess.run, ["which", cmd], capture_output=True, text=True
            )
            if result.returncode != 0:
                missing.append(cmd)

        docker_running = False
        if "docker" not in missing:
            result = await asyncio.to_thread(
                subprocess.run, ["docker", "info"], capture_output=True, text=True, timeout=10
            )
            docker_running = result.returncode == 0

        return {
            "ready": len(missing) == 0 and docker_running,
            "missing": missing,
            "docker_running": docker_running,
        }

    async def create_cluster(self) -> dict:
        status = await self.check_prerequisites()
        if not status["ready"]:
            await self.emit("cluster_error", f"Prerequisites not met", status)
            return {"success": False, "error": f"Missing: {status['missing']}. Docker running: {status['docker_running']}"}

        # Delete existing cluster with the same name before creating
        try:
            existing = await asyncio.to_thread(
                subprocess.run, ["kind", "get", "clusters"], capture_output=True, text=True, timeout=30
            )
            if self.cluster_name in existing.stdout:
                await self.emit("cluster_creating", f"Removing existing cluster: {self.cluster_name}")
                await asyncio.to_thread(
                    subprocess.run, ["kind", "delete", "cluster", "--name", self.cluster_name],
                    capture_output=True, text=True, timeout=120,
                )
                self._ready = False
                self._core_api = None
                await asyncio.sleep(3)
        except Exception:
            pass

        await self.emit("cluster_creating", f"Creating kind cluster: {self.cluster_name}")

        kind_config = {
            "kind": "Cluster",
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "name": self.cluster_name,
            "nodes": [
                {
                    "role": "control-plane",
                    "extraPortMappings": [
                        {"containerPort": 30000, "hostPort": 30000},
                        {"containerPort": 30001, "hostPort": 30001},
                    ],
                },
                {"role": "worker"},
                {"role": "worker"},
            ],
            "networking": {
                "apiServerAddress": "127.0.0.1",
                "podSubnet": "10.244.0.0/16",
                "serviceSubnet": "10.96.0.0/12",
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(kind_config, f)
            config_path = f.name

        await self.emit("cluster_creating", "Running kind create cluster...", {
            "config": kind_config,
        })

        try:
            result = await asyncio.to_thread(
                subprocess.run, ["kind", "create", "cluster", "--config", config_path],
                capture_output=True, text=True, timeout=300,
            )
            os.unlink(config_path)

            if result.returncode != 0:
                await self.emit("cluster_error", f"Cluster creation failed", {
                    "error": result.stderr,
                })
                return {"success": False, "error": result.stderr}

            await self.emit("cluster_ready", f"Cluster {self.cluster_name} created successfully", {
                "output": result.stdout,
            })
        except subprocess.TimeoutExpired:
            os.unlink(config_path)
            await self.emit("cluster_error", "Cluster creation timed out", {})
            return {"success": False, "error": "Timed out creating cluster"}
        except FileNotFoundError:
            await self.emit("cluster_error", "kind command not found", {})
            return {"success": False, "error": "kind not installed"}

        await asyncio.to_thread(self._init_k8s_client)
        await self._setup_vulnerable_configs()

        cluster_info = await self.get_cluster_info()
        return {"success": True, "cluster_info": cluster_info}

    async def _setup_vulnerable_configs(self):
        await self.emit("cluster_configuring", "Setting up vulnerable configurations for attack scenarios")

        try:
            configs = [
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": "attack-targets",
                        "labels": {"purpose": "security-testing"},
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {
                        "name": "vulnerable-sa",
                        "namespace": "default",
                    },
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {
                        "name": "vulnerable-role",
                        "namespace": "default",
                    },
                    "rules": [
                        {"apiGroups": [""], "resources": ["pods", "secrets", "configmaps", "services"],
                         "verbs": ["get", "list", "watch", "create", "delete"]},
                        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings", "clusterrolebindings"],
                         "verbs": ["get", "list", "create", "bind"]},
                        {"apiGroups": ["apps"], "resources": ["deployments", "statefulsets"],
                         "verbs": ["get", "list", "create", "update", "delete"]},
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {
                        "name": "vulnerable-binding",
                        "namespace": "default",
                    },
                    "subjects": [{"kind": "ServiceAccount", "name": "vulnerable-sa", "namespace": "default"}],
                    "roleRef": {"kind": "Role", "name": "vulnerable-role", "apiGroup": "rbac.authorization.k8s.io"},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "demo-db-credentials", "namespace": "default"},
                    "type": "Opaque",
                    "stringData": {
                        "username": "admin",
                        "password": "P@ssw0rd!2024",
                        "connection_string": "postgresql://admin:P@ssw0rd!2024@db.internal:5432/production",
                        "api_key": "sk-prod-8a7f9e2b1c3d4e5f6a7b8c9d0e1f2a3b",
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "demo-tls-certs", "namespace": "default"},
                    "type": "kubernetes.io/tls",
                    "stringData": {
                        "tls.crt": "-----BEGIN CERTIFICATE-----\nMIIBkzCCATigAwIBAgIUEXAMPLE\n-----END CERTIFICATE-----",
                        "tls.key": "-----BEGIN PRIVATE KEY-----\nMIIBkzCCATigAwIBAgIUEXAMPLE\n-----END PRIVATE KEY-----",
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": "app-config", "namespace": "default"},
                    "data": {
                        "app.env": "production",
                        "app.debug": "false",
                        "database.host": "db.internal",
                        "database.port": "5432",
                        "redis.host": "redis.internal",
                        "redis.port": "6379",
                        "aws.access_key_id": "AKIAIOSFODNN7EXAMPLE",
                        "aws.region": "us-east-1",
                    },
                },
            ]

            for cfg in configs:
                try:
                    await asyncio.to_thread(self._apply_manifest, cfg)
                except Exception as e:
                    await self.emit("cluster_warning", f"Failed to apply {cfg.get('kind')}: {e}", {})

            await self.emit("cluster_ready", "Vulnerable configurations applied", {})
        except Exception as e:
            await self.emit("cluster_error", f"Configuration setup failed: {e}", {})

    def _apply_manifest(self, manifest):
        kind = manifest.get("kind", "").lower()
        ns = manifest.get("metadata", {}).get("namespace", "default")

        if kind == "namespace":
            try:
                self._get_core_api().read_namespace(manifest["metadata"]["name"])
                return
            except ApiException:
                self._get_core_api().create_namespace(manifest)
        elif kind == "serviceaccount":
            try:
                self._get_core_api().read_namespaced_service_account(manifest["metadata"]["name"], ns)
                return
            except ApiException:
                self._get_core_api().create_namespaced_service_account(ns, manifest)
        elif kind == "role":
            try:
                self._get_rbac_api().read_namespaced_role(manifest["metadata"]["name"], ns)
                return
            except ApiException:
                self._get_rbac_api().create_namespaced_role(ns, manifest)
        elif kind == "rolebinding":
            try:
                self._get_rbac_api().read_namespaced_role_binding(manifest["metadata"]["name"], ns)
                return
            except ApiException:
                self._get_rbac_api().create_namespaced_role_binding(ns, manifest)
        elif kind == "secret":
            try:
                self._get_core_api().read_namespaced_secret(manifest["metadata"]["name"], ns)
                return
            except ApiException:
                self._get_core_api().create_namespaced_secret(ns, manifest)
        elif kind == "configmap":
            try:
                self._get_core_api().read_namespaced_config_map(manifest["metadata"]["name"], ns)
                return
            except ApiException:
                self._get_core_api().create_namespaced_config_map(ns, manifest)

    async def delete_cluster(self) -> dict:
        try:
            result = await asyncio.to_thread(
                subprocess.run, ["kind", "delete", "cluster", "--name", self.cluster_name],
                capture_output=True, text=True, timeout=120,
            )
            self._ready = False
            self._core_api = None
            self._rbac_api = None
            self._apps_api = None

            if result.returncode == 0:
                await self.emit("cluster_deleted", f"Cluster {self.cluster_name} deleted", {})
                return {"success": True}
            else:
                await self.emit("cluster_error", f"Failed to delete cluster: {result.stderr}", {})
                return {"success": False, "error": result.stderr}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timed out deleting cluster"}

    async def get_cluster_info(self) -> dict:
        if not self._ready:
            try:
                await asyncio.to_thread(self._init_k8s_client)
            except Exception as e:
                return {"ready": False, "error": str(e)}

        try:
            def _fetch_info():
                core = self._get_core_api()
                nodes = core.list_node()
                pods = core.list_pod_for_all_namespaces()
                services = core.list_service_for_all_namespaces()
                namespaces = core.list_namespace()
                return nodes, pods, services, namespaces

            nodes, pods, services, namespaces = await asyncio.to_thread(_fetch_info)

            return {
                "ready": True,
                "name": self.cluster_name,
                "nodes": [
                    {
                        "name": n.metadata.name,
                        "status": n.status.conditions[-1].type if n.status.conditions else "Unknown",
                        "kubelet": n.status.node_info.kubelet_version,
                        "os": n.status.node_info.os_image,
                        "arch": n.status.node_info.architecture,
                        "ip": n.status.addresses[0].address if n.status.addresses else "N/A",
                        "capacity": {
                            "cpu": n.status.capacity.get("cpu"),
                            "memory": n.status.capacity.get("memory"),
                            "pods": n.status.capacity.get("pods"),
                        },
                    }
                    for n in nodes.items
                ],
                "pods": [
                    {
                        "name": p.metadata.name,
                        "namespace": p.metadata.namespace,
                        "node": p.spec.node_name,
                        "status": p.status.phase,
                        "ip": p.status.pod_ip,
                        "containers": len(p.spec.containers),
                    }
                    for p in pods.items
                ],
                "services": [
                    {
                        "name": s.metadata.name,
                        "namespace": s.metadata.namespace,
                        "cluster_ip": s.spec.cluster_ip,
                        "type": s.spec.type,
                        "ports": [
                            {"port": p.port, "target_port": p.target_port, "protocol": p.protocol}
                            for p in s.spec.ports
                        ] if s.spec.ports else [],
                    }
                    for s in services.items
                ],
                "namespaces": [ns.metadata.name for ns in namespaces.items],
                "pod_count": len(pods.items),
                "service_count": len(services.items),
                "node_count": len(nodes.items),
                "namespace_count": len(namespaces.items),
            }
        except Exception as e:
            return {"ready": False, "error": str(e)}

    def _init_k8s_client(self):
        try:
            config.load_kubeconfig()
            self._core_api = client.CoreV1Api()
            self._rbac_api = client.RbacAuthorizationV1Api()
            self._apps_api = client.AppsV1Api()
            self._ready = True
        except Exception as e:
            # Try loading from default location
            kubeconfig_path = os.path.expanduser("~/.kube/config")
            if os.path.exists(kubeconfig_path):
                config.load_kube_config(config_file=kubeconfig_path)
                self._core_api = client.CoreV1Api()
                self._rbac_api = client.RbacAuthorizationV1Api()
                self._apps_api = client.AppsV1Api()
                self._ready = True
            else:
                raise Exception(f"Cannot connect to cluster: {e}")

    def get_api_client(self):
        return client.ApiClient()

    def _get_core_api(self):
        if not self._core_api:
            self._init_k8s_client()
        return self._core_api

    def _get_rbac_api(self):
        if not self._rbac_api:
            self._init_k8s_client()
        return self._rbac_api

    def _get_apps_api(self):
        if not self._apps_api:
            self._init_k8s_client()
        return self._apps_api

    def get_core_api(self):
        return _new_core_api()

    def get_rbac_api(self):
        return _new_rbac_api()

    def get_apps_api(self):
        return _new_apps_api()

    def is_ready(self):
        if not self._ready:
            try:
                self._init_k8s_client()
            except Exception:
                pass
        return self._ready
