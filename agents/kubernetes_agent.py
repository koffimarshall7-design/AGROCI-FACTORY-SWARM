"""Agent KUBERNETES - audit manifests K8s."""
import re
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


K8S_RISKS = {
    "privileged": (r"privileged:\s*true", "critical", "Container privilegie"),
    "host_network": (r"hostNetwork:\s*true", "high", "hostNetwork expose"),
    "host_pid": (r"hostPID:\s*true", "high", "hostPID partage"),
    "host_ipc": (r"hostIPC:\s*true", "high", "hostIPC partage"),
    "host_path": (r"hostPath:", "high", "hostPath monte un dossier hote"),
    "runasroot": (r"runAsUser:\s*0", "high", "Tourne en root"),
    "cluster_admin": (r"cluster-admin", "critical", "Binding cluster-admin"),
    "wildcard_rbac": (r'resources:\s*\n?\s*-\s*["\']?\*["\']?', "high", "RBAC wildcard"),
    "latest_tag": (r"image:\s*\S+:latest", "medium", "Image 'latest'"),
    "allow_privilege": (r"allowPrivilegeEscalation:\s*true", "high", "Privilege escalation"),
    "caps_all": (r'capabilities:[\s\S]{0,100}-\s*ALL', "high", "Toutes capabilities"),
}


class KubernetesAgent(BaseAgent):
    name = "kubernetes"

    def run(self, path):
        root = Path(path)
        print(f"[K8S] audit de {root}")
        findings = []
        k8s_files = 0

        yamls = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
        for y in yamls:
            try:
                content = y.read_text(encoding="utf-8", errors="ignore")
                if not re.search(r"kind:\s*(Deployment|Pod|Service|Ingress|ConfigMap|Secret|Role|ClusterRole|RoleBinding|ClusterRoleBinding|DaemonSet|StatefulSet|Job)", content):
                    continue
                k8s_files += 1
                print(f"[K8S] {y.name}")
                findings += self._audit_file(y, content)
            except Exception:
                pass

        print(f"[K8S] {k8s_files} manifest(s)")

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "path": str(root),
                "k8s_files": k8s_files, "findings": findings}

    def _audit_file(self, y, content):
        out = []
        lines = content.splitlines()
        for name, (regex, sev, reason) in K8S_RISKS.items():
            for m in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                out.append({
                    "type": "k8s_issue", "subtype": name,
                    "file": str(y), "line": line_no,
                    "evidence": lines[line_no - 1].strip()[:100] if line_no <= len(lines) else "",
                    "severity": sev, "reason": reason,
                })
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert K8s security. JSON strict: '
                   '{"validated":[{"type":"","subtype":"","severity":"",'
                   '"impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('subtype')} | {f.get('severity')} | {f.get('file','')}"
                for f in findings[:30])
            r = ask_ai_json(f"K8s findings:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[K8S] llm err: {e}")
            return findings
