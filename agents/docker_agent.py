"""Agent DOCKER - audit Dockerfiles, compose, images."""
import re
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


DOCKERFILE_RISKS = {
    "curl_pipe_bash": (r"curl.*\|\s*(ba)?sh", "high", "curl | bash = RCE possible"),
    "wget_pipe_bash": (r"wget.*\|\s*(ba)?sh", "high", "wget | bash = RCE possible"),
    "latest_tag": (r"^FROM\s+\S+:latest", "medium", "Tag 'latest' non reproductible"),
    "secrets_in_env": (r"ENV\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*\S+", "critical", "Secret hardcode dans image"),
    "chmod_777": (r"chmod\s+(?:-R\s+)?777", "medium", "Permissions 777 trop larges"),
    "sudo_usage": (r"\bsudo\b", "low", "sudo dans container"),
    "apt_no_recommends": (r"apt-get install(?!.*--no-install-recommends)", "low", "Image + grosse"),
    "add_instead_copy": (r"^ADD\s+(?!https)", "low", "ADD au lieu de COPY"),
}

COMPOSE_RISKS = {
    "privileged: true": ("privileged_mode", "critical", "Container privilegie"),
    "network_mode: host": ("host_network", "high", "Reseau hote partage"),
    "pid: host": ("host_pid", "high", "PID namespace partage"),
    "ipc: host": ("host_ipc", "medium", "IPC partage"),
    "/var/run/docker.sock": ("docker_sock", "critical", "Socket Docker monte"),
}


class DockerAgent(BaseAgent):
    name = "docker"

    def run(self, path):
        root = Path(path)
        print(f"[DOCKER] audit de {root}")
        findings = []

        dockerfiles = list(root.rglob("Dockerfile*")) + list(root.rglob("*.dockerfile"))
        compose_files = list(root.rglob("docker-compose*.yml")) + \
                        list(root.rglob("docker-compose*.yaml")) + \
                        list(root.rglob("compose*.yml"))

        for df in dockerfiles:
            print(f"[DOCKER] {df.name}")
            findings += self._audit_dockerfile(df)

        for cf in compose_files:
            print(f"[DOCKER] {cf.name}")
            findings += self._audit_compose(cf)

        print(f"[DOCKER] {len(dockerfiles)} Dockerfile(s), {len(compose_files)} compose(s)")

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "path": str(root),
                "dockerfiles": len(dockerfiles) + len(compose_files),
                "findings": findings}

    def _audit_dockerfile(self, df):
        out = []
        content = df.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        # Verifie USER absent
        if "USER " not in content.upper():
            out.append({
                "type": "dockerfile_issue", "subtype": "root_user",
                "file": str(df), "line": 1, "severity": "medium",
                "reason": "Container tourne en root (pas de USER)",
            })

        for name, (regex, sev, reason) in DOCKERFILE_RISKS.items():
            for m in re.finditer(regex, content, re.IGNORECASE | re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                out.append({
                    "type": "dockerfile_issue", "subtype": name,
                    "file": str(df), "line": line_no,
                    "evidence": m.group(0)[:100],
                    "severity": sev, "reason": reason,
                })
        return out

    def _audit_compose(self, cf):
        out = []
        try:
            content = cf.read_text(encoding="utf-8", errors="ignore")
            for pattern, (sub, sev, reason) in COMPOSE_RISKS.items():
                if pattern in content:
                    out.append({
                        "type": "compose_issue", "subtype": sub,
                        "file": str(cf), "severity": sev, "reason": reason,
                    })
        except Exception:
            pass
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert Docker security. JSON strict: '
                   '{"validated":[{"type":"","subtype":"","severity":"",'
                   '"impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('subtype')} | {f.get('severity')} | {f.get('file','')}"
                for f in findings[:30])
            r = ask_ai_json(f"Docker findings:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[DOCKER] llm err: {e}")
            return findings
