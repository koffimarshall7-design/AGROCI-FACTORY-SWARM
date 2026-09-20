"""Agent CICD - audit GitHub Actions, GitLab CI, Jenkins."""
import re
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


CICD_RISKS = {
    "pull_request_target": (r"on:\s*[\s\S]*pull_request_target", "critical", "pull_request_target = RCE via fork PR"),
    "write_all": (r"permissions:\s*write-all", "high", "permissions write-all"),
    "secrets_in_pr": (r"pull_request[\s\S]{0,200}\$\{\{\s*secrets\.", "high", "Secrets aux PR externes"),
    "script_injection": (r"\$\{\{\s*github\.event\.(issue|pull_request|comment)\.(title|body|head_ref)", "critical", "Script injection"),
    "unpinned_action": (r"uses:\s*\S+@(?:main|master|v\d+)\s*$", "medium", "Action non pinnee"),
    "self_hosted": (r"runs-on:\s*self-hosted", "high", "Self-hosted runner"),
    "secrets_echo": (r"(?i)(echo|print)\s+.*\$CI_.*SECRET", "high", "Secret CI affiche"),
    "docker_privileged": (r"privileged:\s*true", "critical", "Docker privilegie"),
    "curl_bash": (r"curl\s+[^|]+\|\s*(?:ba)?sh", "high", "curl | bash"),
    "secret_plain": (r"(?i)(password|token|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9]{20,}", "critical", "Secret en clair"),
}


class CICDAgent(BaseAgent):
    name = "cicd"

    def run(self, path):
        root = Path(path)
        print(f"[CICD] audit de {root}")
        findings = []
        ci_files = []

        gh_dir = root / ".github" / "workflows"
        if gh_dir.exists():
            ci_files += list(gh_dir.glob("*.yml")) + list(gh_dir.glob("*.yaml"))
        ci_files += list(root.rglob(".gitlab-ci.yml"))
        ci_files += list(root.rglob("Jenkinsfile*"))
        ci_files += list(root.rglob("azure-pipelines.yml"))
        ci_files += list(root.rglob(".circleci/config.yml"))

        for ci in ci_files:
            try:
                content = ci.read_text(encoding="utf-8", errors="ignore")
                print(f"[CICD] {ci.name}")
                findings += self._audit_file(ci, content)
            except Exception:
                pass

        print(f"[CICD] {len(ci_files)} fichier(s)")

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "path": str(root),
                "ci_files": len(ci_files), "findings": findings}

    def _audit_file(self, ci, content):
        out = []
        for name, (regex, sev, reason) in CICD_RISKS.items():
            for m in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                evidence = m.group(0)[:120]
                if "secret" in name or "credential" in name:
                    evidence = re.sub(r'[A-Za-z0-9]{20,}', '***', evidence)
                out.append({
                    "type": "cicd_issue", "subtype": name,
                    "file": str(ci), "line": line_no,
                    "evidence": evidence, "severity": sev, "reason": reason,
                })
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert CI/CD security. JSON strict: '
                   '{"validated":[{"type":"","subtype":"","severity":"",'
                   '"impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('subtype')} | {f.get('severity')} | {f.get('file','')}"
                for f in findings[:30])
            r = ask_ai_json(f"CICD findings:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[CICD] llm err: {e}")
            return findings
