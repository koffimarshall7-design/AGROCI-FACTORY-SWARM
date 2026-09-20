"""Agent DEPENDENCIES - audit des dependances (pip, npm) vs CVE."""
import json
import re
import subprocess
from pathlib import Path
import httpx
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class DependenciesAgent(BaseAgent):
    name = "dependencies"

    def __init__(self):
        super().__init__()
        self.client = httpx.Client(timeout=15)

    def run(self, path="."):
        root = Path(path)
        print(f"[DEPS] audit de {root}")

        findings = []

        # 1. requirements.txt (Python)
        req = root / "requirements.txt"
        if req.exists():
            findings += self._audit_pip(req)

        # 2. package.json (Node)
        pkg = root / "package.json"
        if pkg.exists():
            findings += self._audit_npm(pkg)

        # 3. Analyse LLM finale
        if findings:
            findings = self._analyze(findings)

        return {
            "agent": self.name,
            "path": str(root),
            "findings": findings,
        }

    def _audit_pip(self, req_file):
        out = []
        try:
            r = subprocess.run(
                ["pip-audit", "-r", str(req_file), "--format=json"],
                capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and r.stdout:
                data = json.loads(r.stdout)
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        out.append({
                            "type": "vulnerable_dependency",
                            "ecosystem": "pip",
                            "package": dep.get("name"),
                            "version": dep.get("version"),
                            "vuln_id": vuln.get("id"),
                            "severity": "high",
                            "fix_versions": vuln.get("fix_versions", []),
                            "description": vuln.get("description", "")[:300],
                        })
        except FileNotFoundError:
            print("[DEPS] pip-audit non installe (pip install pip-audit)")
        except Exception as e:
            print(f"[DEPS] erreur pip-audit: {e}")
        return out

    def _audit_npm(self, pkg_file):
        out = []
        try:
            r = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True,
                cwd=str(pkg_file.parent), timeout=120)
            if r.stdout:
                data = json.loads(r.stdout)
                for name, adv in data.get("vulnerabilities", {}).items():
                    out.append({
                        "type": "vulnerable_dependency",
                        "ecosystem": "npm",
                        "package": name,
                        "severity": adv.get("severity", "medium"),
                        "via": [v.get("title") for v in adv.get("via", [])
                                if isinstance(v, dict)][:3],
                        "fix_available": adv.get("fixAvailable", False),
                    })
        except FileNotFoundError:
            print("[DEPS] npm non installe")
        except Exception as e:
            print(f"[DEPS] erreur npm: {e}")
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert supply-chain security. JSON strict: '
                   '{"validated":[{"package":"","severity":"",'
                   '"cve":"","impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f['package']}@{f.get('version','?')} | {f.get('vuln_id','')} | {f.get('severity')}"
                for f in findings[:20])
            r = ask_ai_json(f"Deps vulnerables:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[DEPS] llm err: {e}")
            return findings
