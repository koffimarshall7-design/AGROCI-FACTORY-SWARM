"""Agent SBOM - Software Bill of Materials + CVE mapping via OSV.dev."""
import json
from pathlib import Path
import httpx
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class SBOMAgent(BaseAgent):
    name = "sbom"

    def __init__(self):
        super().__init__()
        self.client = httpx.Client(timeout=15)

    def run(self, path):
        root = Path(path)
        print(f"[SBOM] generation SBOM de {root}")

        components = []
        components += self._read_python(root)
        components += self._read_node(root)
        components += self._read_go(root)
        components += self._read_docker_base(root)

        print(f"[SBOM] {len(components)} composant(s)")

        findings = self._check_osv(components)

        if findings:
            findings = self._analyze(findings)

        sbom = self._to_cyclonedx(components)

        return {"agent": self.name, "path": str(root),
                "components_count": len(components),
                "components": components[:50],
                "sbom_cyclonedx": sbom,
                "findings": findings}

    def _read_python(self, root):
        comps = []
        seen = set()
        for req in root.rglob("requirements*.txt"):
            if not req.exists():
                continue
            for line in req.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = line.split("==") if "==" in line else line.split(">=")
                if len(m) == 2:
                    name = m[0].strip()
                    ver = m[1].strip().split()[0]
                    key = f"pypi:{name}"
                    if key not in seen:
                        seen.add(key)
                        comps.append({"name": name, "version": ver, "ecosystem": "PyPI"})
        return comps

    def _read_node(self, root):
        comps = []
        for pkg in root.rglob("package.json"):
            if "node_modules" in str(pkg):
                continue
            try:
                data = json.loads(pkg.read_text())
                for name, ver in {**data.get("dependencies", {}),
                                  **data.get("devDependencies", {})}.items():
                    comps.append({"name": name,
                                  "version": ver.lstrip("^~>=").split()[0],
                                  "ecosystem": "npm"})
            except Exception:
                pass
        return comps

    def _read_go(self, root):
        comps = []
        for go_mod in root.rglob("go.mod"):
            in_req = False
            for line in go_mod.read_text().splitlines():
                if line.startswith("require"):
                    in_req = True
                    continue
                if in_req and line.strip().startswith(")"):
                    break
                if in_req and line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        comps.append({"name": parts[0],
                                      "version": parts[1].lstrip("v"),
                                      "ecosystem": "Go"})
        return comps

    def _read_docker_base(self, root):
        comps = []
        for df in root.rglob("Dockerfile*"):
            for line in df.read_text(errors="ignore").splitlines():
                if line.strip().upper().startswith("FROM "):
                    img = line.split()[1]
                    if img.lower() != "scratch":
                        parts = img.split(":")
                        comps.append({"name": parts[0],
                                      "version": parts[1] if len(parts) > 1 else "latest",
                                      "ecosystem": "Docker"})
        return comps

    def _check_osv(self, components):
        """Interroge OSV.dev pour chaque composant."""
        out = []
        for c in components[:20]:  # limite pour eviter rate limit
            ecosystem_map = {"PyPI": "PyPI", "npm": "npm", "Go": "Go"}
            eco = ecosystem_map.get(c["ecosystem"])
            if not eco:
                continue
            try:
                r = self.client.post(
                    "https://api.osv.dev/v1/query",
                    json={"package": {"name": c["name"], "ecosystem": eco},
                          "version": c["version"]})
                if r.status_code == 200:
                    data = r.json()
                    for v in data.get("vulns", []):
                        out.append({
                            "type": "vulnerable_dependency",
                            "package": c["name"],
                            "version": c["version"],
                            "ecosystem": c["ecosystem"],
                            "vuln_id": v.get("id"),
                            "severity": self._osv_severity(v),
                            "summary": v.get("summary", "")[:200],
                        })
            except Exception:
                pass
        if out:
            print(f"[SBOM] {len(out)} CVE trouvee(s)")
        return out

    def _osv_severity(self, vuln):
        """Extrait la severite d'un OSV."""
        for sev in vuln.get("severity", []):
            score = sev.get("score", "")
            if "CVSS" in score:
                try:
                    from cvss import CVSS3
                    c = CVSS3(score)
                    return c.severities()[0].lower()
                except Exception:
                    pass
        return "medium"

    def _to_cyclonedx(self, components):
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {"type": "library",
                 "name": c["name"], "version": c["version"],
                 "purl": f"pkg:{c['ecosystem'].lower()}/{c['name']}@{c['version']}"}
                for c in components
            ],
        }

    def _analyze(self, findings):
        try:
            sys = ('Expert supply-chain. JSON strict: '
                   '{"validated":[{"package":"","severity":"",'
                   '"cve":"","impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('package')}@{f.get('version')} | {f.get('vuln_id')}"
                for f in findings[:20])
            r = ask_ai_json(f"Vulns:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[SBOM] llm err: {e}")
            return findings
