"""Agent CONTAINER - scan images Docker (Trivy-like)."""
import subprocess
import shutil
import json
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class ContainerAgent(BaseAgent):
    name = "container"

    def run(self, image=None, path="."):
        """image: nom d'image Docker | path: dossier pour Dockerfiles."""
        findings = []

        # 1. Scan image avec trivy si dispo + image fournie
        if image:
            print(f"[CONTAINER] scan image {image}")
            findings += self._trivy_scan(image)

        # 2. Sinon scan local Docker (containers en cours)
        if not findings:
            print("[CONTAINER] scan containers locaux")
            findings += self._scan_local_containers()

        # 3. Analyse Dockerfiles si path
        if path:
            findings += self._scan_dockerfiles(Path(path))

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "image": image,
                "findings": findings}

    def _trivy_scan(self, image):
        """Utilise trivy si installe."""
        out = []
        trivy = shutil.which("trivy")
        if not trivy:
            print("[CONTAINER] trivy non installe (optionnel)")
            return out
        try:
            r = subprocess.run(
                ["trivy", "image", "--format", "json",
                 "--quiet", "--severity", "HIGH,CRITICAL", image],
                capture_output=True, text=True, timeout=300)
            if r.returncode in (0, 1) and r.stdout:
                data = json.loads(r.stdout)
                for result in data.get("Results", []):
                    for v in result.get("Vulnerabilities", []):
                        out.append({
                            "type": "image_vuln",
                            "image": image,
                            "package": v.get("PkgName"),
                            "version": v.get("InstalledVersion"),
                            "vuln_id": v.get("VulnerabilityID"),
                            "severity": v.get("Severity", "").lower(),
                            "fixed_version": v.get("FixedVersion", ""),
                        })
        except subprocess.TimeoutExpired:
            print("[CONTAINER] trivy timeout")
        except Exception as e:
            print(f"[CONTAINER] trivy err: {e}")
        return out

    def _scan_local_containers(self):
        """Scan des containers Docker en cours."""
        out = []
        try:
            r = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Status}}"],
                capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.split("|")
                    if len(parts) == 3:
                        name, image, status = parts
                        # Verifie si --privileged
                        r2 = subprocess.run(
                            ["docker", "inspect", name, "--format",
                             "{{.HostConfig.Privileged}}"],
                            capture_output=True, text=True, timeout=5)
                        if r2.returncode == 0 and "true" in r2.stdout.lower():
                            out.append({
                                "type": "privileged_container",
                                "name": name, "image": image,
                                "severity": "critical",
                                "reason": "Container tourne en mode privilegie",
                            })
                        # Verifie si root
                        r3 = subprocess.run(
                            ["docker", "inspect", name, "--format",
                             "{{.Config.User}}"],
                            capture_output=True, text=True, timeout=5)
                        if r3.returncode == 0 and not r3.stdout.strip():
                            out.append({
                                "type": "container_root",
                                "name": name, "image": image,
                                "severity": "high",
                                "reason": "Container tourne en root",
                            })
        except FileNotFoundError:
            print("[CONTAINER] docker non installe")
        except Exception as e:
            print(f"[CONTAINER] docker err: {e}")
        return out

    def _scan_dockerfiles(self, root):
        """Scan basique des Dockerfiles."""
        out = []
        if not root.exists():
            return out
        for df in root.rglob("Dockerfile*"):
            try:
                content = df.read_text(errors="ignore")
                if "FROM ubuntu:latest" in content or "FROM alpine:latest" in content:
                    out.append({
                        "type": "container_issue",
                        "file": str(df),
                        "severity": "medium",
                        "reason": "Tag 'latest' dans FROM",
                    })
            except Exception:
                pass
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert container security. JSON strict: '
                   '{"validated":[{"type":"","severity":"",'
                   '"package":"","cve":"","impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('type')} | {f.get('severity')} | {f.get('package','')} | {f.get('vuln_id','')}"
                for f in findings[:30])
            r = ask_ai_json(f"Container findings:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[CONTAINER] llm err: {e}")
            return findings
