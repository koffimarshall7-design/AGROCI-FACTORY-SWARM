"""Orchestrateur 25-agents - pipeline complet DevSecOps."""
import json
from datetime import datetime, timezone
from pathlib import Path

# Core agents
from agents.red_agent import RedAgent
from agents.blue_agent import BlueAgent
from agents.purple_agent import PurpleAgent
from agents.web_agent import WebAgent
from agents.network_agent import NetworkAgent
from agents.critic_agent import CriticAgent
from agents.exploit_agent import ExploitAgent
from agents.stealth_agent import StealthAgent
from agents.risk_agent import RiskAgent
from agents.report_agent import ReportAgent
from agents.notify_agent import NotifyAgent
from agents.bugbounty_agent import BugBountyAgent
from agents.compliance_agent import ComplianceAgent
# Nouveaux
from agents.code_agent import CodeAgent
from agents.cloud_agent import CloudAgent
from agents.mobile_agent import MobileAgent
from agents.iot_agent import IOTAgent
from agents.wireless_agent import WirelessAgent
from agents.api_agent import APIAgent
# DevOps
from agents.secrets_agent import SecretsAgent
from agents.docker_agent import DockerAgent
from agents.kubernetes_agent import KubernetesAgent
from agents.terraform_agent import TerraformAgent
from agents.cicd_agent import CICDAgent
from agents.sbom_agent import SBOMAgent
from agents.container_agent import ContainerAgent

from core.memory import Memory
from core.exceptions import ScopeError


class Orchestrator:
    def __init__(self, scope, enforce_bugbounty=False):
        if not scope:
            raise ValueError("Scope vide")
        self.scope = list(scope)
        self.enforce_bb = enforce_bugbounty

        # Offensifs
        self.red = RedAgent()
        self.web = WebAgent()
        self.network = NetworkAgent()
        self.stealth = StealthAgent()
        self.exploit = ExploitAgent()
        self.api = APIAgent()
        self.iot = IOTAgent()
        self.wireless = WirelessAgent()
        self.mobile = MobileAgent()
        # DevOps
        self.secrets = SecretsAgent()
        self.docker = DockerAgent()
        self.kubernetes = KubernetesAgent()
        self.terraform = TerraformAgent()
        self.cicd = CICDAgent()
        self.sbom = SBOMAgent()
        self.container = ContainerAgent()
        # Autres
        self.code = CodeAgent()
        self.cloud = CloudAgent()
        self.compliance = ComplianceAgent()
        # Validation
        self.critic = CriticAgent()
        # Synthese
        self.risk = RiskAgent()
        self.blue = BlueAgent()
        self.purple = PurpleAgent()
        # Sortie
        self.report = ReportAgent()
        self.notify = NotifyAgent()
        self.bugbounty = BugBountyAgent()
        # Memoire
        self.memory = Memory()

        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)

    def _verify_scope(self, target):
        if not self.enforce_bb:
            return True
        check = self.bugbounty.run(target, mode="check")
        if not check.get("authorized"):
            raise ScopeError(f"'{target}' n'est dans AUCUN programme declare.")
        print(f"[ORCH] scope valide pour {target}")
        return True

    def run(self, objective, send_report=True, notify=True):
        target = self.scope[0]
        is_url = target.startswith(("http://", "https://"))
        is_path = target.startswith(("./", "/", "~")) or Path(target).exists()

        self._verify_scope(target)

        print(f"\n{'='*60}")
        print(f">>> Orchestrateur 25-agents | cible = {target}")
        print(f"{'='*60}")

        history = self.memory.target_history(target)
        if history:
            print(f"[MEMORY] {len(history)} scan(s) precedent(s)")

        report = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "objective": objective,
            "scope": self.scope,
            "history": history,
        }
        all_findings = []

        # ============ MODE CODE LOCAL ============
        if is_path:
            print("\n--- SECRETS ---")
            r = self.secrets.run(target)
            report["secrets"] = r
            all_findings += [{**f, "_source": "secrets"} for f in r.get("findings", [])]

            print("\n--- CODE ---")
            r = self.code.run(target)
            report["code"] = r
            all_findings += [{**f, "_source": "code"} for f in r.get("findings", [])]

            print("\n--- DOCKER ---")
            r = self.docker.run(target)
            report["docker"] = r
            all_findings += [{**f, "_source": "docker"} for f in r.get("findings", [])]

            print("\n--- KUBERNETES ---")
            r = self.kubernetes.run(target)
            report["kubernetes"] = r
            all_findings += [{**f, "_source": "kubernetes"} for f in r.get("findings", [])]

            print("\n--- TERRAFORM ---")
            r = self.terraform.run(target)
            report["terraform"] = r
            all_findings += [{**f, "_source": "terraform"} for f in r.get("findings", [])]

            print("\n--- CICD ---")
            r = self.cicd.run(target)
            report["cicd"] = r
            all_findings += [{**f, "_source": "cicd"} for f in r.get("findings", [])]

            print("\n--- SBOM ---")
            r = self.sbom.run(target)
            report["sbom"] = r
            all_findings += [{**f, "_source": "sbom"} for f in r.get("findings", [])]

            print("\n--- CONTAINER ---")
            r = self.container.run(path=target)
            report["container"] = r
            all_findings += [{**f, "_source": "container"} for f in r.get("findings", [])]

            print("\n--- COMPLIANCE ---")
            report["compliance"] = self.compliance.run(all_findings)

        # ============ MODE CIBLE DISTANTE ============
        if not is_path:
            print("\n--- CLOUD ---")
            r = self.cloud.run()
            report["cloud"] = r
            all_findings += [{**f, "_source": "cloud"} for f in r.get("findings", [])]

            print("\n--- OSINT ---")
            # OSINTAgent est importe plus bas si dispo
            try:
                from agents.osint_agent import OSINTAgent
                report["osint"] = OSINTAgent().run(target)
            except ImportError:
                pass

            print("\n--- RED ---")
            r = self.red.run(objective, target, max_iter=2)
            report["red"] = r
            all_findings += [{**f, "_source": "red"} for f in r.get("findings", [])]

            print("\n--- STEALTH ---")
            report["stealth"] = self.stealth.run(target)

            if is_url:
                print("\n--- CRYPTO ---")
                try:
                    from agents.crypto_agent import CryptoAgent
                    r = CryptoAgent().run(target)
                    report["crypto"] = r
                    all_findings += [{**f, "_source": "crypto"} for f in r.get("findings", [])]
                except ImportError:
                    pass

                print("\n--- WEB ---")
                r = self.web.run(target)
                report["web"] = r
                all_findings += [{**f, "_source": "web"} for f in r.get("findings", [])]

                print("\n--- API ---")
                r = self.api.run(target)
                report["api"] = r
                all_findings += [{**f, "_source": "api"} for f in r.get("findings", [])]
            else:
                print("\n--- NETWORK ---")
                r = self.network.run(target, ports="1-1000")
                report["network"] = r
                all_findings += [{**f, "_source": "network"} for f in r.get("findings", [])]

                print("\n--- IOT ---")
                r = self.iot.run(target)
                report["iot"] = r
                all_findings += [{**f, "_source": "iot"} for f in r.get("findings", [])]

        # ============ VALIDATION ============
        print("\n--- CRITIC ---")
        critic_res = self.critic.run(all_findings, source="multi")
        report["critic"] = critic_res
        validated = critic_res.get("validated", [])

        print("\n--- EXPLOIT ---")
        web_findings = report.get("web", {}).get("findings", [])
        if web_findings:
            report["exploit"] = self.exploit.run(web_findings)
        else:
            report["exploit"] = {"agent": "exploit", "exploits": []}

        print("\n--- RISK ---")
        report["risk"] = self.risk.run(validated)

        print("\n--- COMPLIANCE ---")
        if "compliance" not in report:
            report["compliance"] = self.compliance.run(validated)

        print("\n--- BLUE ---")
        report["blue"] = self.blue.run({"findings": validated})

        print("\n--- PURPLE ---")
        report["purple"] = self.purple.run({"findings": validated}, report["blue"])

        # Sauvegarde
        out = self.log_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        report["report_path"] = str(out)
        print(f"\n>>> JSON: {out}")

        try:
            self.memory.save_scan(report)
        except Exception as e:
            print(f"[MEMORY] erreur: {e}")

        if send_report:
            print("\n--- REPORT ---")
            report["report_files"] = self.report.run(report)

        if notify:
            print("\n--- NOTIFY ---")
            report["notify"] = self.notify.run(report)

        self.memory.close()
        return report
