"""Agent COMPLIANCE - mappe les findings sur RGPD, OWASP, ISO 27001."""
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


FRAMEWORKS = {
    "rgpd": "Reglement General sur la Protection des Donnees (UE)",
    "owasp_asvs": "OWASP Application Security Verification Standard",
    "iso_27001": "ISO/IEC 27001 (management de la securite)",
    "pci_dss": "PCI-DSS (paiement carte bancaire)",
    "nist": "NIST Cybersecurity Framework",
}


class ComplianceAgent(BaseAgent):
    name = "compliance"

    def run(self, findings, frameworks=None):
        """Mappe les findings sur les referentiels specifies."""
        frameworks = frameworks or ["rgpd", "owasp_asvs", "iso_27001"]
        print(f"[COMPLIANCE] mapping sur {len(frameworks)} referentiel(s)")

        result = {"agent": self.name, "frameworks": {}, "overall": "unknown"}

        for fw in frameworks:
            if fw not in FRAMEWORKS:
                continue
            print(f"[COMPLIANCE] analyse {fw}")
            result["frameworks"][fw] = self._check(fw, findings)

        # Synthese globale
        all_status = [
            c.get("status", "unknown")
            for fw in result["frameworks"].values()
            for c in fw.get("checks", [])
        ]
        non_conform = sum(1 for s in all_status if s == "non_conforme")
        result["overall"] = "non_conforme" if non_conform > 0 else "conforme"

        return result

    def _check(self, framework, findings):
        sys = (
            f"Auditeur conformite {FRAMEWORKS[framework]}. "
            "Pour chaque finding, indique si c'est une violation du referentiel. "
            'JSON strict: {"checks":[{"finding":"","status":'
            '"conforme|non_conforme|a_verifier","article":"","impact":""}]}'
        )
        try:
            return ask_ai_json(
                f"Findings:\n{findings}\nReferentiel: {framework}",
                system=sys,
            )
        except Exception as e:
            return {"error": str(e), "checks": []}
