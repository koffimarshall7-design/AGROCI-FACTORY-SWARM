"""Agent BLUE — défensif. Analyse les findings du Red."""
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class BlueAgent(BaseAgent):
    name = "blue"

    def run(self, red_result: dict):
        findings = red_result.get("findings", [])
        if not findings:
            print("[BLUE] aucune faille à défendre")
            return {
                "agent": self.name,
                "status": "rien à défendre",
                "detections": [],
                "remediations": [],
            }

        print(f"[BLUE] analyse de {len(findings)} faille(s)")
        detections = self._detect(findings)
        remediations = self._remediate(detections)
        return {
            "agent": self.name,
            "detections": detections,
            "remediations": remediations,
        }

    def _detect(self, findings):
        system = (
            "Tu es Blue Team. Pour chaque faille, donne sévérité, impact, "
            'détectabilité. JSON strict: {"detections":[{"vector":"",'
            '"severity":"low|med|high|critical","impact":"",'
            '"detectable":true/false}]}'
        )
        return ask_ai_json(f"Failles:\n{findings}", system=system)

    def _remediate(self, detections):
        system = (
            "Tu es Blue Team. Pour chaque détection, donne UNE contre-mesure "
            'concrète. JSON strict: {"remediations":[{"vector":"","fix":"",'
            '"priority":"low|med|high"}]}'
        )
        return ask_ai_json(f"Détections:\n{detections}", system=system)
