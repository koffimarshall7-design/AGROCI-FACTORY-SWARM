"""Agent PURPLE — synthèse Red + Blue. Score global + plan d'action."""
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class PurpleAgent(BaseAgent):
    name = "purple"

    def run(self, red_result: dict, blue_result: dict):
        print("[PURPLE] croisement Red x Blue")
        synthesis = ask_ai_json(
            f"RED:\n{red_result}\n\nBLUE:\n{blue_result}",
            system=(
                "Tu es Purple Team. Croise les résultats offensifs (Red) et "
                "défensifs (Blue). Identifie les failles non couvertes, les "
                "défenses efficaces, et calcule un score global de sécurité "
                "de 0 (critique) à 100 (excellent). "
                'JSON strict: {"score":int,"uncovered":[],'
                '"effective_defenses":[],"priority_actions":["..."]}'
            ),
        )
        return {"agent": self.name, "synthesis": synthesis}
