"""Agent CRITIC - valide/elimine les faux positifs des autres agents."""
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class CriticAgent(BaseAgent):
    name = "critic"

    def run(self, findings, source="unknown"):
        if not findings:
            return {
                "agent": self.name,
                "validated": [],
                "rejected": [],
                "note": "aucun finding",
            }

        print(f"[CRITIC] validation de {len(findings)} finding(s) de {source}")
        system = (
            "Expert pentest SENIOR et SCEPTIQUE. Elimine les FAUX POSITIFS. "
            "Pour chaque finding, decide s'il est vraiment exploitable. "
            'JSON strict: {"validated":[{"type":"","severity":"",'
            '"confidence":"high|med|low","justification":""}],'
            '"rejected":[{"type":"","reason":""}]}'
        )
        try:
            r = ask_ai_json(
                f"Source: {source}\nFindings:\n{findings}",
                system=system,
            )
            v = r.get("validated", [])
            rj = r.get("rejected", [])
            print(f"[CRITIC] {len(v)} valides, {len(rj)} rejetes")
            return {"agent": self.name, "validated": v, "rejected": rj}
        except Exception as e:
            print(f"[CRITIC] err: {e}")
            return {"agent": self.name, "error": str(e)}
