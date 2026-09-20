"""Agent RISK - scoring CVSS v3.1 + impact business."""
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class RiskAgent(BaseAgent):
    name = "risk"

    def run(self, findings):
        if not findings:
            return {"agent": self.name, "scored": [], "total_risk": 0,
                    "average_cvss": 0, "critical_count": 0, "high_count": 0}

        print(f"[RISK] scoring de {len(findings)} finding(s)")
        scored = []
        for f in findings:
            scored.append(self._score(f))

        scored.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        total = sum(x.get("cvss_score", 0) for x in scored)
        avg = total / len(scored) if scored else 0

        return {
            "agent": self.name,
            "scored": scored,
            "total_risk": round(total, 2),
            "average_cvss": round(avg, 2),
            "critical_count": sum(1 for x in scored if x.get("cvss_score", 0) >= 9),
            "high_count": sum(1 for x in scored if 7 <= x.get("cvss_score", 0) < 9),
        }

    def _score(self, finding):
        sys = (
            "Expert CVSS v3.1. JSON strict: "
            '{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",'
            '"cvss_score":9.8,"epss_estimate":0.75,'
            '"business_impact_eur":50000,'
            '"priority":"P0","justification":""}'
        )
        try:
            result = ask_ai_json(f"Finding:\n{finding}", system=sys)
            vector = result.get("vector", "")
            if vector.startswith("CVSS:3.1/"):
                try:
                    from cvss import CVSS3
                    c = CVSS3(vector)
                    result["cvss_score"] = c.scores()[0]
                    result["cvss_severity"] = c.severities()[0]
                except Exception:
                    pass
            result["_finding"] = finding
            return result
        except Exception as e:
            return {"_finding": finding, "error": str(e),
                    "cvss_score": 5.0, "priority": "P2"}
