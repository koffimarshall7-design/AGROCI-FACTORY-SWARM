"""Agent BUG BOUNTY - scope local + formatage Bugcrowd/HackerOne."""
import os
import json
from pathlib import Path
from urllib.parse import urlparse
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class BugBountyAgent(BaseAgent):
    name = "bugbounty"

    def __init__(self):
        super().__init__()
        self.programs_file = Path("config/programs.json")
        self.programs = self._load_programs()

    def _load_programs(self):
        if not self.programs_file.exists():
            self.programs_file.parent.mkdir(exist_ok=True)
            self.programs_file.write_text("{}")
            return {}
        try:
            return json.loads(self.programs_file.read_text())
        except Exception as e:
            print(f"[BUG] programs.json invalide: {e}")
            return {}

    def reload(self):
        self.programs = self._load_programs()
        return self.programs

    def check_scope(self, target):
        host = urlparse(target if "://" in target else f"http://{target}").netloc or target
        matches = []
        for handle, prog in self.programs.items():
            for pattern in prog.get("in_scope", []):
                p = pattern.replace("*.", "")
                if host == pattern or host.endswith("." + p) or host == p:
                    excluded = any(
                        host == o or host.endswith("." + o.replace("*.", ""))
                        for o in prog.get("out_scope", [])
                    )
                    if not excluded:
                        matches.append({
                            "handle": handle,
                            "platform": prog.get("platform"),
                            "matched_pattern": pattern,
                            "offers_bounties": prog.get("offers_bounties", False),
                        })
        return matches

    def format_report(self, finding, program_handle):
        prog = self.programs.get(program_handle, {})
        platform = prog.get("platform", "bugcrowd")
        sys = (
            "Formate ce finding pour " + platform + ". JSON strict: "
            '{"title":"","severity":"","description":"","steps":[],'
            '"impact":"","remediation":""}'
        )
        try:
            report = ask_ai_json(f"Programme: {program_handle}\nFinding:\n{finding}",
                                 system=sys)
            return {"platform": platform, "report": report}
        except Exception as e:
            return {"platform": platform, "error": str(e)}

    def run(self, target=None, mode="check"):
        if mode == "list":
            return {"agent": self.name,
                    "local_programs": list(self.programs.keys()),
                    "count": len(self.programs)}
        if mode == "check":
            if not target:
                return {"error": "target requis"}
            matches = self.check_scope(target)
            return {"agent": self.name, "target": target,
                    "authorized": len(matches) > 0, "matches": matches}
        return {"agent": self.name, "error": "mode inconnu"}
