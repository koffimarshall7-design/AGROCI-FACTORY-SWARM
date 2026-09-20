"""Agent NOTIFY - alerte Telegram si critique trouve."""
import os
import httpx
from agents.base import BaseAgent


class NotifyAgent(BaseAgent):
    name = "notify"

    def __init__(self):
        super().__init__()
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat = os.getenv("TELEGRAM_CHAT_ID", "")

    def run(self, report):
        risk = report.get("risk", {})
        critic = report.get("critic", {})
        validated = critic.get("validated", [])

        criticals = [f for f in validated if f.get("severity") == "critical"]
        highs = [f for f in validated if f.get("severity") == "high"]

        if not criticals and not highs:
            print("[NOTIFY] rien de critique")
            return {"agent": self.name, "sent": False}

        target = report.get("scope", ["?"])[0]
        msg = (
            f"ALERTE PENTEST\n"
            f"Cible: {target}\n"
            f"Critiques: {len(criticals)}\n"
            f"Elevees: {len(highs)}\n"
            f"Score: {report.get('purple', {}).get('synthesis', {}).get('score', '?')}/100\n"
            f"Rapport: {report.get('report_path', '')}"
        )

        sent = self._send_telegram(msg) if self.telegram_token else False
        if not self.telegram_token:
            print("[NOTIFY] pas de token Telegram -> alerte locale")
            print(msg)
        return {"agent": self.name, "sent": sent, "message": msg}

    def _send_telegram(self, msg):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            r = httpx.post(url, json={"chat_id": self.telegram_chat, "text": msg}, timeout=10)
            if r.status_code == 200:
                print("[NOTIFY] Telegram envoye")
                return True
        except Exception as e:
            print(f"[NOTIFY] err: {e}")
        return False
