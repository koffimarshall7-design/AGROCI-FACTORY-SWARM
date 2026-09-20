"""Agent REPORT - genere un rapport HTML professionnel."""
from datetime import datetime
from pathlib import Path
from core.ai_engine import ask_ai
from agents.base import BaseAgent


class ReportAgent(BaseAgent):
    name = "report"

    def __init__(self):
        super().__init__()
        self.out_dir = Path("reports")
        self.out_dir.mkdir(exist_ok=True)

    def run(self, full_report):
        print("[REPORT] generation du rapport")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = full_report.get("scope", ["unknown"])[0]
        safe = target.replace("https://", "").replace("http://", "").replace("/", "_")

        exec_summary = self._exec_summary(full_report)
        html = self._build_html(full_report, exec_summary)

        html_file = self.out_dir / f"rapport_{safe}_{ts}.html"
        html_file.write_text(html, encoding="utf-8")
        print(f"[REPORT] HTML -> {html_file}")

        return {
            "agent": self.name,
            "html": str(html_file),
            "pdf": None,
            "exec_summary": exec_summary,
        }

    def _exec_summary(self, report):
        try:
            sys = ("Redige un resume executif de 5 lignes pour un rapport de "
                   "pentest. Pas de jargon. En francais. Texte brut.")
            purple = report.get("purple", {}).get("synthesis", {})
            critic = report.get("critic", {})
            ctx = (
                f"Cible: {report.get('scope')}\n"
                f"Score securite: {purple.get('score', '?')}/100\n"
                f"Failles validees: {len(critic.get('validated', []))}\n"
                f"Faux positifs rejetes: {len(critic.get('rejected', []))}\n"
                f"Actions prioritaires: {purple.get('priority_actions', [])}"
            )
            return ask_ai(ctx, system=sys, temperature=0.4)
        except Exception as e:
            return f"Resume indisponible: {e}"

    def _build_html(self, report, exec_summary):
        purple = report.get("purple", {}).get("synthesis", {})
        critic = report.get("critic", {})
        risk = report.get("risk", {})
        stealth = report.get("stealth", {})

        score = purple.get("score", "?")
        actions = purple.get("priority_actions", [])
        validated = critic.get("validated", [])
        rejected = critic.get("rejected", [])

        findings_html = ""
        for f in validated:
            findings_html += f"""
            <div class="finding">
              <h3>{f.get('type', '?')} <span class="sev-{f.get('severity','low')}">{f.get('severity','?')}</span></h3>
              <p><b>Impact:</b> {f.get('impact', 'N/A')}</p>
              <p><b>Justification:</b> {f.get('justification', 'N/A')}</p>
              <p><b>Recommandation:</b> {f.get('recommandation', 'N/A')}</p>
            </div>"""

        actions_html = "".join(f"<li>{a}</li>" for a in actions)
        waf_html = ", ".join(w.get("name", "?") for w in stealth.get("waf", [])) or "Aucun detecte"
        subs = stealth.get("subdomains", [])
        subs_html = "".join(f"<li>{s['sub']} -> {s['ip']}</li>" for s in subs[:20]) or "<li>Aucun</li>"

        return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<title>Rapport Pentest - {report.get('scope')}</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 2em auto; padding: 1em; }}
h1 {{ color: #c00; border-bottom: 3px solid #c00; padding-bottom: 0.3em; }}
h2 {{ color: #333; margin-top: 1.5em; border-bottom: 1px solid #ccc; }}
.score {{ font-size: 3em; font-weight: bold; color: {self._score_color(score)}; }}
.finding {{ background: #f5f5f5; padding: 1em; margin: 1em 0; border-left: 4px solid #c00; }}
.sev-critical {{ color: #c00; }} .sev-high {{ color: #e67e22; }}
.sev-medium {{ color: #f39c12; }} .sev-low {{ color: #3498db; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ddd; padding: 0.5em; }}
</style></head><body>

<h1>Rapport de Pentest</h1>
<p><b>Cible :</b> {report.get('scope')}</p>
<p><b>Date :</b> {report.get('ts', '')[:19]}</p>
<p><b>Objectif :</b> {report.get('objective', 'N/A')}</p>

<h2>Score Global</h2>
<div class="score">{score}/100</div>

<h2>Resume Executif</h2>
<pre style="white-space: pre-wrap; font-family: inherit;">{exec_summary}</pre>

<h2>Statistiques</h2>
<table>
<tr><th>Metrique</th><th>Valeur</th></tr>
<tr><td>Failles validees</td><td>{len(validated)}</td></tr>
<tr><td>Faux positifs rejetes</td><td>{len(rejected)}</td></tr>
<tr><td>Score CVSS moyen</td><td>{risk.get('average_cvss', 'N/A')}</td></tr>
<tr><td>WAF detecte</td><td>{waf_html}</td></tr>
</table>

<h2>Failles Validees</h2>
{findings_html if findings_html else '<p>Aucune faille validee.</p>'}

<h2>Actions Prioritaires</h2>
<ul>{actions_html if actions_html else '<li>Aucune.</li>'}</ul>

<h2>Sous-domaines Detectes</h2>
<ul>{subs_html}</ul>

<hr>
<p style="color: #888; font-size: 0.9em;">
Rapport genere automatiquement par Pentest-Avance.
Cadre legal : usage uniquement sur systemes autorises.
</p>

</body></html>"""

    def _score_color(self, score):
        try:
            s = int(score)
            if s >= 80: return "#27ae60"
            if s >= 60: return "#f39c12"
            return "#c00"
        except Exception:
            return "#333"
