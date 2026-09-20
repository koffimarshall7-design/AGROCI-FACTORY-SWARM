"""Serveur Flask + SocketIO - Dashboard temps reel."""
import sys
from pathlib import Path

# Ajoute la racine du projet au PYTHONPATH
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import threading
from datetime import datetime

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit

from core.orchestrator import Orchestrator
from core.memory import Memory

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "pentest-avance-local"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

STATE = {
    "running": False,
    "current_scan": None,
    "events": [],
}


def emit_event(event_type, data):
    payload = {
        "type": event_type,
        "ts": datetime.now().isoformat(),
        "data": data,
    }
    STATE["events"].append(payload)
    socketio.emit("scan_event", payload, broadcast=True)
    print(f"[WS] {event_type}: {str(data)[:80]}")


class WatchedOrchestrator(Orchestrator):
    def _verify_scope(self, target):
        emit_event("scope_check", {"target": target})
        return super()._verify_scope(target)

    def run(self, objective, send_report=True, notify=True):
        emit_event("scan_started", {"target": self.scope[0], "objective": objective})
        original_runs = {}
        for name in ["red", "web", "network", "stealth", "exploit",
                     "critic", "risk", "blue", "purple", "code",
                     "cloud", "compliance"]:
            agent = getattr(self, name, None)
            if agent is None:
                continue
            original_runs[name] = agent.run
            setattr(agent, "run", self._make_wrapper(name, agent.run))
        try:
            report = super().run(objective, send_report, notify)
            emit_event("scan_done", {
                "score": report.get("purple", {}).get("synthesis", {}).get("score"),
                "report_path": report.get("report_path"),
            })
            return report
        except Exception as e:
            emit_event("scan_error", {"error": str(e)})
            raise
        finally:
            for name, orig in original_runs.items():
                setattr(getattr(self, name), "run", orig)
            STATE["running"] = False

    def _make_wrapper(self, agent_name, original_run):
        def wrapper(*args, **kwargs):
            emit_event("phase_started", {"agent": agent_name})
            result = original_run(*args, **kwargs)
            if isinstance(result, dict):
                findings = result.get("findings", [])
                if findings:
                    emit_event("findings", {
                        "agent": agent_name,
                        "count": len(findings),
                        "items": findings[:10],
                    })
                elif "synthesis" in result:
                    emit_event("synthesis", {
                        "agent": agent_name,
                        "data": result["synthesis"],
                    })
            emit_event("phase_done", {"agent": agent_name})
            return result
        return wrapper


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/scans")
def api_scans():
    m = Memory()
    m.conn.row_factory = lambda c, r: dict(
        zip([col[0] for col in c.description], r))
    cur = m.conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY ts DESC LIMIT 50")
    rows = cur.fetchall()
    m.close()
    return jsonify(rows)


@app.route("/api/findings")
def api_findings():
    m = Memory()
    m.conn.row_factory = lambda c, r: dict(
        zip([col[0] for col in c.description], r))
    cur = m.conn.cursor()
    cur.execute("SELECT * FROM findings ORDER BY id DESC LIMIT 200")
    rows = cur.fetchall()
    m.close()
    return jsonify(rows)


@app.route("/api/reports")
def api_reports():
    reports_dir = ROOT / "reports"
    if not reports_dir.exists():
        return jsonify([])
    files = sorted(reports_dir.glob("*.html"),
                   key=lambda f: f.stat().st_mtime, reverse=True)
    return jsonify([{
        "name": f.name,
        "size": f.stat().st_size,
        "mtime": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
        "url": f"/reports/{f.name}",
    } for f in files[:30]])


@app.route("/reports/<path:name>")
def serve_report(name):
    return send_from_directory(str(ROOT / "reports"), name)


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    if STATE["running"]:
        return jsonify({"error": "un scan est deja en cours"}), 409

    data = request.get_json() or {}
    target = data.get("target", "").strip()
    objective = data.get("objective", "Audit complet de securite")
    mode = data.get("mode", "1")

    if not target:
        return jsonify({"error": "cible vide"}), 400

    STATE["running"] = True
    STATE["current_scan"] = {"target": target, "objective": objective}

    def run_scan():
        try:
            enforce = (mode == "2")
            orch = WatchedOrchestrator(scope=[target], enforce_bugbounty=enforce)
            orch.run(objective)
        except Exception as e:
            emit_event("scan_error", {"error": str(e)})
            STATE["running"] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return jsonify({"status": "started", "target": target})


@app.route("/api/status")
def api_status():
    return jsonify({
        "running": STATE["running"],
        "current_scan": STATE["current_scan"],
        "events_count": len(STATE["events"]),
    })


@socketio.on("connect")
def on_connect():
    print("[WS] client connecte")
    emit("scan_event", {
        "type": "connected",
        "ts": datetime.now().isoformat(),
        "data": {"message": "Dashboard connecte"},
    })


if __name__ == "__main__":
    print("=" * 60)
    print("Dashboard Pentest-Avance")
    print("Ouvre ton navigateur sur : http://localhost:5000")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False,
                 allow_unsafe_werkzeug=True)
