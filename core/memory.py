"""Memoire SQLite - persiste les findings entre les runs."""
import sqlite3
from pathlib import Path


class Memory:
    def __init__(self, db_path="data/memory.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, target TEXT, objective TEXT,
            score INTEGER, findings_count INTEGER, report_path TEXT);
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER, target TEXT, type TEXT,
            severity TEXT, source TEXT, evidence TEXT);
        CREATE INDEX IF NOT EXISTS idx_target ON scans(target);
        CREATE INDEX IF NOT EXISTS idx_type ON findings(type);
        """)
        self.conn.commit()

    def save_scan(self, report):
        cur = self.conn.cursor()
        target = report.get("scope", ["?"])[0]
        score = report.get("purple", {}).get("synthesis", {}).get("score", 0)
        validated = report.get("critic", {}).get("validated", [])
        cur.execute(
            "INSERT INTO scans (ts, target, objective, score, findings_count, report_path) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (report.get("ts"), target, report.get("objective"),
             score, len(validated), report.get("report_path")))
        scan_id = cur.lastrowid
        for f in validated:
            cur.execute(
                "INSERT INTO findings (scan_id, target, type, severity, source, evidence) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, target, f.get("type"), f.get("severity"),
                 f.get("_source"), str(f.get("evidence", ""))[:500]))
        self.conn.commit()
        print(f"[MEMORY] scan #{scan_id} sauvegarde ({len(validated)} findings)")
        return scan_id

    def target_history(self, target):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT ts, score, findings_count FROM scans WHERE target = ? "
            "ORDER BY ts DESC LIMIT 10", (target,))
        return [{"ts": r[0], "score": r[1], "findings": r[2]} for r in cur.fetchall()]

    def stats(self):
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*), AVG(score) FROM scans")
        total, avg = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM findings")
        findings = cur.fetchone()[0]
        return {"total_scans": total,
                "avg_score": round(avg, 2) if avg else 0,
                "total_findings": findings}

    def close(self):
        self.conn.close()
