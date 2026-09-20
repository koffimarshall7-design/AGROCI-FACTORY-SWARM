"""Agent NETWORK - scan via nmap + fallback HTTP/curl si nmap filtre."""
import subprocess
import re
import socket
import httpx
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
                5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200,
                11211, 27017]


class NetworkAgent(BaseAgent):
    name = "network"

    def run(self, target, ports="1-1000"):
        print(f"[NET] scan de {target}")
        findings = []

        try:
            ip = socket.gethostbyname(target)
            print(f"[NET] {target} -> {ip}")
        except Exception as e:
            return {"agent": self.name, "error": f"DNS: {e}"}

        # 1. Tentative nmap
        nmap_out = self._scan_nmap(target, ports)
        findings += self._parse_nmap(nmap_out)

        # 2. Fallback TCP connect si nmap vide
        if not findings:
            print("[NET] nmap vide -> fallback TCP connect")
            findings += self._tcp_connect_scan(target)

        # 3. Analyse LLM
        if findings:
            print(f"[NET] analyse de {len(findings)} service(s)")
            findings = self._analyze(findings, target)

        return {
            "agent": self.name,
            "target": target,
            "findings": findings,
            "raw_nmap": nmap_out[:1000] if nmap_out else "",
        }

    def _scan_nmap(self, target, ports):
        try:
            cmd = ["nmap", "-sV", "-T4", "-Pn", "-p", ports, target]
            print(f"[NET] nmap {ports}")
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return r.stdout
        except Exception as e:
            print(f"[NET] nmap err: {e}")
            return ""

    def _parse_nmap(self, output):
        findings = []
        pattern = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)
        for m in pattern.finditer(output):
            port, service, version = m.groups()
            findings.append({
                "type": "open_port",
                "port": int(port),
                "service": service,
                "version": version.strip(),
                "severity": self._severity(port),
                "method": "nmap",
            })
        return findings

    def _tcp_connect_scan(self, target):
        """Scan TCP connect (socket) qui passe meme si nmap est filtre."""
        findings = []
        for port in COMMON_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    if s.connect_ex((target, port)) == 0:
                        svc = self._guess_service(port)
                        findings.append({
                            "type": "open_port",
                            "port": port,
                            "service": svc,
                            "version": "",
                            "severity": self._severity(port),
                            "method": "tcp_connect",
                        })
                        print(f"[NET] ouvert: {port}/{svc}")
            except Exception:
                pass
        return findings

    def _guess_service(self, port):
        table = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 2049: "nfs",
            3306: "mysql", 3389: "rdp", 5432: "postgres",
            5900: "vnc", 6379: "redis", 8000: "http-alt",
            8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
            9000: "http", 9200: "elasticsearch",
            11211: "memcached", 27017: "mongodb",
        }
        return table.get(port, "unknown")

    def _severity(self, port):
        p = int(port)
        if p in (21, 23, 445, 3389, 5900):
            return "high"
        if p in (22, 3306, 5432, 6379, 27017):
            return "medium"
        if p in (80, 8080):
            return "low"
        return "info"

    def _analyze(self, findings, target):
        try:
            system = (
                "Expert pentest reseau. Analyse ces ports. JSON strict: "
                '{"analysis":[{"port":0,"risk":"","severity":""}]}'
            )
            txt = "\n".join(
                f"- port {f['port']}/{f['service']} {f.get('version','')}"
                for f in findings
            )
            r = ask_ai_json(f"Cible: {target}\nServices:\n{txt}", system=system)
            _merged = []
            for orig in findings:
                match = next((a for a in r.get("analysis", []) if a.get("port") == orig.get("port")), None)
                _merged.append({**orig, "llm_analysis": match})
            return _merged if _merged else findings
        except Exception as e:
            print(f"[NET] llm err: {e}")
            return findings
