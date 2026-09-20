"""Agent IOT - scan reseau local pour devices IoT (MQTT, UPnP, cameras)."""
import socket
import subprocess
import re
import concurrent.futures
import httpx
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


# Ports IoT classiques
IOT_PORTS = {
    23: ("telnet", "critical", "Telnet en clair"),
    53: ("dns", "low", "DNS expose"),
    80: ("http", "medium", "Interface web admin"),
    443: ("https", "low", "Interface web SSL"),
    554: ("rtsp", "high", "Camera RTSP"),
    1883: ("mqtt", "high", "MQTT non chiffre"),
    1900: ("upnp", "high", "UPnP SSDP"),
    5000: ("upnp-http", "medium", "UPnP HTTP"),
    5353: ("mdns", "low", "mDNS/Bonjour"),
    8080: ("http-alt", "medium", "Interface web admin"),
    8883: ("mqtts", "low", "MQTT over TLS"),
    9100: ("printer", "high", "Printer RAW"),
    50000: ("sap", "medium", "SAP"),
}

# Patterns de technologies IoT par banniere HTTP
IOT_FINGERPRINTS = {
    "Hikvision": r"(?i)hikvision|HIKVISION",
    "Dahua": r"(?i)dahua",
    "Axis": r"(?i)axis communications",
    "TP-Link": r"(?i)tp-link|TP-LINK",
    "Netgear": r"(?i)netgear",
    "D-Link": r"(?i)d-link|dlink",
    "Mikrotik": r"(?i)mikrotik|routeros",
    "Ubiquiti": r"(?i)ubiquiti|unifi",
    "Sonoff": r"(?i)sonoff|itead",
    "Shelly": r"(?i)shelly",
    "Tuya": r"(?i)tuya",
    "Xiaomi": r"(?i)xiaomi|miwifi",
}


class IOTAgent(BaseAgent):
    name = "iot"

    def __init__(self):
        super().__init__()
        self.client = httpx.Client(timeout=5, follow_redirects=True,
                                    headers={"User-Agent": "PentestAvance/1.0"})

    def run(self, target):
        """target: IP, subnet, ou range (ex: 192.168.1.0/24)."""
        print(f"[IOT] scan reseau IoT sur {target}")
        findings = []

        # 1. Determine les hotes a scanner
        hosts = self._expand(target)
        print(f"[IOT] {len(hosts)} hote(s) a tester")

        # 2. Scan des ports IoT en parallele
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self._scan_host, h): h for h in hosts}
            for fut in concurrent.futures.as_completed(futures):
                host = futures[fut]
                try:
                    findings += fut.result()
                except Exception:
                    pass

        # 3. UPnP discovery
        findings += self._upnp_discover()

        # 4. mDNS discovery
        findings += self._mdns_discover()

        print(f"[IOT] {len(findings)} finding(s)")

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "target": target,
                "hosts_scanned": len(hosts), "findings": findings}

    def _expand(self, target):
        """Etend une cible en liste d'IPs."""
        # CIDR
        if "/" in target:
            try:
                import ipaddress
                net = ipaddress.ip_network(target, strict=False)
                # Limite a 256 IPs max
                return [str(ip) for ip in list(net.hosts())[:256]]
            except Exception:
                pass
        # Range
        if "-" in target:
            m = re.match(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", target)
            if m:
                prefix, start, end = m.groups()
                return [f"{prefix}{i}" for i in range(int(start), int(end)+1)]
        # IP unique ou hostname
        return [target]

    def _scan_host(self, host):
        """Scanne un host pour les ports IoT."""
        out = []
        for port, (service, sev, reason) in IOT_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.8)
                    if s.connect_ex((host, port)) == 0:
                        finding = {
                            "type": "iot_service_exposed",
                            "host": host,
                            "port": port,
                            "service": service,
                            "severity": sev,
                            "reason": reason,
                        }
                        # Tente d'identifier le device via banniere HTTP
                        if service in ("http", "http-alt", "upnp-http"):
                            fp = self._fingerprint_device(host, port)
                            if fp:
                                finding["device"] = fp
                        out.append(finding)
            except Exception:
                pass
        return out

    def _fingerprint_device(self, host, port):
        """Identifie le device IoT via la banniere HTTP."""
        try:
            r = self.client.get(f"http://{host}:{port}/")
            text = (r.text[:3000] + str(r.headers)).lower()
            for vendor, pattern in IOT_FINGERPRINTS.items():
                if re.search(pattern, text, re.IGNORECASE):
                    return vendor
            # Cherche title HTML
            m = re.search(r"<title>([^<]+)</title>", r.text, re.IGNORECASE)
            if m:
                return m.group(1).strip()[:50]
        except Exception:
            pass
        return None

    def _upnp_discover(self):
        """Decouverte UPnP via SSDP."""
        out = []
        try:
            msg = (
                'M-SEARCH * HTTP/1.1\r\n'
                'HOST: 239.255.255.250:1900\r\n'
                'MAN: "ssdp:discover"\r\n'
                'MX: 2\r\n'
                'ST: ssdp:all\r\n\r\n'
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(msg.encode(), ("239.255.255.250", 1900))

            devices = set()
            try:
                while True:
                    data, addr = sock.recvfrom(65535)
                    text = data.decode("utf-8", errors="ignore")
                    server = re.search(r"SERVER:\s*(.+)", text, re.IGNORECASE)
                    location = re.search(r"LOCATION:\s*(.+)", text, re.IGNORECASE)
                    if server:
                        dev = server.group(1).strip()[:100]
                        if dev not in devices:
                            devices.add(dev)
                            out.append({
                                "type": "upnp_device",
                                "host": addr[0],
                                "server": dev,
                                "location": location.group(1).strip() if location else "",
                                "severity": "medium",
                                "reason": "Device UPnP annonce sur le reseau",
                            })
                            print(f"[IOT] UPnP: {dev} @ {addr[0]}")
            except socket.timeout:
                pass
            sock.close()
        except Exception as e:
            print(f"[IOT] UPnP err: {e}")
        return out

    def _mdns_discover(self):
        """Decouverte mDNS (Bonjour)."""
        out = []
        # mDNS est complexe a implementer sans lib dediee
        # On fait juste un check basique du port 5353
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00", 
                         ("224.0.0.251", 5353))
                try:
                    data, addr = s.recvfrom(4096)
                    out.append({
                        "type": "mdns_active",
                        "host": addr[0],
                        "severity": "low",
                        "reason": "mDNS actif (devices annoncent services)",
                    })
                except socket.timeout:
                    pass
        except Exception:
            pass
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert IoT security. JSON strict: '
                   '{"validated":[{"type":"","device":"",'
                   '"severity":"","impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('type')} | {f.get('host','')} | {f.get('service','')} | {f.get('severity')}"
                for f in findings[:30])
            r = ask_ai_json(f"Findings IoT:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[IOT] llm err: {e}")
            return findings
