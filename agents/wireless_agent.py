"""Agent WIRELESS - analyse reseaux Wi-Fi (WPS, WPA2, WEP, open)."""
import re
import json
import subprocess
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class WirelessAgent(BaseAgent):
    name = "wireless"

    def run(self, mode="scan"):
        print(f"[WIRELESS] mode={mode}")
        findings = []
        if mode == "scan":
            findings += self._scan_networks()
        if findings:
            findings = self._analyze(findings)
        return {"agent": self.name, "findings": findings}

    def _scan_networks(self):
        out = []

        # Methode 1 : termux-api (app Termux:API requise)
        try:
            r = subprocess.run(
                ["termux-wifi-scaninfo"],
                capture_output=True, text=True, timeout=8)
            if r.returncode == 0 and r.stdout.strip():
                try:
                    networks = json.loads(r.stdout)
                    for n in networks:
                        out += self._analyze_network(n)
                    print(f"[WIRELESS] {len(networks)} reseau(x) via Termux API")
                    return out
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            print("[WIRELESS] termux-wifi-scaninfo timeout -> app Termux:API manquante ?")
        except FileNotFoundError:
            print("[WIRELESS] termux-api non installe")
        except Exception as e:
            print(f"[WIRELESS] err: {e}")

        # Methode 2 : iw dev scan (root souvent requis)
        try:
            r = subprocess.run(["iw", "dev"], capture_output=True,
                               text=True, timeout=5)
            if r.returncode == 0:
                iface = "wlan0"
                m = re.search(r"Interface (\S+)", r.stdout)
                if m:
                    iface = m.group(1)
                r2 = subprocess.run(
                    ["iw", "dev", iface, "scan"],
                    capture_output=True, text=True, timeout=15)
                if r2.returncode == 0:
                    out += self._parse_iw_scan(r2.stdout)
                    print(f"[WIRELESS] scan iw via {iface}")
        except FileNotFoundError:
            print("[WIRELESS] iw non installe")
        except subprocess.TimeoutExpired:
            print("[WIRELESS] iw scan timeout")
        except Exception as e:
            print(f"[WIRELESS] iw err: {e}")

        if not out:
            print("[WIRELESS] aucune methode disponible")
            print("[WIRELESS] -> installe l'app Termux:API depuis F-Droid")
        return out

    def _analyze_network(self, net):
        out = []
        ssid = net.get("ssid", "")
        cap = net.get("capabilities", "")
        if "WPA" not in cap and "WEP" not in cap:
            out.append({"type": "open_network", "ssid": ssid,
                        "bssid": net.get("bssid", ""),
                        "severity": "high",
                        "reason": "Reseau Wi-Fi ouvert"})
        if "WEP" in cap:
            out.append({"type": "wep_network", "ssid": ssid,
                        "severity": "critical",
                        "reason": "WEP casse en minutes"})
        if "WPS" in cap:
            out.append({"type": "wps_enabled", "ssid": ssid,
                        "severity": "high",
                        "reason": "WPS active"})
        if "WPA-" in cap and "WPA2" not in cap and "WPA3" not in cap:
            out.append({"type": "wpa1_only", "ssid": ssid,
                        "severity": "medium",
                        "reason": "WPA1 obsolete"})
        return out

    def _parse_iw_scan(self, output):
        out = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                if current:
                    out += self._analyze_network({
                        "ssid": current.get("ssid", ""),
                        "bssid": current.get("bssid", ""),
                        "capabilities": current.get("cap", ""),
                    })
                current = {"bssid": line.split()[1].rstrip("(").strip()}
            elif line.startswith("SSID:"):
                current["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("capability:"):
                current["cap"] = line
        if current:
            out += self._analyze_network({
                "ssid": current.get("ssid", ""),
                "bssid": current.get("bssid", ""),
                "capabilities": current.get("cap", ""),
            })
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert Wi-Fi security. JSON strict: '
                   '{"validated":[{"ssid":"","severity":"",'
                   '"impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('type')} | {f.get('ssid','')} | {f.get('severity')}"
                for f in findings[:30])
            r = ask_ai_json(f"Findings Wi-Fi:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[WIRELESS] llm err: {e}")
            return findings
