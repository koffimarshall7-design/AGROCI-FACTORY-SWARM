"""Agent STEALTH - recon avancee : WAF, tech stack, subdomains, WHOIS."""
import socket
import subprocess
import re
import httpx
from urllib.parse import urlparse
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


# Wordlist courte de subdomains courants
SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "test", "admin",
    "portal", "app", "blog", "shop", "cdn", "static", "assets",
    "dashboard", "docs", "git", "jenkins", "ci", "monitor",
    "vpn", "ftp", "db", "backup", "old", "new", "beta", "alpha",
]

# Signatures WAF dans les headers
WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "aws_waf": ["awselb", "x-amz"],
    "akamai": ["akamai", "ak-bmsc"],
    "sucuri": ["sucuri", "x-sucuri"],
    "imperva": ["imperva", "incap_ses"],
    "f5": ["big-ip", "x-wa-info"],
    "modsecurity": ["mod_security", "modsecurity"],
}


class StealthAgent(BaseAgent):
    name = "stealth"

    def __init__(self, timeout=10):
        super().__init__()
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible)"},
        )

    def run(self, target):
        print(f"[STEALTH] recon de {target}")
        result = {
            "agent": self.name,
            "target": target,
            "dns": {},
            "waf": [],
            "tech_stack": {},
            "subdomains": [],
            "whois": "",
        }

        # 1. DNS
        result["dns"] = self._dns_lookup(target)

        # 2. HTTP headers + WAF
        url = target if target.startswith("http") else f"https://{target}"
        headers, waf = self._fingerprint(url)
        result["waf"] = waf
        result["tech_stack"] = self._tech_stack(headers, url)

        # 3. Subdomains
        root = urlparse(url).netloc
        result["subdomains"] = self._subdomain_scan(root)

        # 4. WHOIS (via whois CLI si dispo)
        result["whois"] = self._whois(root)

        # 5. Synthese LLM
        print(f"[STEALTH] {len(result['subdomains'])} subdomain(s), "
              f"{len(result['waf'])} WAF detecte(s)")
        result["summary"] = self._summarize(result)

        self.client.close()
        return result

    def _dns_lookup(self, target):
        out = {}
        try:
            hostname = urlparse(target if target.startswith("http") else f"https://{target}").netloc or target
            out["ip"] = socket.gethostbyname(hostname)
            # Reverse DNS
            try:
                out["reverse"] = socket.gethostbyaddr(out["ip"])[0]
            except Exception:
                pass
            # MX / TXT via nslookup
            for rtype in ["MX", "TXT", "NS"]:
                try:
                    r = subprocess.run(
                        ["nslookup", "-type=" + rtype, hostname],
                        capture_output=True, text=True, timeout=10
                    )
                    lines = [
                        l.strip() for l in r.stdout.splitlines()
                        if l.strip() and "=" in l and "Server" not in l and "Address" not in l[:15]
                    ]
                    if lines:
                        out[rtype.lower()] = lines[:5]
                except Exception:
                    pass
        except Exception as e:
            out["error"] = str(e)
        return out

    def _fingerprint(self, url):
        waf = []
        headers = {}
        try:
            r = self.client.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}

            # WAF detection
            combined = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
            for waf_name, sigs in WAF_SIGNATURES.items():
                if any(sig in combined for sig in sigs):
                    waf.append({"name": waf_name, "confidence": "high"})

            # Test WAF actif : envoyer payload simple
            try:
                r2 = self.client.get(url + "/?x=<script>alert(1)</script>")
                if r2.status_code in (403, 406, 419):
                    waf.append({"name": "actif", "confidence": "medium",
                                "reason": f"Payload bloque ({r2.status_code})"})
            except Exception:
                pass
        except Exception as e:
            print(f"[STEALTH] fingerprint err: {e}")
        return headers, waf

    def _tech_stack(self, headers, url):
        stack = {}
        srv = headers.get("server", "")
        pwr = headers.get("x-powered-by", "")
        gen = headers.get("x-generator", "")

        if srv:
            stack["server"] = srv
        if pwr:
            stack["powered_by"] = pwr
        if gen:
            stack["generator"] = gen

        # Detection CMS/framework via body
        try:
            r = self.client.get(url)
            body = r.text[:5000].lower()
            sigs = {
                "wordpress": ["wp-content", "wp-includes"],
                "drupal": ["drupal.js", "sites/default"],
                "joomla": ["joomla", "/components/com_"],
                "react": ["react", "_next"],
                "vue": ["vue.js", "__vue__"],
                "angular": ["ng-version", "angular"],
                "django": ["csrfmiddlewaretoken", "django"],
                "flask": ["werkzeug"],
                "php": ["<?php", ".php"],
                "nginx": ["nginx"],
                "apache": ["apache"],
            }
            for tech, patterns in sigs.items():
                if any(p in body for p in patterns):
                    stack.setdefault("frameworks", []).append(tech)
        except Exception:
            pass
        return stack

    def _subdomain_scan(self, root):
        found = []
        # Nettoie le root (enleve www. si present)
        base = root.replace("www.", "", 1)
        for sub in SUBDOMAINS:
            host = f"{sub}.{base}"
            try:
                ip = socket.gethostbyname(host)
                found.append({"sub": host, "ip": ip})
                print(f"[STEALTH] subdomain: {host} -> {ip}")
            except Exception:
                pass
        return found

    def _whois(self, root):
        base = root.replace("www.", "", 1)
        try:
            r = subprocess.run(["whois", base], capture_output=True,
                               text=True, timeout=15)
            # Extrait les infos clefs
            out = []
            for line in r.stdout.splitlines()[:40]:
                if any(k in line.lower() for k in
                       ["registrar:", "creation", "expir", "name server",
                        "registrant", "updated"]):
                    out.append(line.strip())
            return "\n".join(out[:15])
        except FileNotFoundError:
            return "whois non installe (pkg install whois)"
        except Exception as e:
            return f"err: {e}"

    def _summarize(self, result):
        try:
            sys = (
                "Expert recon pentest. Resume ces infos. JSON strict: "
                '{"risk_level":"low|med|high","attack_surface":"",'
                '"interesting_targets":[],"next_steps":[]}'
            )
            return ask_ai_json(f"Recon:\n{result}", system=sys)
        except Exception as e:
            print(f"[STEALTH] llm err: {e}")
            return {"risk_level": "unknown"}
