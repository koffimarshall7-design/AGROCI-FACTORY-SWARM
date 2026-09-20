"""Agent OSINT - collecte passive d'informations publiques."""
import socket
import subprocess
from urllib.parse import urlparse
import httpx
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


# Sources OSINT publiques
DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Common services a verifier dans les DNS
DNS_TYPES = ["MX", "TXT", "NS", "CNAME", "SOA"]


class OSINTAgent(BaseAgent):
    name = "osint"

    def __init__(self):
        super().__init__()
        self.client = httpx.Client(timeout=10, follow_redirects=True)

    def run(self, target):
        host = self._extract_host(target)
        print(f"[OSINT] collecte passive sur {host}")

        result = {
            "agent": self.name,
            "host": host,
            "dns": {},
            "email_patterns": [],
            "technologies": [],
            "certificates": [],
            "public_info": {},
            "findings": [],
        }

        # 1. DNS records
        result["dns"] = self._dns_records(host)

        # 2. Emails / pattern via DNS TXT + SPF
        result["email_patterns"] = self._email_from_txt(result["dns"])

        # 3. Technologies via headers (comme stealth mais plus focalise OSINT)
        result["technologies"] = self._technologies(target, host)

        # 4. crt.sh (certificats SSL publics)
        result["certificates"] = self._crtsh(host)

        # 5. Resume LLM
        result["summary"] = self._summarize(result)

        return result

    def _extract_host(self, target):
        if "://" in target:
            return urlparse(target).netloc.split(":")[0]
        return target.split(":")[0]

    def _dns_records(self, host):
        records = {}
        for rtype in DNS_TYPES:
            try:
                r = subprocess.run(
                    ["nslookup", f"-type={rtype}", host],
                    capture_output=True, text=True, timeout=10)
                lines = [l.strip() for l in r.stdout.splitlines()
                         if l.strip() and not l.startswith("Server:")
                         and not l.startswith("Address:")
                         and "Non-authoritative" not in l]
                if lines:
                    records[rtype] = lines[:10]
            except Exception:
                pass
        return records

    def _email_from_txt(self, dns):
        emails = []
        for line in dns.get("TXT", []):
            lower = line.lower()
            if "spf" in lower or "v=dkim" in lower:
                # Extrait les domaines mentionnes
                for word in line.split():
                    if "." in word and "@" not in word:
                        pass
            # Emails directs
            if "@" in line:
                for token in line.split():
                    if "@" in token and "." in token:
                        emails.append(token.strip("\"'"))
        return list(set(emails))

    def _technologies(self, target, host):
        techs = []
        try:
            url = target if target.startswith("http") else f"https://{host}"
            r = self.client.get(url)
            h = {k.lower(): v for k, v in r.headers.items()}
            if "server" in h:
                techs.append({"type": "server", "value": h["server"]})
            if "x-powered-by" in h:
                techs.append({"type": "framework", "value": h["x-powered-by"]})
            if "x-generator" in h:
                techs.append({"type": "cms", "value": h["x-generator"]})
            if "cf-ray" in h:
                techs.append({"type": "cdn", "value": "Cloudflare"})
            if "x-amz" in " ".join(h.keys()):
                techs.append({"type": "cdn", "value": "AWS CloudFront"})
        except Exception:
            pass
        return techs

    def _crtsh(self, host):
        """Recupere les sous-domaines via crt.sh (certificate transparency)."""
        try:
            r = self.client.get(
                f"https://crt.sh/?q=%25.{host}&output=json", timeout=15)
            if r.status_code != 200:
                return []
            data = r.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n and "*" not in n and n.endswith(host):
                        subs.add(n)
            result = sorted(list(subs))[:30]
            print(f"[OSINT] {len(result)} subdomain(s) via crt.sh")
            return result
        except Exception as e:
            print(f"[OSINT] crt.sh err: {e}")
            return []

    def _summarize(self, result):
        try:
            sys = ('Analyste OSINT. JSON strict: '
                   '{"risk_level":"low|med|high",'
                   '"exposed_info":[],"attack_surface":"",'
                   '"interesting_targets":[]}')
            return ask_ai_json(f"Donnees OSINT:\n{result}", system=sys)
        except Exception as e:
            return {"risk_level": "unknown", "error": str(e)}
