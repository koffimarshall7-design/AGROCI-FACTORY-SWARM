"""Agent WEB - audit HTTP : headers, endpoints, SQLi, XSS, LFI."""
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup

from core.ai_engine import ask_ai_json
from agents.base import BaseAgent

PATHS = ["/admin", "/.env", "/.git/config", "/robots.txt",
         "/sitemap.xml", "/api/v1", "/swagger.json", "/phpinfo.php"]
SQLI = ["'", "\"", "' OR '1'='1", "1' AND SLEEP(2)--"]
XSS  = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
LFI  = ["../../../etc/passwd", "/etc/passwd"]


class WebAgent(BaseAgent):
    name = "web"

    def __init__(self, timeout=10):
        super().__init__()
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "PentestAvance/1.0"},
        )

    def run(self, url):
        print(f"[WEB] audit de {url}")
        findings = []
        findings += self._headers(url)
        findings += self._paths(url)
        forms = self._forms(url)
        print(f"[WEB] {len(forms)} formulaire(s)")
        findings += self._fuzz_params(url)
        findings += self._fuzz_forms(forms)
        if findings:
            findings = self._llm(findings)
        self.client.close()
        return {"agent": self.name, "url": url, "findings": findings}

    def _headers(self, url):
        out = []
        sec = {
            "strict-transport-security": "HSTS manquant",
            "content-security-policy": "CSP manquant",
            "x-frame-options": "Clickjacking possible",
            "x-content-type-options": "MIME sniffing",
            "referrer-policy": "Fuite referrer",
        }
        try:
            r = self.client.get(url)
            h = {k.lower(): v for k, v in r.headers.items()}
            for k, reason in sec.items():
                if k not in h:
                    out.append({
                        "type": "missing_header",
                        "header": k,
                        "severity": "low",
                        "reason": reason,
                    })
            srv = h.get("server", "")
            if re.search(r"\d+\.\d+", srv):
                out.append({
                    "type": "info_leak",
                    "value": srv,
                    "severity": "low",
                })
        except Exception as e:
            print(f"[WEB] headers err: {e}")
        return out

    def _paths(self, url):
        out = []
        p = urlparse(url)
        root = f"{p.scheme}://{p.netloc}"
        for path in PATHS:
            u = urljoin(root, path)
            try:
                r = self.client.get(u)
                if r.status_code == 200 and len(r.content) > 0:
                    head = r.text[:500].lower()
                    if "404" not in head and "not found" not in head:
                        sev = "medium" if path in ("/.env", "/.git/config") else "low"
                        out.append({
                            "type": "exposed_endpoint",
                            "url": u,
                            "status": r.status_code,
                            "severity": sev,
                        })
                        print(f"[WEB] expose: {u}")
            except Exception:
                pass
        return out

    def _forms(self, url):
        forms = []
        try:
            r = self.client.get(url)
            soup = BeautifulSoup(r.text, "html.parser")
            for f in soup.find_all("form"):
                action = f.get("action") or url
                method = (f.get("method") or "get").lower()
                inputs = []
                for inp in f.find_all(["input", "textarea"]):
                    n = inp.get("name")
                    if n:
                        inputs.append({
                            "name": n,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
                forms.append({
                    "action": urljoin(url, action),
                    "method": method,
                    "inputs": inputs,
                })
        except Exception as e:
            print(f"[WEB] forms err: {e}")
        return forms

    def _fuzz_params(self, url):
        out = []
        p = urlparse(url)
        params = parse_qs(p.query)
        if not params:
            return out
        base = f"{p.scheme}://{p.netloc}{p.path}"
        flat = {k: v[0] for k, v in params.items()}

        for param in params:
            for pl in SQLI[:3]:
                try:
                    t0 = time.time()
                    r = self.client.get(base, params={**flat, param: pl})
                    dt = time.time() - t0
                    body = r.text.lower()
                    sql_errors = [
                        "sql syntax", "mysql_fetch", "sqlite",
                        "postgresql", "ora-", "unclosed quotation",
                    ]
                    if any(e in body for e in sql_errors):
                        out.append({
                            "type": "sqli",
                            "url": str(r.url),
                            "param": param,
                            "payload": pl,
                            "severity": "critical",
                        })
                        print(f"[WEB] SQLi sur {param}")
                    if dt > 1.8 and "sleep" in pl.lower():
                        out.append({
                            "type": "sqli_blind",
                            "url": str(r.url),
                            "param": param,
                            "severity": "critical",
                        })
                except Exception:
                    pass

            for pl in XSS:
                try:
                    r = self.client.get(base, params={**flat, param: pl})
                    if pl in r.text:
                        out.append({
                            "type": "xss_reflected",
                            "url": str(r.url),
                            "param": param,
                            "payload": pl,
                            "severity": "high",
                        })
                        print(f"[WEB] XSS sur {param}")
                except Exception:
                    pass

            for pl in LFI:
                try:
                    r = self.client.get(base, params={**flat, param: pl})
                    if "root:x:" in r.text or "root:0:0" in r.text:
                        out.append({
                            "type": "lfi",
                            "url": str(r.url),
                            "param": param,
                            "severity": "critical",
                        })
                        print(f"[WEB] LFI sur {param}")
                except Exception:
                    pass
        return out

    def _fuzz_forms(self, forms):
        out = []
        for form in forms[:5]:
            for pl in XSS[:2]:
                data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("submit", "button", "hidden"):
                        data[inp["name"]] = inp["value"]
                    else:
                        data[inp["name"]] = pl
                try:
                    if form["method"] == "post":
                        r = self.client.post(form["action"], data=data)
                    else:
                        r = self.client.get(form["action"], params=data)
                    if pl in r.text:
                        out.append({
                            "type": "xss_form",
                            "url": form["action"],
                            "severity": "high",
                        })
                        print(f"[WEB] XSS form: {form['action']}")
                except Exception:
                    pass
        return out

    def _llm(self, findings):
        try:
            sys = (
                "Analyste pentest web. JSON strict: "
                '{"validated":[{"type":"","severity":"","impact":""}]}'
            )
            txt = "\n".join(
                f"- {f['type']} | {f.get('severity','')}" for f in findings
            )
            r = ask_ai_json(f"Findings:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[WEB] llm err: {e}")
            return findings
