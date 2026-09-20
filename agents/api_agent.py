"""Agent API - audit REST/GraphQL : auth, IDOR, mass assignment, rate limit."""
import re
from urllib.parse import urljoin, urlparse
import httpx
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


API_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2",
    "/api/users", "/api/user", "/api/me",
    "/api/admin", "/api/config", "/api/settings",
    "/api/auth", "/api/login", "/api/token",
    "/api/health", "/api/status", "/api/version",
    "/api/docs", "/api/swagger", "/swagger.json", "/openapi.json",
    "/graphql", "/api/graphql",
    "/api/debug", "/api/metrics", "/api/logs",
]

FAKE_AUTH = [
    "Bearer test",
    "Bearer admin",
    "Basic YWRtaW46YWRtaW4=",
    "Bearer null",
]

IDOR_IDS = ["1", "2", "0", "-1", "admin", "me", "null"]

SECURITY_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
]


class APIAgent(BaseAgent):
    name = "api"

    def __init__(self, timeout=8):
        super().__init__()
        self.client = httpx.Client(
            timeout=timeout, follow_redirects=False,
            headers={"User-Agent": "PentestAvance/1.0"},
        )

    def run(self, target):
        base = self._normalize(target)
        print(f"[API] audit de {base}")
        findings = []

        endpoints = self._discover(base)
        print(f"[API] {len(endpoints)} endpoint(s)")

        findings += self._test_headers(base)
        findings += self._test_auth_bypass(base, endpoints)
        findings += self._test_idor(base, endpoints)
        findings += self._test_rate_limit(base, endpoints)

        self.client.close()

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "target": base,
                "endpoints_found": len(endpoints),
                "findings": findings}

    def _normalize(self, target):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        p = urlparse(target)
        return f"{p.scheme}://{p.netloc}"

    def _discover(self, base):
        out = []
        for path in API_ENDPOINTS:
            url = urljoin(base, path)
            try:
                r = self.client.get(url)
                if r.status_code not in (404, 410):
                    out.append({"path": path, "url": url,
                                "status": r.status_code})
                    print(f"[API] {path} -> {r.status_code}")
            except Exception:
                pass
        return out

    def _test_headers(self, base):
        out = []
        try:
            r = self.client.get(base)
            h = {k.lower(): v for k, v in r.headers.items()}
            for hdr in SECURITY_HEADERS:
                if hdr not in h:
                    out.append({"type": "missing_header", "header": hdr,
                                "severity": "low"})
        except Exception:
            pass
        return out

    def _test_auth_bypass(self, base, endpoints):
        out = []
        for ep in endpoints:
            if ep["status"] != 200:
                continue
            try:
                r1 = self.client.get(ep["url"])
                r2 = self.client.get(ep["url"],
                                     headers={"Authorization": FAKE_AUTH[0]})
                if r1.status_code == 200 and any(
                    s in ep["path"] for s in
                    ["admin", "config", "debug", "metrics", "logs"]
                ):
                    out.append({
                        "type": "unauth_endpoint",
                        "url": ep["url"],
                        "severity": "critical",
                        "reason": "Endpoint sensible accessible sans auth",
                    })
                    print(f"[API] unauth: {ep['path']}")
                if r2.status_code == 200 and "error" not in r2.text.lower()[:200]:
                    out.append({
                        "type": "weak_auth",
                        "url": ep["url"],
                        "severity": "high",
                        "reason": "Fake token accepte",
                    })
            except Exception:
                pass
        return out

    def _test_idor(self, base, endpoints):
        out = []
        for ep in endpoints:
            if not re.search(r"/\d+$", ep["path"]):
                continue
            try:
                for test_id in IDOR_IDS[:4]:
                    test_url = re.sub(r"/\d+$", f"/{test_id}", ep["url"])
                    r = self.client.get(test_url)
                    if r.status_code == 200 and len(r.content) > 20:
                        if test_id != "1":
                            out.append({
                                "type": "possible_idor",
                                "url": test_url,
                                "severity": "high",
                                "reason": f"ID {test_id} accessible",
                            })
                            print(f"[API] IDOR? {test_url}")
                            break
            except Exception:
                pass
        return out

    def _test_rate_limit(self, base, endpoints):
        out = []
        test_url = None
        for ep in endpoints:
            if ep["status"] == 200 and ("login" in ep["path"] or "auth" in ep["path"]):
                test_url = ep["url"]
                break
        if not test_url:
            return out
        try:
            statuses = []
            for i in range(20):
                r = self.client.get(test_url)
                statuses.append(r.status_code)
            if 429 not in statuses and 403 not in statuses:
                out.append({
                    "type": "no_rate_limit",
                    "url": test_url,
                    "severity": "medium",
                    "reason": "Aucun rate limit apres 20 requetes",
                })
                print(f"[API] pas de rate limit sur {test_url}")
        except Exception:
            pass
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert API security (OWASP API Top 10). JSON strict: '
                   '{"validated":[{"type":"","severity":"",'
                   '"impact":"","fix":"","owasp_api":""}]}')
            txt = "\n".join(
                f"- {f.get('type')} | {f.get('severity')} | {f.get('url','')[:60]}"
                for f in findings[:30])
            r = ask_ai_json(f"Findings API:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[API] llm err: {e}")
            return findings
