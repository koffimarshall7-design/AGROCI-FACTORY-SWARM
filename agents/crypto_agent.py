"""Agent CRYPTO - audit TLS/SSL (protocoles, certificats, ciphers)."""
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


# Protocoles obsoletes
WEAK_PROTOCOLS = {
    "SSLv2": ssl.PROTOCOL_SSLv23,  # Alias, on teste via OpenSSL
    "SSLv3": "SSLv3",
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}

# Ciphers faibles
WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]


class CryptoAgent(BaseAgent):
    name = "crypto"

    def run(self, target):
        host = self._extract_host(target)
        print(f"[CRYPTO] audit TLS de {host}")

        findings = []

        # 1. Info certificat
        cert_info = self._get_certificate(host)
        if cert_info.get("error"):
            return {"agent": self.name, "error": cert_info["error"]}

        # 2. Verif expiration
        findings += self._check_expiration(cert_info)

        # 3. Verif cipher/protocole
        findings += self._check_protocol(host)

        # 4. Verif chaine
        findings += self._check_chain(host, cert_info)

        # 5. Analyse LLM
        if findings:
            findings = self._analyze(findings, cert_info)

        return {
            "agent": self.name,
            "host": host,
            "certificate": {
                "subject": cert_info.get("subject"),
                "issuer": cert_info.get("issuer"),
                "not_before": cert_info.get("not_before"),
                "not_after": cert_info.get("not_after"),
                "serial": cert_info.get("serial"),
            },
            "findings": findings,
        }

    def _extract_host(self, target):
        if "://" in target:
            return urlparse(target).netloc.split(":")[0]
        return target.split(":")[0]

    def _get_certificate(self, host):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial": cert.get("serialNumber"),
                        "version": version,
                        "cipher": cipher,
                    }
        except ssl.SSLError as e:
            return {"error": f"SSL error: {e}"}
        except socket.timeout:
            return {"error": f"Timeout sur {host}:443"}
        except Exception as e:
            return {"error": str(e)}

    def _check_expiration(self, cert):
        out = []
        try:
            not_after = datetime.strptime(
                cert["not_after"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days

            if days_left < 0:
                out.append({
                    "type": "cert_expired",
                    "severity": "critical",
                    "days": days_left,
                    "reason": f"Certificat expire depuis {abs(days_left)} jours",
                })
            elif days_left < 7:
                out.append({
                    "type": "cert_expiring_soon",
                    "severity": "high",
                    "days": days_left,
                    "reason": f"Expire dans {days_left} jours",
                })
            elif days_left < 30:
                out.append({
                    "type": "cert_expiring",
                    "severity": "medium",
                    "days": days_left,
                    "reason": f"Expire dans {days_left} jours",
                })
        except Exception:
            pass
        return out

    def _check_protocol(self, host):
        out = []
        # Test TLS 1.0/1.1 (obsoletes)
        for proto_name, proto_version in [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = proto_version
                ctx.maximum_version = proto_version
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        out.append({
                            "type": "weak_protocol_enabled",
                            "protocol": proto_name,
                            "severity": "medium" if proto_name == "TLSv1.1" else "high",
                            "reason": f"{proto_name} supporte (obsolete)",
                        })
            except Exception:
                pass  # Protocole desactive = bon

        # Detection cipher faible
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in WEAK_CIPHERS:
                            if weak.lower() in cipher_name.lower():
                                out.append({
                                    "type": "weak_cipher",
                                    "cipher": cipher_name,
                                    "severity": "high",
                                    "reason": f"Cipher faible detecte: {weak}",
                                })
                                break
        except Exception:
            pass
        return out

    def _check_chain(self, host, cert_info):
        out = []
        # Verifie si le certificat est auto-signe
        subject = cert_info.get("subject", {})
        issuer = cert_info.get("issuer", {})
        if subject == issuer:
            out.append({
                "type": "self_signed_cert",
                "severity": "medium",
                "reason": "Certificat auto-signe",
            })
        # Verifie si le hostname matche le CN
        cn = subject.get("commonName", "")
        if cn and host not in cn and not cn.startswith("*."):
            out.append({
                "type": "hostname_mismatch",
                "severity": "high",
                "cn": cn,
                "reason": f"CN '{cn}' != host '{host}'",
            })
        return out

    def _analyze(self, findings, cert_info):
        try:
            sys = ('Expert TLS/SSL. JSON strict: '
                   '{"validated":[{"type":"","severity":"",'
                   '"impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f['type']} | {f.get('severity','')} | {f.get('reason','')}"
                for f in findings)
            r = ask_ai_json(
                f"Cert:\n{cert_info.get('issuer')}\nFindings:\n{txt}",
                system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[CRYPTO] llm err: {e}")
            return findings
