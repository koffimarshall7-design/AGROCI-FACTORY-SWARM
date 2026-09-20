"""Agent CLOUD - audit config AWS/GCP/Azure (buckets, IAM, logs)."""
import os
import httpx
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


class CloudAgent(BaseAgent):
    name = "cloud"

    def __init__(self):
        super().__init__()
        self.client = httpx.Client(timeout=10, follow_redirects=True)

    def run(self, mode="local"):
        """mode: 'local' (config locale) | 'buckets' (URLs de buckets)."""
        print(f"[CLOUD] audit mode={mode}")
        findings = []

        # 1. Verif credentials exposees dans l'environnement
        findings += self._check_env_creds()

        # 2. Verif buckets publics (via config locale)
        findings += self._check_public_buckets()

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "findings": findings}

    def _check_env_creds(self):
        """Detecte des credentials cloud exposes dans les variables d'env."""
        out = []
        sensitive = {
            "AWS_ACCESS_KEY_ID": "AWS access key",
            "AWS_SECRET_ACCESS_KEY": "AWS secret key",
            "GOOGLE_APPLICATION_CREDENTIALS": "GCP credentials path",
            "AZURE_CLIENT_SECRET": "Azure client secret",
            "GITHUB_TOKEN": "GitHub token",
        }
        for var, desc in sensitive.items():
            if os.getenv(var):
                out.append({
                    "type": "cloud_cred_in_env",
                    "variable": var,
                    "severity": "high",
                    "reason": f"{desc} exposee dans l'environnement",
                })
        if out:
            print(f"[CLOUD] {len(out)} credential(s) cloud dans l'env")
        return out

    def _check_public_buckets(self):
        """Verifie si des buckets declares localement sont publics."""
        out = []
        # Lit une liste de buckets dans config/buckets.txt
        bucket_file = "config/buckets.txt"
        if not os.path.exists(bucket_file):
            return out

        with open(bucket_file) as f:
            buckets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        for bucket in buckets:
            # Test AWS S3
            for url in [
                f"https://{bucket}.s3.amazonaws.com/",
                f"https://storage.googleapis.com/{bucket}/",
                f"https://{bucket}.blob.core.windows.net/",
            ]:
                try:
                    r = self.client.get(url)
                    if r.status_code == 200 and "ListBucketResult" in r.text:
                        out.append({
                            "type": "public_bucket",
                            "url": url,
                            "severity": "critical",
                            "reason": "Bucket listing public",
                        })
                        print(f"[CLOUD] bucket public: {url}")
                except Exception:
                    pass
        return out

    def _analyze(self, findings):
        try:
            sys = (
                "Expert cloud security. JSON strict: "
                '{"validated":[{"type":"","severity":"","impact":"","fix":""}]}'
            )
            r = ask_ai_json(f"Findings cloud:\n{findings}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[CLOUD] err: {e}")
            return findings
