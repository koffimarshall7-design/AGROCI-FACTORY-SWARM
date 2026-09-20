"""Agent SECRETS - scanner global de secrets (trufflehog-like)."""
import re
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


SECRET_PATTERNS = {
    "aws_access": (r"AKIA[0-9A-Z]{16}", "critical"),
    "aws_secret": (r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    "gcp_key": (r"AIza[0-9A-Za-z\-_]{35}", "critical"),
    "openai": (r"sk-[A-Za-z0-9]{20,}", "critical"),
    "groq": (r"gsk_[A-Za-z0-9]{20,}", "critical"),
    "anthropic": (r"sk-ant-[A-Za-z0-9\-_]{20,}", "critical"),
    "github_pat": (r"ghp_[A-Za-z0-9]{36}", "critical"),
    "github_oauth": (r"gho_[A-Za-z0-9]{36}", "critical"),
    "gitlab_pat": (r"glpat-[A-Za-z0-9\-_]{20}", "critical"),
    "slack_bot": (r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+", "critical"),
    "slack_user": (r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+", "critical"),
    "stripe_live": (r"sk_live_[A-Za-z0-9]{24,}", "critical"),
    "stripe_test": (r"sk_test_[A-Za-z0-9]{24,}", "high"),
    "twilio": (r"SK[0-9a-fA-F]{32}", "high"),
    "sendgrid": (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "high"),
    "private_key": (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    "jwt": (r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]+", "medium"),
    "generic_password": (r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]", "high"),
    "generic_api_key": (r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{16,}['\"]", "high"),
    "generic_token": (r"(?i)(?:secret|token)[_-]?key?\s*[:=]\s*['\"][^'\"]{16,}['\"]", "high"),
    "basic_auth_url": (r"://[^:/\s]+:[^@/\s]+@", "high"),
    "connection_string": (r"(?i)(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@", "critical"),
}

SCAN_EXT = {".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".cs",
            ".env", ".yaml", ".yml", ".json", ".xml", ".ini", ".conf",
            ".tf", ".tfvars", ".md", ".txt", ".sh", ".bash", ".zsh",
            ".properties", ".toml", ".cfg", ".pem", ".key"}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
             ".pytest_cache", "dist", "build", ".tox", "target",
             "vendor", ".mypy_cache", ".ruff_cache"}

FALSE_POSITIVES = [
    "AKIAIOSFODNN7EXAMPLE",
    "sk_test_example",
    "your_api_key_here",
    "xxx",
    "placeholder",
    "exemple",
    "example",
]


class SecretsAgent(BaseAgent):
    name = "secrets"

    def run(self, path):
        root = Path(path)
        print(f"[SECRETS] scan de {root}")

        findings = []
        files_scanned = 0

        for f in self._walk(root):
            files_scanned += 1
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                findings += self._scan_file(f, content)
            except Exception:
                pass

        print(f"[SECRETS] {files_scanned} fichier(s), {len(findings)} secret(s)")

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "path": str(root),
                "files_scanned": files_scanned, "findings": findings}

    def _walk(self, root):
        for f in root.rglob("*"):
            if f.is_file() and not any(p in f.parts for p in SKIP_DIRS):
                if f.suffix.lower() in SCAN_EXT or f.name.startswith(".env") or \
                   "dockerfile" in f.name.lower() or f.name.endswith(".pem"):
                    try:
                        if f.stat().st_size < 5_000_000:
                            yield f
                    except Exception:
                        pass

    def _scan_file(self, f, content):
        out = []
        for name, (regex, sev) in SECRET_PATTERNS.items():
            for m in re.finditer(regex, content):
                matched = m.group(0)
                low = matched.lower()
                if any(fp in low for fp in FALSE_POSITIVES):
                    continue
                line_no = content[:m.start()].count("\n") + 1
                masked = matched[:6] + "***" + matched[-4:] if len(matched) > 14 else "***"
                out.append({
                    "type": "hardcoded_secret",
                    "subtype": name,
                    "file": str(f),
                    "line": line_no,
                    "evidence": masked,
                    "severity": sev,
                })
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert secrets detection. Confirme les vrais secrets. '
                   'JSON strict: {"validated":[{"type":"","subtype":"",'
                   '"file":"","severity":"","impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('subtype')} | {f.get('severity')} | {f.get('file','')}"
                for f in findings[:30])
            r = ask_ai_json(f"Secrets detectes:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[SECRETS] llm err: {e}")
            return findings
