"""Agent CODE - audit de code source (secrets, injections, deps)."""
import re
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


# Patterns de secrets hardcodes
SECRET_PATTERNS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "openai_key": r"sk-[A-Za-z0-9]{20,}",
    "groq_key": r"gsk_[A-Za-z0-9]{20,}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9\-]+",
    "private_key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    "password_assign": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",
    "api_key_assign": r"(?i)api[_-]?key\s*=\s*['\"][^'\"]{10,}['\"]",
}

# Extensions a scanner
CODE_EXT = [".py", ".js", ".ts", ".php", ".rb", ".go", ".java",
            ".env", ".yaml", ".yml", ".json", ".xml", ".txt", ".conf"]

# Patterns d'injection basique
INJECTION_PATTERNS = {
    "sql_concat": r"(?i)(execute|query|cursor)\s*\(\s*[\"'].*\+.*[\"']",
    "os_command": r"(?i)(os\.system|subprocess\.(call|run|Popen))\s*\(",
    "eval_usage": r"(?i)\beval\s*\(",
    "exec_usage": r"(?i)\bexec\s*\(",
    "innerHTML": r"\.innerHTML\s*=",
    "pickle_load": r"pickle\.loads?\s*\(",
}

# Fichiers a ignorer
SKIP_DIRS = {".git", "venv", "node_modules", "__pycache__",
             ".pytest_cache", "dist", "build"}


class CodeAgent(BaseAgent):
    name = "code"

    def run(self, path):
        root = Path(path)
        if not root.exists():
            return {"agent": self.name, "error": f"{path} introuvable"}

        print(f"[CODE] audit de {root}")
        findings = []
        files_scanned = 0

        for f in self._walk(root):
            files_scanned += 1
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                findings += self._scan_secrets(f, content)
                findings += self._scan_injections(f, content)
            except Exception:
                pass

        print(f"[CODE] {files_scanned} fichier(s), {len(findings)} finding(s)")
        if findings:
            findings = self._analyze(findings)

        return {
            "agent": self.name,
            "path": str(root),
            "files_scanned": files_scanned,
            "findings": findings,
        }

    def _walk(self, root):
        for f in root.rglob("*"):
            if f.is_file() and not any(p in f.parts for p in SKIP_DIRS):
                if f.suffix in CODE_EXT or f.name.startswith(".env"):
                    yield f

    def _scan_secrets(self, f, content):
        out = []
        for name, pattern in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content):
                # Numero de ligne
                line_no = content[:m.start()].count("\n") + 1
                # Masque le secret
                secret = m.group(0)
                masked = secret[:6] + "***" + secret[-4:] if len(secret) > 12 else "***"
                out.append({
                    "type": "hardcoded_secret",
                    "subtype": name,
                    "file": str(f),
                    "line": line_no,
                    "evidence": masked,
                    "severity": "critical" if name in ("private_key", "aws_key") else "high",
                })
        return out

    def _scan_injections(self, f, content):
        out = []
        for name, pattern in INJECTION_PATTERNS.items():
            for m in re.finditer(pattern, content):
                line_no = content[:m.start()].count("\n") + 1
                out.append({
                    "type": "potential_injection",
                    "subtype": name,
                    "file": str(f),
                    "line": line_no,
                    "evidence": m.group(0)[:80],
                    "severity": "high" if name in ("sql_concat", "os_command", "eval_usage") else "medium",
                })
        return out

    def _analyze(self, findings):
        try:
            sys = (
                "Analyste securite code. Verifie chaque finding et propose "
                "un fix concret. JSON strict: "
                '{"validated":[{"type":"","file":"","line":0,'
                '"severity":"","fix":"","cwe":""}]}'
            )
            txt = "\n".join(
                f"- {f['type']}/{f.get('subtype','')} | {f['file']}:{f['line']}"
                for f in findings[:30]
            )
            r = ask_ai_json(f"Findings code:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[CODE] analyse LLM echouee: {e}")
            return findings
