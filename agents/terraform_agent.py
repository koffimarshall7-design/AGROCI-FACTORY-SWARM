"""Agent TERRAFORM - audit IaC."""
import re
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


TF_RISKS = {
    "hardcoded_secret": (r'(?i)(password|secret|token|api_key|access_key)\s*=\s*"[^"]{8,}"', "critical", "Secret hardcode"),
    "public_s3": (r'acl\s*=\s*"public-read"', "critical", "S3 public-read"),
    "public_s3_rw": (r'acl\s*=\s*"public-read-write"', "critical", "S3 public-read-write"),
    "public_ip": (r'associate_public_ip_address\s*=\s*true', "medium", "IP publique"),
    "open_sg": (r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', "high", "SG ouvert"),
    "iam_wildcard": (r'"\*"\s*(?:,|\])', "high", "IAM wildcard"),
    "no_encryption": (r'encrypted\s*=\s*false', "high", "Non chiffre"),
    "logging_disabled": (r'enable_logging\s*=\s*false', "medium", "Logs desactives"),
    "rds_public": (r'publicly_accessible\s*=\s*true', "critical", "RDS public"),
    "no_backup": (r'(?i)backup_retention_period\s*=\s*0', "high", "Pas de backup"),
}


class TerraformAgent(BaseAgent):
    name = "terraform"

    def run(self, path):
        root = Path(path)
        print(f"[TF] audit de {root}")
        findings = []
        tf_files = list(root.rglob("*.tf")) + list(root.rglob("*.tfvars"))

        for tf in tf_files:
            try:
                content = tf.read_text(encoding="utf-8", errors="ignore")
                print(f"[TF] {tf.name}")
                findings += self._audit_file(tf, content)
            except Exception:
                pass

        print(f"[TF] {len(tf_files)} fichier(s)")

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "path": str(root),
                "tf_files": len(tf_files), "findings": findings}

    def _audit_file(self, tf, content):
        out = []
        lines = content.splitlines()
        for name, (regex, sev, reason) in TF_RISKS.items():
            for m in re.finditer(regex, content, re.MULTILINE):
                line_no = content[:m.start()].count("\n") + 1
                evidence = m.group(0)[:100]
                if "secret" in name or "password" in name or "key" in name:
                    evidence = re.sub(r'"[^"]{8,}"', '"***"', evidence)
                out.append({
                    "type": "terraform_issue", "subtype": name,
                    "file": str(tf), "line": line_no,
                    "evidence": evidence, "severity": sev, "reason": reason,
                })
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert Terraform/IaC. JSON strict: '
                   '{"validated":[{"type":"","subtype":"","severity":"",'
                   '"impact":"","fix":""}]}')
            txt = "\n".join(
                f"- {f.get('subtype')} | {f.get('severity')} | {f.get('file','')}"
                for f in findings[:30])
            r = ask_ai_json(f"TF findings:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[TF] llm err: {e}")
            return findings
