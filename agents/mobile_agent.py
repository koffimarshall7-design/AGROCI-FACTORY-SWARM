"""Agent MOBILE - audit APK Android / IPA iOS (decompilation, secrets)."""
import re
import zipfile
import subprocess
import shutil
from pathlib import Path
from core.ai_engine import ask_ai_json
from agents.base import BaseAgent


# Permissions Android dangereuses
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": ("high", "Lecture des SMS"),
    "android.permission.SEND_SMS": ("high", "Envoi de SMS (premium)"),
    "android.permission.READ_CONTACTS": ("medium", "Lecture contacts"),
    "android.permission.ACCESS_FINE_LOCATION": ("medium", "GPS precis"),
    "android.permission.RECORD_AUDIO": ("high", "Micro"),
    "android.permission.CAMERA": ("medium", "Camera"),
    "android.permission.READ_CALL_LOG": ("high", "Journal appels"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("low", "Ecriture SD"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("critical", "Installation APK"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("high", "Overlay (phishing)"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("critical", "Accessibilite"),
    "android.permission.PACKAGE_USAGE_STATS": ("medium", "Usage apps"),
}

# Patterns de secrets dans le code decompile
MOBILE_SECRET_PATTERNS = {
    "google_api": (r"AIza[0-9A-Za-z\-_]{35}", "critical"),
    "firebase": (r"https://[a-z0-9\-]+\.firebaseio\.com", "medium"),
    "aws_key": (r"AKIA[0-9A-Z]{16}", "critical"),
    "stripe": (r"sk_live_[A-Za-z0-9]{24,}", "critical"),
    "private_key": (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "critical"),
    "jwt": (r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]+", "medium"),
    "hardcoded_password": (r'(?i)password\s*[:=]\s*"[^"]{6,}"', "high"),
    "api_endpoint_http": (r"http://[a-z0-9\.\-]+\.[a-z]{2,}", "low"),
}


class MobileAgent(BaseAgent):
    name = "mobile"

    def run(self, apk_path):
        p = Path(apk_path)
        if not p.exists():
            return {"agent": self.name, "error": f"{apk_path} introuvable"}

        print(f"[MOBILE] audit de {p.name}")
        findings = []

        # 1. Verifie que c'est bien un APK
        if p.suffix.lower() == ".apk":
            findings += self._audit_apk(p)
        elif p.suffix.lower() == ".ipa":
            findings += self._audit_ipa(p)
        elif p.suffix.lower() == ".aab":
            findings += self._audit_aab(p)
        else:
            return {"agent": self.name, "error": f"Extension non supportee: {p.suffix}"}

        if findings:
            findings = self._analyze(findings)

        return {"agent": self.name, "path": str(p), "findings": findings}

    # ---------- APK ----------
    def _audit_apk(self, apk):
        out = []

        # 1. Contenu ZIP (classes.dex, ressources)
        try:
            with zipfile.ZipFile(apk) as z:
                names = z.namelist()
                print(f"[MOBILE] {len(names)} fichiers dans l'APK")
                # Cherche des fichiers sensibles
                for name in names:
                    if any(s in name.lower() for s in
                           [".env", "config.json", "secret", "credential",
                            ".pem", ".key", "google-services.json",
                            "keystore", ".jks"]):
                        out.append({
                            "type": "sensitive_file_in_apk",
                            "file": name,
                            "severity": "high",
                            "reason": f"Fichier sensible embarque: {name}",
                        })
        except Exception as e:
            print(f"[MOBILE] erreur ZIP: {e}")
            return [{"type": "apk_error", "error": str(e)}]

        # 2. Analyse AndroidManifest.xml (cherche permissions + debuggable + backup)
        try:
            with zipfile.ZipFile(apk) as z:
                manifest = z.read("AndroidManifest.xml")
                text = manifest.decode("utf-8", errors="ignore")
                out += self._audit_manifest(text, apk)
        except Exception:
            pass

        # 3. Decompilation avec apktool (si dispo)
        apktool = shutil.which("apktool")
        if apktool:
            print("[MOBILE] apktool trouve, decompilation...")
            out += self._apktool_scan(apk)
        else:
            print("[MOBILE] apktool non installe (optionnel)")

        # 4. Cherche strings dans le DEX
        out += self._scan_dex_strings(apk)

        return out

    def _audit_manifest(self, text, apk):
        out = []
        # Permissions
        for perm in re.findall(r'android\.permission\.[A-Z_]+', text):
            if perm in DANGEROUS_PERMISSIONS:
                sev, reason = DANGEROUS_PERMISSIONS[perm]
                out.append({
                    "type": "dangerous_permission",
                    "permission": perm,
                    "file": str(apk),
                    "severity": sev,
                    "reason": reason,
                })
        # android:debuggable="true"
        if 'debuggable="true"' in text or "debuggable='true'" in text:
            out.append({
                "type": "apk_debuggable",
                "severity": "critical",
                "reason": "App debug activable (extraction memoire possible)",
            })
        # android:allowBackup="true"
        if 'allowBackup="true"' in text:
            out.append({
                "type": "apk_backup_allowed",
                "severity": "high",
                "reason": "Backup ADB possible (vol de donnees)",
            })
        # android:exported="true" sur activity/service
        exported = text.count('exported="true"')
        if exported > 3:
            out.append({
                "type": "many_exported_components",
                "count": exported,
                "severity": "medium",
                "reason": f"{exported} composants exportes (surface d'attaque)",
            })
        # cleartext traffic
        if "usesCleartextTraffic" in text and 'usesCleartextTraffic="true"' in text:
            out.append({
                "type": "cleartext_traffic",
                "severity": "high",
                "reason": "HTTP en clair autorise",
            })
        return out

    def _scan_dex_strings(self, apk):
        """Cherche secrets dans les strings du DEX."""
        out = []
        try:
            with zipfile.ZipFile(apk) as z:
                for name in z.namelist():
                    if name.endswith(".dex") or name.endswith(".so"):
                        data = z.read(name)
                        text = data.decode("utf-8", errors="ignore")
                        for sub, (regex, sev) in MOBILE_SECRET_PATTERNS.items():
                            for m in re.finditer(regex, text):
                                matched = m.group(0)
                                if len(matched) < 8:
                                    continue
                                masked = matched[:6] + "***"
                                out.append({
                                    "type": "secret_in_apk",
                                    "subtype": sub,
                                    "file": name,
                                    "evidence": masked,
                                    "severity": sev,
                                })
                                break  # 1 seul par type pour eviter le spam
        except Exception:
            pass
        return out

    def _apktool_scan(self, apk):
        """Decompile avec apktool et scanne les sources."""
        out = []
        out_dir = Path("/tmp/apktool_out")
        if out_dir.exists():
            shutil.rmtree(out_dir)
        try:
            r = subprocess.run(
                ["apktool", "d", "-f", "-o", str(out_dir), str(apk)],
                capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                return out
            # Cherche secrets dans les smali
            for f in out_dir.rglob("*.smali"):
                text = f.read_text(errors="ignore")
                for sub, (regex, sev) in MOBILE_SECRET_PATTERNS.items():
                    if re.search(regex, text):
                        out.append({
                            "type": "secret_in_smali",
                            "subtype": sub,
                            "file": str(f),
                            "severity": sev,
                        })
                        break
        except Exception as e:
            print(f"[MOBILE] apktool err: {e}")
        return out

    # ---------- IPA (iOS) ----------
    def _audit_ipa(self, ipa):
        """Analyse basique d'un IPA iOS."""
        out = []
        try:
            with zipfile.ZipFile(ipa) as z:
                names = z.namelist()
                for name in names:
                    # Info.plist
                    if name.endswith("Info.plist"):
                        try:
                            plist = z.read(name).decode("utf-8", errors="ignore")
                            if "NSAllowsArbitraryLoads" in plist and "true" in plist:
                                out.append({
                                    "type": "ios_ats_disabled",
                                    "file": name,
                                    "severity": "high",
                                    "reason": "App Transport Security desactive",
                                })
                        except Exception:
                            pass
                    # Binaires + secrets
                    if name.endswith((".plist", ".json", ".strings")):
                        data = z.read(name).decode("utf-8", errors="ignore")
                        if re.search(r"AKIA[0-9A-Z]{16}", data):
                            out.append({
                                "type": "aws_key_in_ipa",
                                "file": name,
                                "severity": "critical",
                            })
        except Exception as e:
            out.append({"type": "ipa_error", "error": str(e)})
        return out

    # ---------- AAB (Android App Bundle) ----------
    def _audit_aab(self, aab):
        out = []
        try:
            with zipfile.ZipFile(aab) as z:
                names = z.namelist()
                print(f"[MOBILE] {len(names)} fichiers dans le AAB")
                for name in names:
                    if "debug" in name.lower() or ".env" in name.lower():
                        out.append({
                            "type": "sensitive_file_in_aab",
                            "file": name,
                            "severity": "high",
                        })
        except Exception as e:
            out.append({"type": "aab_error", "error": str(e)})
        return out

    def _analyze(self, findings):
        try:
            sys = ('Expert mobile security (OWASP MASVS). JSON strict: '
                   '{"validated":[{"type":"","severity":"",'
                   '"impact":"","fix":"","masvs":""}]}')
            txt = "\n".join(
                f"- {f.get('type')} | {f.get('severity')} | {f.get('reason','')[:60]}"
                for f in findings[:30])
            r = ask_ai_json(f"Findings mobile:\n{txt}", system=sys)
            return r.get("validated", findings)
        except Exception as e:
            print(f"[MOBILE] llm err: {e}")
            return findings
