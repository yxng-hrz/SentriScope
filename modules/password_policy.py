"""
SENTRISCOPE — Password Policy Checker
"""

import platform
import subprocess
import re
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


# ─── Niveaux de sévérité ──────────────────────────────────────────────────────

class PolicyLevel:
    GOOD    = "good"
    WARNING = "warning"
    DANGER  = "danger"
    INFO    = "info"


@dataclass
class PolicyCheck:
    """Résultat d'un contrôle individuel."""
    id: str
    title: str
    description: str
    status: str           # PolicyLevel.*
    value: str            # Valeur actuelle détectée
    recommendation: str
    score_impact: int     # Points déduits si pas GOOD (0‑25)


@dataclass
class PolicyReport:
    """Rapport complet de politique de mots de passe."""
    os_name: str
    scanned_at: str
    checks: List[PolicyCheck] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Score sur 100 (100 = parfait)."""
        total_impact = sum(c.score_impact for c in self.checks if c.status != PolicyLevel.GOOD)
        return max(0, 100 - total_impact)

    @property
    def good_count(self)    -> int: return sum(1 for c in self.checks if c.status == PolicyLevel.GOOD)
    @property
    def warning_count(self) -> int: return sum(1 for c in self.checks if c.status == PolicyLevel.WARNING)
    @property
    def danger_count(self)  -> int: return sum(1 for c in self.checks if c.status == PolicyLevel.DANGER)


# ─── Checker principal ────────────────────────────────────────────────────────

class PasswordPolicyChecker:
    """Analyse la politique de mots de passe du système local."""

    def run(self) -> PolicyReport:
        os_name = platform.system()
        report = PolicyReport(os_name=os_name, scanned_at=datetime.now().isoformat())

        if os_name == "Windows":
            checks = self._check_windows()
        elif os_name == "Linux":
            checks = self._check_linux()
        elif os_name == "Darwin":
            checks = self._check_macos()
        else:
            checks = self._check_generic()

        # Toujours ajouter les vérifications universelles
        checks += self._check_universal()
        report.checks = checks
        return report

    # ── Windows ───────────────────────────────────────────────────────────────

    def _check_windows(self) -> List[PolicyCheck]:
        checks = []
        policy = self._get_windows_policy()

        # Longueur minimale
        min_len = policy.get("min_length", 0)
        checks.append(PolicyCheck(
            id="win_min_length",
            title="Longueur minimale",
            description="Nombre minimal de caractères requis pour un mot de passe.",
            status=PolicyLevel.GOOD if min_len >= 12 else (PolicyLevel.WARNING if min_len >= 8 else PolicyLevel.DANGER),
            value=f"{min_len} caractères",
            recommendation="Recommandé : ≥ 12 caractères (ANSSI). Idéal : ≥ 16.",
            score_impact=0 if min_len >= 12 else (10 if min_len >= 8 else 20),
        ))

        # Complexité
        complexity = policy.get("complexity", False)
        checks.append(PolicyCheck(
            id="win_complexity",
            title="Complexité activée",
            description="Exige majuscules, minuscules, chiffres et symboles.",
            status=PolicyLevel.GOOD if complexity else PolicyLevel.DANGER,
            value="Activée" if complexity else "Désactivée",
            recommendation="Activer la complexité dans : Stratégie de sécurité locale > Stratégie de compte.",
            score_impact=0 if complexity else 20,
        ))

        # Expiration
        max_age = policy.get("max_age_days", 0)
        checks.append(PolicyCheck(
            id="win_max_age",
            title="Expiration du mot de passe",
            description="Durée maximale de validité avant changement obligatoire.",
            status=PolicyLevel.GOOD if 30 <= max_age <= 90 else (PolicyLevel.WARNING if max_age <= 180 else PolicyLevel.DANGER),
            value=f"{max_age} jours" if max_age > 0 else "Jamais",
            recommendation="Recommandé : 60-90 jours. 0 = n'expire jamais (déconseillé).",
            score_impact=0 if 30 <= max_age <= 90 else (5 if max_age <= 180 else 15),
        ))

        # Historique
        history = policy.get("history_count", 0)
        checks.append(PolicyCheck(
            id="win_history",
            title="Historique des mots de passe",
            description="Nombre de mots de passe mémorisés pour éviter la réutilisation.",
            status=PolicyLevel.GOOD if history >= 10 else (PolicyLevel.WARNING if history >= 5 else PolicyLevel.DANGER),
            value=f"{history} mots de passe mémorisés",
            recommendation="Recommandé : ≥ 10 (empêche la réutilisation des anciens mdp).",
            score_impact=0 if history >= 10 else (5 if history >= 5 else 10),
        ))

        # Verrouillage de compte
        lockout = policy.get("lockout_threshold", 0)
        checks.append(PolicyCheck(
            id="win_lockout",
            title="Seuil de verrouillage de compte",
            description="Nombre de tentatives échouées avant blocage du compte.",
            status=PolicyLevel.GOOD if 3 <= lockout <= 10 else (PolicyLevel.WARNING if lockout <= 15 else PolicyLevel.DANGER),
            value=f"{lockout} tentatives" if lockout > 0 else "Désactivé",
            recommendation="Recommandé : 5 tentatives. 0 = pas de verrouillage (attaque brute-force possible).",
            score_impact=0 if 3 <= lockout <= 10 else (5 if 0 < lockout <= 15 else 15),
        ))

        # Durée de verrouillage
        lockout_dur = policy.get("lockout_duration", 0)
        checks.append(PolicyCheck(
            id="win_lockout_duration",
            title="Durée de verrouillage",
            description="Temps en minutes avant déblocage automatique du compte.",
            status=PolicyLevel.GOOD if lockout_dur >= 15 else (PolicyLevel.WARNING if lockout_dur >= 5 else PolicyLevel.DANGER),
            value=f"{lockout_dur} minutes" if lockout_dur > 0 else "0 (manuel seulement)",
            recommendation="Recommandé : ≥ 15 minutes (ralentit les attaques brute-force).",
            score_impact=0 if lockout_dur >= 15 else (5 if lockout_dur >= 5 else 10),
        ))

        return checks

    def _get_windows_policy(self) -> Dict:
        """Récupérer la politique via 'net accounts'."""
        policy = {
            "min_length": 0, "complexity": False, "max_age_days": 0,
            "history_count": 0, "lockout_threshold": 0, "lockout_duration": 0,
        }
        try:
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True, text=True, timeout=10,
                creationflags=0x08000000 if platform.system() == "Windows" else 0
            )
            output = result.stdout

            for line in output.splitlines():
                line_low = line.lower()
                nums = re.findall(r"\d+", line)
                if not nums:
                    continue
                val = int(nums[0])

                if "longueur minimale" in line_low or "minimum password length" in line_low:
                    policy["min_length"] = val
                elif "durée de vie max" in line_low or "maximum password age" in line_low:
                    policy["max_age_days"] = val
                elif "historique" in line_low or "password history" in line_low:
                    policy["history_count"] = val
                elif "seuil de verrouillage" in line_low or "lockout threshold" in line_low:
                    policy["lockout_threshold"] = val
                elif "durée de verrouillage" in line_low or "lockout duration" in line_low:
                    policy["lockout_duration"] = val

            # Complexité via secedit (best effort)
            try:
                tmp = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "secpol_tmp.cfg")
                subprocess.run(
                    ["secedit", "/export", "/cfg", tmp, "/quiet"],
                    capture_output=True, timeout=15,
                    creationflags=0x08000000
                )
                if os.path.exists(tmp):
                    with open(tmp, "r", encoding="utf-16-le", errors="ignore") as f:
                        content = f.read()
                    if "PasswordComplexity = 1" in content:
                        policy["complexity"] = True
                    os.unlink(tmp)
            except Exception:
                pass

        except Exception as e:
            policy["_error"] = str(e)

        return policy

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> List[PolicyCheck]:
        checks = []
        logindefs = self._read_login_defs()
        pwquality = self._read_pwquality()
        pam_ok = self._check_pam_pwquality()

        # Longueur minimale
        min_len = pwquality.get("minlen", logindefs.get("PASS_MIN_LEN", 0))
        checks.append(PolicyCheck(
            id="lnx_min_length",
            title="Longueur minimale",
            description="minlen dans /etc/security/pwquality.conf ou PASS_MIN_LEN dans /etc/login.defs.",
            status=PolicyLevel.GOOD if min_len >= 12 else (PolicyLevel.WARNING if min_len >= 8 else PolicyLevel.DANGER),
            value=f"{min_len} caractères" if min_len else "Non défini",
            recommendation="Configurer minlen = 12 dans /etc/security/pwquality.conf.",
            score_impact=0 if min_len >= 12 else (10 if min_len >= 8 else 20),
        ))

        # Complexité (pwquality)
        dcredit  = abs(pwquality.get("dcredit",  0))
        ucredit  = abs(pwquality.get("ucredit",  0))
        lcredit  = abs(pwquality.get("lcredit",  0))
        ocredit  = abs(pwquality.get("ocredit",  0))
        has_complexity = dcredit > 0 or ucredit > 0 or ocredit > 0
        checks.append(PolicyCheck(
            id="lnx_complexity",
            title="Complexité (pwquality)",
            description="dcredit, ucredit, lcredit, ocredit dans pwquality.conf.",
            status=PolicyLevel.GOOD if has_complexity else PolicyLevel.DANGER,
            value=f"chiffres:{dcredit} MAJ:{ucredit} min:{lcredit} spéciaux:{ocredit}",
            recommendation="Définir dcredit=-1 ucredit=-1 ocredit=-1 dans /etc/security/pwquality.conf.",
            score_impact=0 if has_complexity else 15,
        ))

        # PAM pwquality activé
        checks.append(PolicyCheck(
            id="lnx_pam",
            title="Module PAM pam_pwquality",
            description="Vérifie que pam_pwquality.so est chargé dans /etc/pam.d/common-password.",
            status=PolicyLevel.GOOD if pam_ok else PolicyLevel.WARNING,
            value="Activé" if pam_ok else "Non détecté",
            recommendation="Ajouter 'password requisite pam_pwquality.so retry=3' dans /etc/pam.d/common-password.",
            score_impact=0 if pam_ok else 10,
        ))

        # Expiration max
        max_days = logindefs.get("PASS_MAX_DAYS", 99999)
        checks.append(PolicyCheck(
            id="lnx_max_days",
            title="Expiration (PASS_MAX_DAYS)",
            description="Durée maximale en jours avant changement obligatoire (/etc/login.defs).",
            status=PolicyLevel.GOOD if 30 <= max_days <= 90 else (PolicyLevel.WARNING if max_days <= 180 else PolicyLevel.DANGER),
            value=f"{max_days} jours",
            recommendation="Définir PASS_MAX_DAYS 90 dans /etc/login.defs.",
            score_impact=0 if 30 <= max_days <= 90 else (5 if max_days <= 180 else 15),
        ))

        # Âge minimum
        min_days = logindefs.get("PASS_MIN_DAYS", 0)
        checks.append(PolicyCheck(
            id="lnx_min_days",
            title="Délai avant re-changement (PASS_MIN_DAYS)",
            description="Nombre minimal de jours entre deux changements de mot de passe.",
            status=PolicyLevel.GOOD if min_days >= 1 else PolicyLevel.WARNING,
            value=f"{min_days} jours",
            recommendation="Définir PASS_MIN_DAYS 1 pour éviter les contournements d'historique.",
            score_impact=0 if min_days >= 1 else 5,
        ))

        # Historique (pam_pwhistory)
        hist_ok = self._check_pam_pwhistory()
        checks.append(PolicyCheck(
            id="lnx_history",
            title="Historique (pam_pwhistory)",
            description="Empêche la réutilisation des anciens mots de passe.",
            status=PolicyLevel.GOOD if hist_ok else PolicyLevel.WARNING,
            value="Activé" if hist_ok else "Non détecté",
            recommendation="Ajouter 'password required pam_pwhistory.so remember=10' dans /etc/pam.d/common-password.",
            score_impact=0 if hist_ok else 10,
        ))

        # Verrouillage (pam_faillock)
        faillock_ok = self._check_pam_faillock()
        checks.append(PolicyCheck(
            id="lnx_faillock",
            title="Verrouillage de compte (pam_faillock)",
            description="Bloque le compte après N tentatives échouées.",
            status=PolicyLevel.GOOD if faillock_ok else PolicyLevel.DANGER,
            value="Activé" if faillock_ok else "Non détecté",
            recommendation="Configurer pam_faillock dans /etc/pam.d/common-auth (deny=5 unlock_time=900).",
            score_impact=0 if faillock_ok else 15,
        ))

        return checks

    def _read_login_defs(self) -> Dict:
        result = {}
        try:
            with open("/etc/login.defs", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                result[parts[0]] = int(parts[1])
                            except ValueError:
                                result[parts[0]] = parts[1]
        except Exception:
            pass
        return result

    def _read_pwquality(self) -> Dict:
        result = {}
        paths = ["/etc/security/pwquality.conf", "/etc/pwquality.conf"]
        for path in paths:
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, _, v = line.partition("=")
                            try:
                                result[k.strip()] = int(v.strip())
                            except ValueError:
                                result[k.strip()] = v.strip()
                break
            except Exception:
                pass
        return result

    def _check_pam_pwquality(self) -> bool:
        for path in ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]:
            try:
                with open(path, "r") as f:
                    if "pam_pwquality" in f.read():
                        return True
            except Exception:
                pass
        return False

    def _check_pam_pwhistory(self) -> bool:
        for path in ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]:
            try:
                with open(path, "r") as f:
                    if "pam_pwhistory" in f.read() or "pam_unix" in f.read():
                        return True
            except Exception:
                pass
        return False

    def _check_pam_faillock(self) -> bool:
        for path in ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/security/faillock.conf"]:
            try:
                with open(path, "r") as f:
                    content = f.read()
                    if "pam_faillock" in content or "pam_tally2" in content:
                        return True
            except Exception:
                pass
        return False

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> List[PolicyCheck]:
        checks = []
        policy = self._get_macos_policy()

        min_len = policy.get("minLength", 0)
        checks.append(PolicyCheck(
            id="mac_min_length",
            title="Longueur minimale",
            description="Paramètre minLength de la politique de mot de passe locale.",
            status=PolicyLevel.GOOD if min_len >= 12 else (PolicyLevel.WARNING if min_len >= 8 else PolicyLevel.DANGER),
            value=f"{min_len} caractères" if min_len else "Non défini",
            recommendation="sudo pwpolicy -setglobalpolicy 'minChars=12'",
            score_impact=0 if min_len >= 12 else (10 if min_len >= 8 else 20),
        ))

        require_alpha = policy.get("requiresAlpha", False)
        require_numeric = policy.get("requiresNumeric", False)
        checks.append(PolicyCheck(
            id="mac_complexity",
            title="Complexité requise",
            description="Exige des lettres et chiffres (requiresAlpha + requiresNumeric).",
            status=PolicyLevel.GOOD if (require_alpha and require_numeric) else PolicyLevel.WARNING,
            value="Oui" if (require_alpha and require_numeric) else "Partielle ou absente",
            recommendation="sudo pwpolicy -setglobalpolicy 'requiresAlpha=1 requiresNumeric=1'",
            score_impact=0 if (require_alpha and require_numeric) else 10,
        ))

        max_failed = policy.get("maxFailedPasswordAttempts", 0)
        checks.append(PolicyCheck(
            id="mac_lockout",
            title="Tentatives avant verrouillage",
            description="Nombre de tentatives échouées avant blocage du compte.",
            status=PolicyLevel.GOOD if 3 <= max_failed <= 10 else PolicyLevel.WARNING,
            value=f"{max_failed}" if max_failed else "Non limité",
            recommendation="sudo pwpolicy -setglobalpolicy 'maxFailedPasswordAttempts=5'",
            score_impact=0 if 3 <= max_failed <= 10 else 10,
        ))

        return checks

    def _get_macos_policy(self) -> Dict:
        result = {}
        try:
            out = subprocess.check_output(
                ["pwpolicy", "-getglobalpolicy"], stderr=subprocess.DEVNULL,
                timeout=5, text=True
            )
            for token in out.split():
                if "=" in token:
                    k, _, v = token.partition("=")
                    try:
                        result[k] = int(v)
                    except ValueError:
                        result[k] = v.lower() in ("1", "true", "yes")
        except Exception:
            pass
        return result

    # ── Vérifications universelles (toutes plateformes) ───────────────────────

    def _check_universal(self) -> List[PolicyCheck]:
        checks = []

        # Mot de passe admin par défaut dans SENTRISCOPE
        try:
            from modules.database import db
            import hashlib
            default_hash = hashlib.sha256(b"admin").hexdigest()
            conn = db._get_conn()
            cur = conn.execute(
                "SELECT username FROM users WHERE password_hash = ? AND role = 'admin'",
                (default_hash,)
            )
            row = cur.fetchone()
            conn.close()
            default_pwd_found = row is not None
        except Exception:
            default_pwd_found = False

        checks.append(PolicyCheck(
            id="app_default_password",
            title="Mot de passe admin par défaut",
            description="Vérifie si le compte admin SENTRISCOPE utilise encore le mot de passe 'admin'.",
            status=PolicyLevel.DANGER if default_pwd_found else PolicyLevel.GOOD,
            value="'admin' (mot de passe par défaut)" if default_pwd_found else "Modifié ✓",
            recommendation="Changer immédiatement le mot de passe admin dans Paramètres > Gestion des comptes.",
            score_impact=25 if default_pwd_found else 0,
        ))

        # Fichier shadow lisible (Linux)
        if platform.system() == "Linux":
            shadow_readable = os.access("/etc/shadow", os.R_OK)
            checks.append(PolicyCheck(
                id="lnx_shadow_perms",
                title="Permissions /etc/shadow",
                description="Le fichier shadow contient les hashes de mots de passe. Il ne doit pas être lisible par tous.",
                status=PolicyLevel.DANGER if shadow_readable else PolicyLevel.GOOD,
                value="Lisible sans root ⚠️" if shadow_readable else "Protégé ✓",
                recommendation="chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
                score_impact=20 if shadow_readable else 0,
            ))

        return checks

    # ── Generic fallback ──────────────────────────────────────────────────────

    def _check_generic(self) -> List[PolicyCheck]:
        return [PolicyCheck(
            id="generic_unsupported",
            title="Système non supporté",
            description=f"La détection automatique n'est pas disponible pour {platform.system()}.",
            status=PolicyLevel.INFO,
            value=platform.system(),
            recommendation="Vérifiez manuellement votre politique de mots de passe.",
            score_impact=0,
        )]
