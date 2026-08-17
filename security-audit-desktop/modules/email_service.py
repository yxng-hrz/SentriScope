"""
SENTRISCOPE — EmailService v2
Configuration automatique SMTP depuis le domaine email.
"""

import smtplib
import ssl
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime

from modules.database import db


# ── Fournisseurs connus → config SMTP automatique ─────────────────────────────
SMTP_PROVIDERS = {
    "gmail.com":       ("smtp.gmail.com",      587, False),
    "googlemail.com":  ("smtp.gmail.com",      587, False),
    "outlook.com":     ("smtp.office365.com",  587, False),
    "hotmail.com":     ("smtp.office365.com",  587, False),
    "live.com":        ("smtp.office365.com",  587, False),
    "office365.com":   ("smtp.office365.com",  587, False),
    "yahoo.com":       ("smtp.mail.yahoo.com", 587, False),
    "yahoo.fr":        ("smtp.mail.yahoo.com", 587, False),
    "icloud.com":      ("smtp.mail.me.com",    587, False),
    "me.com":          ("smtp.mail.me.com",    587, False),
    "protonmail.com":  ("127.0.0.1",           1025, False),  # Bridge local
    "proton.me":       ("127.0.0.1",           1025, False),
    "ovh.com":         ("ssl0.ovh.net",        465, True),
    "ovh.net":         ("ssl0.ovh.net",        465, True),
    "laposte.net":     ("smtp.laposte.net",    465, True),
    "orange.fr":       ("smtp.orange.fr",      465, True),
    "free.fr":         ("smtp.free.fr",        465, True),
    "sfr.fr":          ("smtp.sfr.fr",         465, True),
    "wanadoo.fr":      ("smtp.orange.fr",      465, True),
}

PROVIDER_LABELS = {
    "gmail.com":      "Gmail",
    "googlemail.com": "Gmail",
    "outlook.com":    "Outlook / Microsoft 365",
    "hotmail.com":    "Outlook / Hotmail",
    "live.com":       "Outlook / Live",
    "office365.com":  "Microsoft 365",
    "yahoo.com":      "Yahoo Mail",
    "yahoo.fr":       "Yahoo Mail",
    "icloud.com":     "iCloud Mail",
    "me.com":         "iCloud Mail",
    "protonmail.com": "ProtonMail (Bridge)",
    "proton.me":      "ProtonMail (Bridge)",
    "ovh.com":        "OVH Mail",
    "ovh.net":        "OVH Mail",
    "laposte.net":    "La Poste",
    "orange.fr":      "Orange Mail",
    "free.fr":        "Free Mail",
    "sfr.fr":         "SFR Mail",
}

PROVIDER_HINTS = {
    "gmail.com":      "Utilisez un mot de passe d'application Google (pas votre mot de passe Google)\nCompte → Sécurité → Mots de passe d'application",
    "googlemail.com": "Utilisez un mot de passe d'application Google\nCompte → Sécurité → Mots de passe d'application",
    "outlook.com":    "Utilisez votre mot de passe Microsoft habituel",
    "hotmail.com":    "Utilisez votre mot de passe Microsoft habituel",
    "live.com":       "Utilisez votre mot de passe Microsoft habituel",
    "office365.com":  "Utilisez votre mot de passe Microsoft 365",
    "yahoo.com":      "Activez SMTP dans Yahoo Mail → Sécurité → Mot de passe d'application",
    "icloud.com":     "Utilisez un mot de passe spécifique à l'app\nApple ID → Sécurité → Mots de passe dédiés",
    "protonmail.com": "Requis : ProtonMail Bridge installé et actif sur ce PC",
    "proton.me":      "Requis : ProtonMail Bridge installé et actif sur ce PC",
}


def detect_provider(email: str) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[bool]]:
    """Retourne (label, server, port, use_ssl) depuis le domaine de l'email."""
    try:
        domain = email.strip().lower().split("@")[1]
    except IndexError:
        return None, None, None, None

    if domain in SMTP_PROVIDERS:
        server, port, ssl = SMTP_PROVIDERS[domain]
        label = PROVIDER_LABELS.get(domain, domain)
        return label, server, port, ssl

    # Essai générique : mail.domain.tld port 587
    return f"Personnalisé ({domain})", f"smtp.{domain}", 587, False


class EmailService:
    """Service email avec auto-détection SMTP."""

    def __init__(self):
        self._load_config()

    def _load_config(self):
        self.smtp_server   = db.get_setting("smtp_server",    "")
        self.smtp_port     = int(db.get_setting("smtp_port",  "587"))
        self.smtp_username = db.get_setting("smtp_username",  "")
        self.smtp_password = db.get_setting("smtp_password",  "")
        self.smtp_use_ssl  = db.get_setting("smtp_use_ssl",   "false") == "true"
        self.from_name     = db.get_setting("smtp_from_name", "SENTRISCOPE")
        self.from_email    = db.get_setting("smtp_from_email","")

    def reload_config(self):
        self._load_config()

    def is_configured(self) -> bool:
        return bool(self.smtp_server and self.smtp_username and self.smtp_password)

    def save_simple(self, email: str, password: str) -> str:
        """
        Config simplifiée : email + mot de passe.
        Auto-détecte le fournisseur. Retourne le label du fournisseur.
        """
        label, server, port, use_ssl = detect_provider(email)
        server  = server  or "smtp." + email.split("@")[-1]
        port    = port    or 587
        use_ssl = use_ssl or False

        db.set_setting("smtp_server",   server)
        db.set_setting("smtp_port",     str(port))
        db.set_setting("smtp_username", email)
        db.set_setting("smtp_password", password)
        db.set_setting("smtp_use_ssl",  "true" if use_ssl else "false")
        db.set_setting("smtp_from_name","SENTRISCOPE")
        db.set_setting("smtp_from_email", email)
        self._load_config()
        return label or "Inconnu"

    def save_config(self, server, port, username, password, use_ssl, from_name, from_email):
        db.set_setting("smtp_server",   server)
        db.set_setting("smtp_port",     str(port))
        db.set_setting("smtp_username", username)
        db.set_setting("smtp_password", password)
        db.set_setting("smtp_use_ssl",  "true" if use_ssl else "false")
        db.set_setting("smtp_from_name", from_name)
        db.set_setting("smtp_from_email", from_email or username)
        self._load_config()

    def test_connection(self) -> Tuple[bool, str]:
        if not self.is_configured():
            return False, "Email non configuré"
        try:
            ctx = ssl.create_default_context()
            if self.smtp_use_ssl:
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=ctx, timeout=10) as s:
                    s.login(self.smtp_username, self.smtp_password)
            else:
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as s:
                    s.starttls(context=ctx)
                    s.login(self.smtp_username, self.smtp_password)
            return True, f"Connexion réussie vers {self.smtp_server}"
        except smtplib.SMTPAuthenticationError:
            return False, "Authentification refusée — vérifiez email / mot de passe d'application"
        except smtplib.SMTPException as e:
            return False, f"Erreur SMTP : {e}"
        except Exception as e:
            return False, f"Erreur : {e}"

    def send_email(self, to: str, subject: str, body_text: str,
                   body_html: str = None, attachments: List[str] = None) -> Tuple[bool, str]:
        if not self.is_configured():
            return False, "Email non configuré — allez dans Paramètres"
        try:
            msg = MIMEMultipart("alternative")
            msg["From"]    = f"{self.from_name} <{self.from_email or self.smtp_username}>"
            msg["To"]      = to
            msg["Subject"] = subject
            msg.attach(MIMEText(body_text, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))
            if attachments:
                for fp in attachments:
                    self._attach(msg, fp)
            ctx = ssl.create_default_context()
            if self.smtp_use_ssl:
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=ctx) as s:
                    s.login(self.smtp_username, self.smtp_password)
                    s.sendmail(self.from_email or self.smtp_username, [to], msg.as_string())
            else:
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as s:
                    s.starttls(context=ctx)
                    s.login(self.smtp_username, self.smtp_password)
                    s.sendmail(self.from_email or self.smtp_username, [to], msg.as_string())
            return True, f"Email envoyé à {to}"
        except smtplib.SMTPAuthenticationError:
            return False, "Authentification refusée"
        except smtplib.SMTPRecipientsRefused:
            return False, "Adresse email invalide"
        except Exception as e:
            return False, f"Erreur : {e}"

    def _attach(self, msg, filepath: str):
        p = Path(filepath)
        if not p.exists():
            return
        with open(p, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{p.name}"')
        msg.attach(part)

    def send_report(self, to: str, report_path: str, title: str = None) -> Tuple[bool, str]:
        title    = title or "Rapport d'Audit de Sécurité"
        date_str = datetime.now().strftime("%d/%m/%Y à %H:%M")
        subject  = f"[SENTRISCOPE] {title} — {datetime.now().strftime('%d/%m/%Y')}"
        txt = f"Bonjour,\n\nVeuillez trouver ci-joint le rapport d'audit de sécurité.\n\nCordialement,\n{self.from_name}"
        html = f"""<!DOCTYPE html><html><body style="font-family:sans-serif;color:#1f2937;max-width:600px;margin:auto">
<div style="background:linear-gradient(135deg,#10b981,#059669);padding:28px;border-radius:12px 12px 0 0">
  <h2 style="margin:0;color:#fff">🛡️ {title}</h2>
  <p style="margin:8px 0 0;color:rgba(255,255,255,.8);font-size:13px">{date_str}</p>
</div>
<div style="background:#f9fafb;padding:28px">
  <p>Bonjour,</p>
  <p>Veuillez trouver ci-joint le rapport d'audit de sécurité SENTRISCOPE.</p>
  <ul>
    <li>📊 Analyse des hôtes du réseau</li>
    <li>🔌 Ports ouverts et services</li>
    <li>⚠️ Vulnérabilités identifiées</li>
    <li>💡 Recommandations de sécurité</li>
  </ul>
  <p>Cordialement,<br><strong>{self.from_name}</strong></p>
</div>
<div style="background:#e5e7eb;padding:14px;border-radius:0 0 12px 12px;font-size:11px;color:#6b7280;text-align:center">
  Généré par SENTRISCOPE Security Audit Platform
</div>
</body></html>"""
        return self.send_email(to, subject, txt, html, [report_path] if report_path else None)


email_service = EmailService()
