"""SENTRISCOPE — SettingsPage"""
import threading
import customtkinter as ctk
from modules.database import db
from modules.email_service import email_service, detect_provider, PROVIDER_HINTS
from widgets.base import BasePage, get_theme


def _label(parent, text, bold=False, muted=False, pady=(0, 4)):
    theme = get_theme()
    ctk.CTkLabel(
        parent, text=text,
        font=("Segoe UI", 12, "bold" if bold else "normal"),
        text_color=theme.text_muted if muted else theme.text_primary,
        anchor="w"
    ).pack(anchor="w", pady=pady)


class SettingsPage(BasePage):

    def setup_ui(self):
        theme = get_theme()
        self.page_header("Paramètres", "Configuration de l'application")

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # ────────────────────────────────────────────────────────────
        # 1. EMAIL
        # ────────────────────────────────────────────────────────────
        email_sec = self.create_section("📧 Notifications par email", scroll)
        email_sec.pack(fill="x", pady=(0, 14))

        ef = ctk.CTkFrame(email_sec, fg_color="transparent")
        ef.pack(fill="x", padx=20, pady=(0, 20))

        ctk.CTkLabel(
            ef,
            text="Entrez votre adresse email et votre mot de passe d'application.\n"
                 "SENTRISCOPE détecte automatiquement votre fournisseur (Gmail, Outlook, Yahoo…).",
            font=("Segoe UI", 11),
            text_color=theme.text_muted,
            justify="left", anchor="w"
        ).pack(fill="x", pady=(0, 16))

        # — Email —
        _label(ef, "Adresse email", bold=True)
        email_row = ctk.CTkFrame(ef, fg_color="transparent")
        email_row.pack(fill="x", pady=(0, 4))

        self._email_entry = ctk.CTkEntry(
            email_row, height=42, font=("Segoe UI", 13),
            placeholder_text="vous@gmail.com", corner_radius=10
        )
        self._email_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._email_entry.bind("<KeyRelease>", self._on_email_change)

        self._provider_badge = ctk.CTkLabel(
            email_row, text="", font=("Segoe UI", 11),
            fg_color="transparent", text_color=theme.text_muted,
            width=150, anchor="w"
        )
        self._provider_badge.pack(side="left")

        # — Hint contextuel —
        self._hint_frame = ctk.CTkFrame(ef, fg_color=theme.bg_secondary, corner_radius=8)
        self._hint_lbl = ctk.CTkLabel(
            self._hint_frame, text="",
            font=("Segoe UI", 11), text_color=theme.text_muted,
            justify="left", anchor="w", wraplength=700
        )
        self._hint_lbl.pack(fill="x", padx=12, pady=10)
        # hint_frame affiché dynamiquement

        # — Mot de passe —
        _label(ef, "Mot de passe d'application", bold=True, pady=(12, 4))
        pwd_row = ctk.CTkFrame(ef, fg_color="transparent")
        pwd_row.pack(fill="x")

        self._pwd_entry = ctk.CTkEntry(
            pwd_row, height=42, font=("Segoe UI", 13),
            show="•", placeholder_text="Mot de passe ou app password", corner_radius=10
        )
        self._pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self._show_pwd = ctk.CTkSwitch(pwd_row, text="Afficher",
                                        font=("Segoe UI", 11),
                                        command=self._toggle_pwd)
        self._show_pwd.pack(side="left")

        # — Boutons —
        btn_row = ctk.CTkFrame(ef, fg_color="transparent")
        btn_row.pack(fill="x", pady=(18, 0))

        self._save_btn = ctk.CTkButton(
            btn_row, text="💾  Enregistrer",
            font=("Segoe UI", 13, "bold"), height=42, corner_radius=10,
            fg_color=theme.accent, command=self._save
        )
        self._save_btn.pack(side="left", padx=(0, 10))

        self._test_btn = ctk.CTkButton(
            btn_row, text="📨  Envoyer un email test",
            font=("Segoe UI", 13), height=42, corner_radius=10,
            fg_color=theme.bg_secondary, hover_color=theme.bg_hover,
            command=self._send_test
        )
        self._test_btn.pack(side="left")

        self._status = ctk.CTkLabel(ef, text="", font=("Segoe UI", 12),
                                     text_color=theme.text_muted)
        self._status.pack(anchor="w", pady=(12, 0))

        # ────────────────────────────────────────────────────────────
        # 2. CONFIG SMTP AVANCÉE
        # ────────────────────────────────────────────────────────────
        adv_sec = self.create_section("⚙️ Configuration SMTP avancée", scroll)
        adv_sec.pack(fill="x", pady=(0, 14))

        adv_f = ctk.CTkFrame(adv_sec, fg_color="transparent")
        adv_f.pack(fill="x", padx=20, pady=(0, 16))

        ctk.CTkLabel(
            adv_f,
            text="Pour les entreprises avec un serveur SMTP personnalisé.",
            font=("Segoe UI", 11), text_color=theme.text_muted, anchor="w"
        ).pack(anchor="w", pady=(0, 12))

        # Ligne serveur / port / ssl
        adv_row = ctk.CTkFrame(adv_f, fg_color="transparent")
        adv_row.pack(fill="x")

        # Serveur (flex)
        sf = ctk.CTkFrame(adv_row, fg_color="transparent")
        sf.pack(side="left", fill="x", expand=True, padx=(0, 8))
        _label(sf, "Serveur SMTP", muted=True)
        self._adv_server = ctk.CTkEntry(sf, height=38, corner_radius=8,
                                         placeholder_text="smtp.exemple.com")
        self._adv_server.pack(fill="x")

        # Port (fixe 90 px)
        pf = ctk.CTkFrame(adv_row, fg_color="transparent", width=90)
        pf.pack(side="left", padx=4)
        pf.pack_propagate(False)
        _label(pf, "Port", muted=True)
        self._adv_port = ctk.CTkEntry(pf, height=38, corner_radius=8,
                                       placeholder_text="587")
        self._adv_port.pack(fill="x")

        # SSL (fixe 80 px)
        ssl_f = ctk.CTkFrame(adv_row, fg_color="transparent", width=80)
        ssl_f.pack(side="left", padx=(4, 0))
        ssl_f.pack_propagate(False)
        _label(ssl_f, "SSL", muted=True)
        self._adv_ssl = ctk.CTkSwitch(ssl_f, text="")
        self._adv_ssl.pack(anchor="w", pady=(4, 0))

        ctk.CTkButton(
            adv_f, text="💾  Sauvegarder config avancée",
            font=("Segoe UI", 12), height=38, corner_radius=8,
            fg_color=theme.bg_secondary, hover_color=theme.bg_hover,
            command=self._save_advanced
        ).pack(anchor="w", pady=(12, 0))

        # ────────────────────────────────────────────────────────────
        # 3. CHANGER MOT DE PASSE
        # ────────────────────────────────────────────────────────────
        acc_sec = self.create_section("👤 Compte", scroll)
        acc_sec.pack(fill="x", pady=(0, 14))

        af = ctk.CTkFrame(acc_sec, fg_color="transparent")
        af.pack(fill="x", padx=20, pady=(0, 16))

        _label(af, "Changer de mot de passe", bold=True, pady=(0, 12))

        pwd3_row = ctk.CTkFrame(af, fg_color="transparent")
        pwd3_row.pack(fill="x")

        for attr, placeholder in [
            ("_old_pwd",     "Mot de passe actuel"),
            ("_new_pwd",     "Nouveau mot de passe"),
            ("_confirm_pwd", "Confirmer"),
        ]:
            col = ctk.CTkFrame(pwd3_row, fg_color="transparent")
            col.pack(side="left", fill="x", expand=True, padx=(0, 8))
            entry = ctk.CTkEntry(col, height=38, show="•",
                                  corner_radius=8, placeholder_text=placeholder)
            entry.pack(fill="x")
            setattr(self, attr, entry)

        foot_row = ctk.CTkFrame(af, fg_color="transparent")
        foot_row.pack(fill="x", pady=(10, 0))

        self._pwd_status = ctk.CTkLabel(foot_row, text="",
                                         font=("Segoe UI", 11),
                                         text_color=theme.text_muted)
        self._pwd_status.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            foot_row, text="Mettre à jour",
            font=("Segoe UI", 12), height=38, corner_radius=8, width=140,
            fg_color=theme.accent, command=self._change_pwd
        ).pack(side="right")

        # Charger
        self._load()

    # ── Chargement ────────────────────────────────────────────────────────────

    def _load(self):
        email = db.get_setting("smtp_username", "")
        pwd   = db.get_setting("smtp_password", "")
        self._email_entry.delete(0, "end")
        self._email_entry.insert(0, email)
        self._pwd_entry.delete(0, "end")
        self._pwd_entry.insert(0, pwd)
        self._adv_server.delete(0, "end")
        self._adv_server.insert(0, db.get_setting("smtp_server", ""))
        self._adv_port.delete(0, "end")
        self._adv_port.insert(0, db.get_setting("smtp_port", "587"))
        if db.get_setting("smtp_use_ssl", "false") == "true":
            self._adv_ssl.select()
        if email:
            self._on_email_change()

    # ── Détection fournisseur ─────────────────────────────────────────────────

    def _on_email_change(self, _=None):
        theme = get_theme()
        email = self._email_entry.get().strip()
        label, server, port, use_ssl = detect_provider(email)

        if label and server:
            self._provider_badge.configure(
                text=f"✓ {label}", text_color=theme.success,
                fg_color=theme.bg_secondary, corner_radius=6
            )
            try:
                domain = email.lower().split("@")[1]
            except IndexError:
                domain = ""
            hint = PROVIDER_HINTS.get(domain, "")
            if hint:
                self._hint_frame.pack(fill="x", pady=(8, 0))
                self._hint_lbl.configure(text=f"ℹ️  {hint}")
            else:
                self._hint_frame.pack_forget()
        else:
            self._provider_badge.configure(text="", fg_color="transparent")
            self._hint_frame.pack_forget()

    # ── Sauvegarde simple ─────────────────────────────────────────────────────

    def _save(self):
        theme = get_theme()
        email = self._email_entry.get().strip()
        pwd   = self._pwd_entry.get()
        if not email:
            return self._set_status("Entrez votre adresse email", theme.warning)
        if "@" not in email:
            return self._set_status("Adresse email invalide", theme.danger)
        if not pwd:
            return self._set_status("Entrez votre mot de passe d'application", theme.warning)

        label = email_service.save_simple(email, pwd)
        self._set_status(f"✅ Configuré — {label}", theme.success)
        self._adv_server.delete(0, "end")
        self._adv_server.insert(0, email_service.smtp_server)
        self._adv_port.delete(0, "end")
        self._adv_port.insert(0, str(email_service.smtp_port))

    # ── Test email ────────────────────────────────────────────────────────────

    def _send_test(self):
        theme = get_theme()
        email = self._email_entry.get().strip()
        pwd   = self._pwd_entry.get()
        if not email or not pwd:
            return self._set_status("Configurez votre email avant de tester", theme.warning)

        email_service.save_simple(email, pwd)
        self._set_status("📨 Test en cours…", theme.text_muted)
        self._test_btn.configure(state="disabled")

        def _run():
            ok, msg = email_service.test_connection()
            if ok:
                ok2, msg2 = email_service.send_email(
                    to=email,
                    subject="✅ SENTRISCOPE — Email de test",
                    body_text="Votre configuration email fonctionne correctement.",
                    body_html="""<html><body style="font-family:sans-serif;max-width:500px;margin:auto">
<div style="background:#10b981;padding:20px;border-radius:10px 10px 0 0">
  <h2 style="margin:0;color:#fff">✅ Email de test SENTRISCOPE</h2>
</div>
<div style="background:#f9fafb;padding:24px">
  <p>Votre configuration email fonctionne correctement !</p>
  <p style="color:#6b7280;font-size:13px">Vous recevrez les alertes et rapports sur cette adresse.</p>
</div></body></html>"""
                )
                result = (ok2, f"Email envoyé à {email}" if ok2 else msg2)
            else:
                result = (False, msg)
            self.after(0, lambda: self._test_done(*result))

        threading.Thread(target=_run, daemon=True).start()

    def _test_done(self, ok: bool, msg: str):
        theme = get_theme()
        self._test_btn.configure(state="normal")
        self._set_status(f"✅ {msg}" if ok else f"❌ {msg}",
                          theme.success if ok else theme.danger)

    # ── Config avancée ────────────────────────────────────────────────────────

    def _save_advanced(self):
        theme = get_theme()
        email = self._email_entry.get().strip()
        pwd   = self._pwd_entry.get()
        try:
            port = int(self._adv_port.get() or 587)
        except ValueError:
            port = 587
        email_service.save_config(
            server=self._adv_server.get().strip(), port=port,
            username=email, password=pwd,
            use_ssl=bool(self._adv_ssl.get()),
            from_name="SENTRISCOPE", from_email=email
        )
        self._set_status("✅ Config avancée sauvegardée", theme.success)

    # ── Changement de mot de passe ────────────────────────────────────────────

    def _change_pwd(self):
        theme   = get_theme()
        old     = self._old_pwd.get()
        new     = self._new_pwd.get()
        confirm = self._confirm_pwd.get()
        if not old or not new:
            self._pwd_status.configure(text="Remplissez tous les champs",
                                        text_color=theme.warning)
            return
        if new != confirm:
            self._pwd_status.configure(text="Les mots de passe ne correspondent pas",
                                        text_color=theme.danger)
            return
        if len(new) < 6:
            self._pwd_status.configure(text="Minimum 6 caractères",
                                        text_color=theme.warning)
            return
        ok = db.change_password(self.app.current_user.id, old, new)
        if ok:
            self._pwd_status.configure(text="✅ Mot de passe mis à jour",
                                        text_color=theme.success)
            for e in [self._old_pwd, self._new_pwd, self._confirm_pwd]:
                e.delete(0, "end")
        else:
            self._pwd_status.configure(text="❌ Mot de passe actuel incorrect",
                                        text_color=theme.danger)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _toggle_pwd(self):
        self._pwd_entry.configure(show="" if self._show_pwd.get() else "•")

    def _set_status(self, msg: str, color: str):
        self._status.configure(text=msg, text_color=color)
