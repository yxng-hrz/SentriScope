"""
SENTRISCOPE — PasswordPolicyPage
Audit de la politique de mots de passe locale
"""

import threading
import customtkinter as ctk

from modules.password_policy import PasswordPolicyChecker, PolicyReport, PolicyCheck, PolicyLevel
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard


# ─── Couleurs sémantiques ─────────────────────────────────────────────────────

def _level_color(status: str, theme) -> str:
    return {
        PolicyLevel.GOOD:    theme.success,
        PolicyLevel.WARNING: theme.warning,
        PolicyLevel.DANGER:  theme.danger,
        PolicyLevel.INFO:    theme.info,
    }.get(status, theme.text_secondary)


def _level_icon(status: str) -> str:
    return {
        PolicyLevel.GOOD:    "✅",
        PolicyLevel.WARNING: "⚠️",
        PolicyLevel.DANGER:  "❌",
        PolicyLevel.INFO:    "ℹ️",
    }.get(status, "❓")


def _score_color(score: int, theme) -> str:
    if score >= 80: return theme.success
    if score >= 55: return theme.warning
    return theme.danger


def _score_label(score: int) -> str:
    if score >= 80: return "Bonne politique"
    if score >= 55: return "Améliorations requises"
    return "Politique insuffisante"


# ─── Page principale ──────────────────────────────────────────────────────────

class PasswordPolicyPage(BasePage):
    """Audit de la politique de mots de passe système."""

    def setup_ui(self):
        self._report: PolicyReport | None = None
        self._scanning = False
        theme = get_theme()

        # ── Header ──────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))

        left_hdr = ctk.CTkFrame(header, fg_color="transparent")
        left_hdr.pack(side="left")

        ctk.CTkLabel(left_hdr, text="Password Policy",
                     font=("Segoe UI", 28, "bold")).pack(anchor="w")
        ctk.CTkLabel(left_hdr,
                     text="Audit de la politique de mots de passe locale",
                     font=("Segoe UI", 13),
                     text_color=theme.text_secondary).pack(anchor="w")

        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")

        self._scan_btn = ctk.CTkButton(
            btn_frame, text="🔍  Analyser",
            font=("Segoe UI", 13, "bold"), height=40,
            fg_color=theme.accent,
            command=self._start_scan
        )
        self._scan_btn.pack(side="left")

        # ── Résumé score (4 stats cards) ────────────────────────────
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 16))
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._card_score   = StatsCard(stats_frame, "Score global",  "—",  theme.accent,  "🛡️")
        self._card_good    = StatsCard(stats_frame, "Conformes",     "—",  theme.success, "✅")
        self._card_warn    = StatsCard(stats_frame, "Avertissements","—",  theme.warning, "⚠️")
        self._card_danger  = StatsCard(stats_frame, "Critiques",     "—",  theme.danger,  "❌")

        for i, card in enumerate([self._card_score, self._card_good,
                                   self._card_warn, self._card_danger]):
            card.grid(row=0, column=i, padx=4, sticky="nsew")

        # ── Barre de score + état ────────────────────────────────────
        score_banner = ctk.CTkFrame(self, fg_color=theme.bg_card, corner_radius=14)
        score_banner.pack(fill="x", pady=(0, 16))

        banner_inner = ctk.CTkFrame(score_banner, fg_color="transparent")
        banner_inner.pack(fill="x", padx=24, pady=16)

        # Ligne gauche : score chiffré + label
        left_b = ctk.CTkFrame(banner_inner, fg_color="transparent")
        left_b.pack(side="left")

        self._score_num_lbl = ctk.CTkLabel(
            left_b, text="—",
            font=("Segoe UI", 44, "bold"),
            text_color=theme.text_muted
        )
        self._score_num_lbl.pack(side="left")

        ctk.CTkLabel(left_b, text=" / 100",
                     font=("Segoe UI", 20),
                     text_color=theme.text_muted).pack(side="left", pady=(10, 0))

        self._score_txt_lbl = ctk.CTkLabel(
            left_b, text="  Lancez l'analyse",
            font=("Segoe UI", 14),
            text_color=theme.text_muted
        )
        self._score_txt_lbl.pack(side="left", padx=(16, 0), pady=(10, 0))

        # Barre de progression
        right_b = ctk.CTkFrame(banner_inner, fg_color="transparent")
        right_b.pack(side="right", fill="x", expand=True, padx=(40, 0))

        self._score_bar = ctk.CTkProgressBar(
            right_b, height=14, corner_radius=7,
            progress_color=theme.text_muted,
            fg_color=theme.bg_secondary
        )
        self._score_bar.pack(fill="x", pady=(14, 0))
        self._score_bar.set(0)

        self._os_lbl = ctk.CTkLabel(
            right_b, text="",
            font=("Segoe UI", 10),
            text_color=theme.text_muted
        )
        self._os_lbl.pack(anchor="e", pady=(4, 0))

        # ── Zone de résultats scrollable ─────────────────────────────
        results_section = self.create_section("📋 Contrôles détaillés")
        results_section.pack(fill="both", expand=True)

        self._results_scroll = ctk.CTkScrollableFrame(
            results_section, fg_color="transparent"
        )
        self._results_scroll.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Placeholder initial
        self._show_placeholder()

    # ── Placeholder ───────────────────────────────────────────────────────────

    def _show_placeholder(self):
        theme = get_theme()
        for w in self._results_scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self._results_scroll,
            text="🔍  Cliquez sur Analyser pour auditer la politique de mots de passe de ce système",
            font=("Segoe UI", 13),
            text_color=theme.text_muted
        ).pack(pady=60)

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        theme = get_theme()
        self._scan_btn.configure(text="⏳  Analyse…", state="disabled")

        for w in self._results_scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self._results_scroll,
            text="⏳  Analyse en cours…",
            font=("Segoe UI", 13),
            text_color=theme.text_muted
        ).pack(pady=60)

        def _run():
            checker = PasswordPolicyChecker()
            report = checker.run()
            self.after(0, lambda: self._apply_report(report))

        threading.Thread(target=_run, daemon=True).start()

    def _apply_report(self, report: PolicyReport):
        self._report = report
        self._scanning = False
        theme = get_theme()
        score = report.score

        # Cards
        self._card_score.set_value(f"{score}/100")
        self._card_score.set_color(_score_color(score, theme))
        self._card_good.set_value(str(report.good_count))
        self._card_warn.set_value(str(report.warning_count))
        self._card_danger.set_value(str(report.danger_count))

        # Banner
        color = _score_color(score, theme)
        self._score_num_lbl.configure(text=str(score), text_color=color)
        self._score_txt_lbl.configure(text=f"  {_score_label(score)}", text_color=color)
        self._score_bar.configure(progress_color=color)
        self._score_bar.set(score / 100)
        self._os_lbl.configure(text=f"Système : {report.os_name}  ·  Analysé le {report.scanned_at[:19].replace('T', ' à ')}")

        # Bouton
        self._scan_btn.configure(text="🔄  Ré-analyser", state="normal")

        # Résultats
        self._render_checks(report.checks)

    # ── Rendu des contrôles ───────────────────────────────────────────────────

    def _render_checks(self, checks):
        theme = get_theme()

        for w in self._results_scroll.winfo_children():
            w.destroy()

        if not checks:
            ctk.CTkLabel(self._results_scroll,
                         text="Aucun contrôle disponible.",
                         text_color=theme.text_muted).pack(pady=30)
            return

        # Grouper : danger en premier, puis warning, good, info
        order = {PolicyLevel.DANGER: 0, PolicyLevel.WARNING: 1,
                 PolicyLevel.GOOD: 2, PolicyLevel.INFO: 3}
        sorted_checks = sorted(checks, key=lambda c: order.get(c.status, 9))

        for check in sorted_checks:
            self._render_check_card(check, theme)

    def _render_check_card(self, check: PolicyCheck, theme):
        color  = _level_color(check.status, theme)
        icon   = _level_icon(check.status)
        is_ok  = check.status == PolicyLevel.GOOD

        # Carte principale
        card = ctk.CTkFrame(
            self._results_scroll,
            fg_color=theme.bg_card,
            corner_radius=12
        )
        card.pack(fill="x", pady=5, padx=2)

        # Bande colorée latérale gauche
        accent_bar = ctk.CTkFrame(card, fg_color=color, corner_radius=0, width=4)
        accent_bar.pack(side="left", fill="y")
        accent_bar.pack_propagate(False)

        # Contenu
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=16, pady=14)

        # ── Ligne 1 : icône + titre + badge valeur ───────────────────
        top_row = ctk.CTkFrame(body, fg_color="transparent")
        top_row.pack(fill="x")

        ctk.CTkLabel(top_row, text=icon,
                     font=("Segoe UI Emoji", 16)).pack(side="left")

        ctk.CTkLabel(top_row,
                     text=f"  {check.title}",
                     font=("Segoe UI", 13, "bold")).pack(side="left")

        # Badge valeur détectée
        badge_frame = ctk.CTkFrame(top_row,
                                    fg_color=theme.bg_secondary,
                                    corner_radius=8)
        badge_frame.pack(side="right")
        ctk.CTkLabel(badge_frame,
                     text=check.value,
                     font=("Segoe UI", 11),
                     text_color=color).pack(padx=10, pady=3)

        # ── Ligne 2 : description ────────────────────────────────────
        ctk.CTkLabel(body,
                     text=check.description,
                     font=("Segoe UI", 11),
                     text_color=theme.text_secondary,
                     anchor="w", justify="left",
                     wraplength=800).pack(fill="x", pady=(6, 0))

        # ── Ligne 3 : recommandation (masquée si tout est ok) ────────
        if not is_ok:
            rec_frame = ctk.CTkFrame(body,
                                      fg_color=theme.bg_secondary,
                                      corner_radius=8)
            rec_frame.pack(fill="x", pady=(10, 0))
            ctk.CTkLabel(rec_frame,
                         text=f"💡  {check.recommendation}",
                         font=("Segoe UI", 11),
                         text_color=theme.text_muted,
                         anchor="w", justify="left",
                         wraplength=790).pack(fill="x", padx=12, pady=8)

        # ── Impact sur le score ──────────────────────────────────────
        if check.score_impact > 0:
            ctk.CTkLabel(body,
                         text=f"Impact sur le score : -{check.score_impact} pts",
                         font=("Segoe UI", 10),
                         text_color=theme.danger).pack(anchor="e", pady=(6, 0))

    def on_show(self):
        # Relancer une analyse si on revient sur la page et qu'on n'en a pas encore
        if self._report is None and not self._scanning:
            self._start_scan()
