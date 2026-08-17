"""SENTRISCOPE — CompliancePage (v2.8 — rafraîchissement dynamique + UI améliorée)"""
import customtkinter as ctk

from modules.compliance import (
    ComplianceFramework, ComplianceControl,
    ComplianceStatus, MaturityLevel, compliance_manager, CROSS_MAP,
)
from widgets.base import BasePage, get_theme


_STATUS_ICONS = {
    ComplianceStatus.COMPLIANT:      "✅",
    ComplianceStatus.PARTIAL:        "⚠️",
    ComplianceStatus.NON_COMPLIANT:  "❌",
    ComplianceStatus.NOT_EVALUATED:  "⏳",
    ComplianceStatus.NOT_APPLICABLE: "➖",
}

_STATUS_COLORS = {
    ComplianceStatus.COMPLIANT:      "#22c55e",
    ComplianceStatus.PARTIAL:        "#f97316",
    ComplianceStatus.NON_COMPLIANT:  "#ef4444",
    ComplianceStatus.NOT_EVALUATED:  "#6b7280",
    ComplianceStatus.NOT_APPLICABLE: "#475569",
}

_MATURITY_COLORS = {
    MaturityLevel.NOT_ASSESSED: "#6b7280",
    MaturityLevel.INITIAL:      "#ef4444",
    MaturityLevel.MANAGED:      "#f97316",
    MaturityLevel.DEFINED:      "#eab308",
    MaturityLevel.MEASURED:     "#22c55e",
    MaturityLevel.OPTIMIZED:    "#3b82f6",
}


class CompliancePage(BasePage):
    """Page conformité — ISO 27001, RGPD, CIS Controls, NIS2 + Maturité CMMI + Mapping croisé"""

    def setup_ui(self):
        theme = get_theme()
        self._fw_overview_widgets: dict = {}
        self._fw_header_widgets: dict = {}

        # ── Header ──────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(0, 16))

        left_hdr = ctk.CTkFrame(header, fg_color="transparent")
        left_hdr.pack(side="left")
        ctk.CTkLabel(left_hdr, text="Conformité",
                     font=("Segoe UI", 28, "bold")).pack(side="left")
        ctk.CTkLabel(left_hdr, text="  ISO 27001 · RGPD · CIS Controls · NIS2",
                     font=("Segoe UI", 13),
                     text_color=theme.text_secondary).pack(side="left", pady=(6, 0))

        right_hdr = ctk.CTkFrame(header, fg_color="transparent")
        right_hdr.pack(side="right")

        ctk.CTkButton(
            right_hdr, text="🔄 Actualiser", height=34, width=120,
            font=("Segoe UI", 12),
            fg_color=theme.bg_card, hover_color=theme.bg_secondary,
            command=self._refresh_all
        ).pack(side="left", padx=(0, 10))

        badge = ctk.CTkFrame(right_hdr, fg_color=theme.bg_card, corner_radius=12)
        badge.pack(side="left")
        badge_inner = ctk.CTkFrame(badge, fg_color="transparent")
        badge_inner.pack(padx=20, pady=10)

        gs = compliance_manager.get_global_score()
        sc = self._score_color(gs, theme)
        self.global_score_label = ctk.CTkLabel(
            badge_inner, text=f"{gs:.0f}%",
            font=("Segoe UI", 24, "bold"), text_color=sc)
        self.global_score_label.pack(side="left")
        ctk.CTkLabel(badge_inner, text="  Score",
                     font=("Segoe UI", 12), text_color=theme.text_secondary).pack(side="left")

        ctk.CTkFrame(badge_inner, fg_color=theme.border, width=1, height=28).pack(
            side="left", padx=12, fill="y")

        mat = compliance_manager.get_global_maturity()
        mc = self._maturity_color(mat)
        self.global_maturity_label = ctk.CTkLabel(
            badge_inner, text=f"{mat:.1f}/5",
            font=("Segoe UI", 24, "bold"), text_color=mc)
        self.global_maturity_label.pack(side="left")
        ctk.CTkLabel(badge_inner, text="  Maturité",
                     font=("Segoe UI", 12), text_color=theme.text_secondary).pack(side="left")

        # ── Tabview ─────────────────────────────────────────────────────────────
        self.tabview = ctk.CTkTabview(self, fg_color=theme.bg_card, corner_radius=16)
        self.tabview.pack(fill="both", expand=True)

        overview_tab = self.tabview.add("📊 Vue d'ensemble")
        self.create_overview_tab(overview_tab)

        frameworks = compliance_manager.get_all_frameworks()
        self.framework_tabs: dict = {}
        for fw in frameworks:
            tab = self.tabview.add(fw.name)
            self.framework_tabs[fw.id] = {'tab': tab, 'framework': fw, 'loaded': False}

        mapping_tab = self.tabview.add("🔗 Mapping croisé")
        self.framework_tabs['_mapping'] = {'tab': mapping_tab, 'loaded': False}

        self.tabview.set("📊 Vue d'ensemble")
        self.tabview.configure(command=self._on_tab_change)

    # ── Lazy loading ─────────────────────────────────────────────────────────────

    def _on_tab_change(self):
        current = self.tabview.get()
        if current == "🔗 Mapping croisé":
            data = self.framework_tabs.get('_mapping')
            if data and not data['loaded']:
                self.create_mapping_tab(data['tab'])
                data['loaded'] = True
            return
        for fw_id, data in self.framework_tabs.items():
            if fw_id == '_mapping':
                continue
            if data['framework'].name == current and not data['loaded']:
                self.create_framework_tab(data['tab'], data['framework'])
                data['loaded'] = True
                break

    # ── Rafraîchissement ─────────────────────────────────────────────────────────

    def _refresh_all(self):
        """Rafraîchit toutes les données affichées sans reconstruire l'UI."""
        self._update_global_badge()
        self.update_overview_tab()
        self._update_fw_headers()

    def _update_global_badge(self):
        theme = get_theme()
        score = compliance_manager.get_global_score()
        self.global_score_label.configure(
            text=f"{score:.0f}%",
            text_color=self._score_color(score, theme))
        mat = compliance_manager.get_global_maturity()
        self.global_maturity_label.configure(
            text=f"{mat:.1f}/5",
            text_color=self._maturity_color(mat))

    def update_global_score(self):
        """Alias conservé pour compatibilité avec le dashboard."""
        self._update_global_badge()

    def update_overview_tab(self):
        """Met à jour les cartes de la vue d'ensemble sans les recréer."""
        theme = get_theme()
        for fw in compliance_manager.get_all_frameworks():
            w = self._fw_overview_widgets.get(fw.id)
            if not w:
                continue
            score = fw.compliance_score
            sc = self._score_color(score, theme)
            mat = fw.avg_maturity
            mc = self._maturity_color(mat)
            try:
                w['score_lbl'].configure(text=f"{score:.0f}%", text_color=sc)
                w['score_bar'].configure(progress_color=sc)
                w['score_bar'].set(score / 100)
                w['mat_lbl'].configure(text=f"Maturité {mat:.1f}/5", text_color=mc)
                w['mat_bar'].configure(progress_color=mc)
                w['mat_bar'].set(mat / 5.0)
                w['compliant_lbl'].configure(text=f"✅ {fw.compliant_count}")
                w['partial_lbl'].configure(text=f"⚠️ {fw.partial_count}")
                w['non_compliant_lbl'].configure(text=f"❌ {fw.non_compliant_count}")
                w['not_evaluated_lbl'].configure(text=f"⏳ {fw.not_evaluated_count}")
            except Exception:
                pass

    def _update_fw_headers(self):
        """Met à jour les en-têtes des onglets framework déjà chargés."""
        theme = get_theme()
        for fw_id, hw in self._fw_header_widgets.items():
            fw = compliance_manager.get_framework(fw_id)
            if not fw:
                continue
            score = fw.compliance_score
            mat = fw.avg_maturity
            try:
                hw['score_lbl'].configure(
                    text=f"Score: {score:.0f}%",
                    text_color=self._score_color(score, theme))
                hw['mat_lbl'].configure(
                    text=f"Maturité: {mat:.1f}/5",
                    text_color=self._maturity_color(mat))
            except Exception:
                pass

    def on_show(self):
        self._refresh_all()

    # ── Vue d'ensemble ───────────────────────────────────────────────────────────

    def create_overview_tab(self, parent):
        theme = get_theme()
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=10, pady=10)
        scroll.grid_columnconfigure((0, 1), weight=1)

        for i, fw in enumerate(compliance_manager.get_all_frameworks()):
            card = ctk.CTkFrame(scroll, fg_color=theme.bg_secondary, corner_radius=12)
            card.grid(row=i // 2, column=i % 2, padx=10, pady=10, sticky="nsew")

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=20, pady=20)

            ctk.CTkLabel(inner, text=fw.name,
                         font=("Segoe UI", 18, "bold")).pack(anchor="w")
            ctk.CTkLabel(inner, text=fw.description,
                         font=("Segoe UI", 11),
                         text_color=theme.text_secondary).pack(anchor="w", pady=(2, 12))

            score = fw.compliance_score
            sc = self._score_color(score, theme)
            mat = fw.avg_maturity
            mc = self._maturity_color(mat)

            # Ligne score + maturité
            metrics = ctk.CTkFrame(inner, fg_color="transparent")
            metrics.pack(fill="x", pady=(0, 8))

            score_lbl = ctk.CTkLabel(metrics, text=f"{score:.0f}%",
                                     font=("Segoe UI", 32, "bold"), text_color=sc)
            score_lbl.pack(side="left")

            mat_box = ctk.CTkFrame(metrics, fg_color="transparent")
            mat_box.pack(side="left", padx=(20, 0))

            mat_lbl = ctk.CTkLabel(mat_box, text=f"Maturité {mat:.1f}/5",
                                   font=("Segoe UI", 11, "bold"), text_color=mc)
            mat_lbl.pack(anchor="w")
            mat_bar = ctk.CTkProgressBar(mat_box, height=6, corner_radius=3,
                                         progress_color=mc, fg_color=theme.bg_card, width=100)
            mat_bar.pack(anchor="w", pady=(2, 0))
            mat_bar.set(mat / 5.0)

            score_bar = ctk.CTkProgressBar(metrics, height=10, corner_radius=5,
                                           progress_color=sc, fg_color=theme.bg_card)
            score_bar.pack(side="right", fill="x", expand=True, padx=(20, 0))
            score_bar.set(score / 100)

            # Séparateur
            ctk.CTkFrame(inner, fg_color=theme.border, height=1).pack(fill="x", pady=(4, 8))

            # Compteurs statut
            stats_frame = ctk.CTkFrame(inner, fg_color="transparent")
            stats_frame.pack(fill="x")

            stat_defs = [
                ("compliant_lbl",     f"✅ {fw.compliant_count}",     "Conformes",     theme.success),
                ("partial_lbl",       f"⚠️ {fw.partial_count}",       "Partiels",      theme.warning),
                ("non_compliant_lbl", f"❌ {fw.non_compliant_count}", "Non conformes", theme.danger),
                ("not_evaluated_lbl", f"⏳ {fw.not_evaluated_count}", "À évaluer",     theme.text_muted),
            ]
            stat_refs = {}
            for ref_key, value, sub, color in stat_defs:
                col = ctk.CTkFrame(stats_frame, fg_color="transparent")
                col.pack(side="left", padx=(0, 14))
                lbl = ctk.CTkLabel(col, text=value, font=("Segoe UI", 12), text_color=color)
                lbl.pack(anchor="w")
                ctk.CTkLabel(col, text=sub, font=("Segoe UI", 10),
                             text_color=theme.text_muted).pack(anchor="w")
                stat_refs[ref_key] = lbl

            self._fw_overview_widgets[fw.id] = {
                'score_lbl': score_lbl, 'score_bar': score_bar,
                'mat_lbl':   mat_lbl,   'mat_bar':   mat_bar,
                **stat_refs,
            }

    # ── Onglet framework ─────────────────────────────────────────────────────────

    def create_framework_tab(self, parent, framework: ComplianceFramework):
        theme = get_theme()

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=10, pady=(10, 6))

        ctk.CTkLabel(hdr, text=framework.description,
                     font=("Segoe UI", 12),
                     text_color=theme.text_secondary).pack(side="left")

        score = framework.compliance_score
        mat = framework.avg_maturity

        score_lbl = ctk.CTkLabel(hdr, text=f"Score: {score:.0f}%",
                                 font=("Segoe UI", 14, "bold"),
                                 text_color=self._score_color(score, theme))
        score_lbl.pack(side="right")

        mat_lbl = ctk.CTkLabel(hdr, text=f"Maturité: {mat:.1f}/5",
                               font=("Segoe UI", 12, "bold"),
                               text_color=self._maturity_color(mat))
        mat_lbl.pack(side="right", padx=(0, 16))

        self._fw_header_widgets[framework.id] = {
            'score_lbl': score_lbl,
            'mat_lbl':   mat_lbl,
        }

        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        for category, controls in framework.get_controls_by_category().items():
            cat_frame = ctk.CTkFrame(scroll, fg_color=theme.bg_secondary, corner_radius=10)
            cat_frame.pack(fill="x", pady=5)

            cat_hdr = ctk.CTkFrame(cat_frame, fg_color="transparent")
            cat_hdr.pack(fill="x", padx=15, pady=(10, 6))
            ctk.CTkLabel(cat_hdr, text=f"📁 {category}",
                         font=("Segoe UI", 14, "bold")).pack(side="left")
            compliant = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
            ctk.CTkLabel(cat_hdr, text=f"{compliant}/{len(controls)}",
                         font=("Segoe UI", 11),
                         text_color=theme.success if compliant == len(controls) else theme.text_secondary
                         ).pack(side="right")

            controls_frame = ctk.CTkFrame(cat_frame, fg_color="transparent")
            controls_frame.pack(fill="x", padx=10, pady=(0, 10))
            for control in controls:
                self.create_control_row(controls_frame, framework.id, control)

    def create_control_row(self, parent, framework_id: str, control: ComplianceControl):
        """Ligne de contrôle avec barre colorée, statut, maturité et date de vérification."""
        theme = get_theme()
        status_color = _STATUS_COLORS.get(control.status, "#6b7280")

        row = ctk.CTkFrame(parent, fg_color=theme.bg_card, corner_radius=8)
        row.pack(fill="x", pady=2)

        # Barre colorée latérale (couleur = statut)
        ctk.CTkFrame(row, fg_color=status_color, width=3, corner_radius=0).pack(
            side="left", fill="y")

        inner = ctk.CTkFrame(row, fg_color="transparent")
        inner.pack(fill="x", padx=10, pady=8, expand=True)

        # Partie gauche : icône + titre
        info = ctk.CTkFrame(inner, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True)

        title_row = ctk.CTkFrame(info, fg_color="transparent")
        title_row.pack(fill="x")

        icon_label = ctk.CTkLabel(title_row,
                                   text=_STATUS_ICONS.get(control.status, "⏳"),
                                   font=("Segoe UI", 13))
        icon_label.pack(side="left", padx=(0, 6))

        ctk.CTkLabel(title_row, text=control.id,
                     font=("Segoe UI", 10, "bold"),
                     text_color=theme.text_muted).pack(side="left")
        ctk.CTkLabel(title_row, text=f"  {control.title}",
                     font=("Segoe UI", 11)).pack(side="left")

        mapped = CROSS_MAP.get(control.id, [])
        if mapped:
            ctk.CTkLabel(title_row, text=f"  🔗 {len(mapped)}",
                         font=("Segoe UI", 9),
                         text_color=theme.accent).pack(side="left")

        if control.last_checked:
            ctk.CTkLabel(info, text=f"Vérifié : {control.last_checked}",
                         font=("Segoe UI", 9),
                         text_color=theme.text_muted).pack(anchor="w")

        # Partie droite : sélecteurs
        menus = ctk.CTkFrame(inner, fg_color="transparent")
        menus.pack(side="right")

        # Sélecteur statut
        status_var = ctk.StringVar(value=control.status.value)

        def on_status_change(new_val):
            status_map = {s.value: s for s in ComplianceStatus}
            new_enum = status_map.get(new_val, ComplianceStatus.NOT_EVALUATED)
            compliance_manager.update_control(
                framework_id, control.id, status=new_enum,
                checked_by=self.app.current_user.username)
            icon_label.configure(text=_STATUS_ICONS.get(new_enum, "⏳"))
            self._refresh_all()

        ctk.CTkOptionMenu(
            menus, values=[s.value for s in ComplianceStatus],
            variable=status_var, width=120, height=26,
            font=("Segoe UI", 9),
            command=on_status_change
        ).pack(side="left", padx=(0, 4))

        # Sélecteur maturité
        maturity_var = ctk.StringVar(value=control.maturity.label)

        def on_maturity_change(new_label):
            mat_map = {m.label: m for m in MaturityLevel}
            new_mat = mat_map.get(new_label, MaturityLevel.NOT_ASSESSED)
            compliance_manager.update_control(
                framework_id, control.id, maturity=new_mat,
                checked_by=self.app.current_user.username)
            mat_menu.configure(button_color=_MATURITY_COLORS.get(new_mat, "#6b7280"))
            self._refresh_all()

        mat_menu = ctk.CTkOptionMenu(
            menus, values=[m.label for m in MaturityLevel],
            variable=maturity_var, width=100, height=26,
            font=("Segoe UI", 9),
            button_color=_MATURITY_COLORS.get(control.maturity, "#6b7280"),
            command=on_maturity_change)
        mat_menu.pack(side="left")

    # ── Onglet Mapping croisé ────────────────────────────────────────────────────

    def create_mapping_tab(self, parent):
        theme = get_theme()

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(hdr, text="Correspondances entre référentiels",
                     font=("Segoe UI", 14, "bold")).pack(side="left")
        ctk.CTkLabel(hdr,
                     text="  Valider un contrôle peut impacter les frameworks liés",
                     font=("Segoe UI", 11),
                     text_color=theme.text_secondary).pack(side="left")

        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        from modules.compliance import _RAW_MAPPINGS
        seen: set = set()
        for group in _RAW_MAPPINGS:
            key = tuple(sorted(group))
            if key not in seen:
                seen.add(key)
                self._create_mapping_group(scroll, group, theme)

    def _create_mapping_group(self, parent, group, theme):
        card = ctk.CTkFrame(parent, fg_color=theme.bg_secondary, corner_radius=10)
        card.pack(fill="x", pady=4)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=12)

        for i, cid in enumerate(group):
            ctrl, fw_name = self._find_control(cid)
            if not ctrl:
                continue
            if i > 0:
                ctk.CTkLabel(inner, text="↔", font=("Segoe UI", 12),
                             text_color=theme.accent).pack(side="left", padx=4)

            chip = ctk.CTkFrame(inner, fg_color=theme.bg_card, corner_radius=8)
            chip.pack(side="left", padx=2)
            chip_inner = ctk.CTkFrame(chip, fg_color="transparent")
            chip_inner.pack(padx=10, pady=6)

            ctk.CTkLabel(chip_inner, text=fw_name,
                         font=("Segoe UI", 8),
                         text_color=theme.text_muted).pack(anchor="w")

            r = ctk.CTkFrame(chip_inner, fg_color="transparent")
            r.pack(anchor="w")
            ctk.CTkLabel(r, text=f"{_STATUS_ICONS.get(ctrl.status, '⏳')} {cid}",
                         font=("Segoe UI", 11, "bold")).pack(side="left")
            ctk.CTkLabel(r, text=f" {ctrl.maturity.icon}",
                         font=("Segoe UI", 10)).pack(side="left")

            ctk.CTkLabel(chip_inner, text=ctrl.title,
                         font=("Segoe UI", 9),
                         text_color=theme.text_secondary).pack(anchor="w")

    def _find_control(self, control_id: str):
        for fw in compliance_manager.get_all_frameworks():
            for ctrl in fw.controls:
                if ctrl.id == control_id:
                    return ctrl, fw.name
        return None, None

    # ── Helpers couleurs ─────────────────────────────────────────────────────────

    @staticmethod
    def _score_color(score: float, theme) -> str:
        if score >= 70:
            return theme.success
        if score >= 40:
            return theme.warning
        return theme.danger

    @staticmethod
    def _maturity_color(level: float) -> str:
        if level >= 4.0: return "#3b82f6"
        if level >= 3.0: return "#22c55e"
        if level >= 2.0: return "#eab308"
        if level >= 1.0: return "#f97316"
        return "#6b7280"
