"""SENTRISCOPE — VulnerabilitiesPage"""
import webbrowser
import customtkinter as ctk
from tkinter import messagebox
from modules import ReportGenerator
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard
from widgets.helpers import SEV_ORDER, SEV_COLOR, SEV_ICON, sev_counts, risk_score, risk_color


class VulnerabilitiesPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        self._filter_sev = "Toutes"; self._filter_host = ""; self._fp_set = set()

        btn_frame = self.page_header("Vulnérabilités", "Analyse des risques détectés sur le réseau")
        ctk.CTkButton(btn_frame, text="📥 Export CSV", height=36, font=("Segoe UI", 12),
                      fg_color=t.success, command=self._export_csv).pack(side="left", padx=4)
        ctk.CTkButton(btn_frame, text="🔃 Actualiser", height=36, font=("Segoe UI", 12),
                      fg_color=t.accent, command=self.refresh_vulnerabilities).pack(side="left", padx=4)

        sf = ctk.CTkFrame(self, fg_color="transparent"); sf.pack(fill="x", pady=(0, 12))
        sf.grid_columnconfigure((0,1,2,3,4), weight=1)
        self.stat_total = StatsCard(sf, "Total", "0", t.accent, "🔍")
        self.stat_critical = StatsCard(sf, "Critiques", "0", "#ef4444", "🔴")
        self.stat_high = StatsCard(sf, "Hautes", "0", "#f97316", "🟠")
        self.stat_medium = StatsCard(sf, "Moyennes", "0", t.warning, "🟡")
        self.stat_low = StatsCard(sf, "Basses", "0", t.success, "🟢")
        for i, c in enumerate([self.stat_total, self.stat_critical, self.stat_high, self.stat_medium, self.stat_low]):
            c.grid(row=0, column=i, padx=4, sticky="nsew")

        mid = ctk.CTkFrame(self, fg_color="transparent"); mid.pack(fill="x", pady=(0, 10))
        mid.grid_columnconfigure(0, weight=2); mid.grid_columnconfigure(1, weight=1)

        rc = ctk.CTkFrame(mid, fg_color=t.bg_card, corner_radius=12)
        rc.grid(row=0, column=0, padx=(0, 6), sticky="nsew")
        ri = ctk.CTkFrame(rc, fg_color="transparent"); ri.pack(fill="x", padx=16, pady=14)
        ctk.CTkLabel(ri, text="Score de risque global", font=("Segoe UI", 11), text_color=t.text_muted).pack(anchor="w")
        r2 = ctk.CTkFrame(ri, fg_color="transparent"); r2.pack(fill="x", pady=(6, 8))
        self.risk_label = ctk.CTkLabel(r2, text="0 / 100", font=("Segoe UI", 28, "bold"), text_color=t.success)
        self.risk_label.pack(side="left")
        self._risk_desc = ctk.CTkLabel(r2, text="  Aucun scan effectué", font=("Segoe UI", 12), text_color=t.text_muted)
        self._risk_desc.pack(side="left")
        self.risk_bar = ctk.CTkProgressBar(ri, height=8, corner_radius=4, progress_color=t.success)
        self.risk_bar.pack(fill="x"); self.risk_bar.set(0)

        fc = ctk.CTkFrame(mid, fg_color=t.bg_card, corner_radius=12)
        fc.grid(row=0, column=1, padx=(6, 0), sticky="nsew")
        fi = ctk.CTkFrame(fc, fg_color="transparent"); fi.pack(fill="x", padx=16, pady=14)
        ctk.CTkLabel(fi, text="Filtrer par sévérité", font=("Segoe UI", 11), text_color=t.text_muted).pack(anchor="w")
        self._sev_combo = ctk.CTkComboBox(fi, height=34, state="readonly",
            values=["Toutes","Critiques","Hautes","Moyennes","Basses"], command=self._on_filter_change)
        self._sev_combo.pack(fill="x", pady=(6, 8)); self._sev_combo.set("Toutes")
        ctk.CTkLabel(fi, text="Filtrer par hôte", font=("Segoe UI", 11), text_color=t.text_muted).pack(anchor="w")
        self._host_entry = ctk.CTkEntry(fi, height=34, placeholder_text="192.168.1.x…")
        self._host_entry.pack(fill="x", pady=(6, 0))
        self._host_entry.bind("<Return>", lambda e: self.refresh_vulnerabilities())

        ls = self.create_section("📋 Vulnérabilités détectées"); ls.pack(fill="both", expand=True)
        self.vulns_scroll = ctk.CTkScrollableFrame(ls, fg_color="transparent")
        self.vulns_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.empty_state(self.vulns_scroll, "🔍", "Lancez un scan réseau pour détecter les vulnérabilités")

    def on_show(self): self.refresh_vulnerabilities()
    def _on_filter_change(self, _=None): self.refresh_vulnerabilities()

    def refresh_vulnerabilities(self):
        vulns = self.app.vulnerabilities
        sev_map = {"Critiques":"critical", "Hautes":"high", "Moyennes":"medium", "Basses":"low"}
        sf = sev_map.get(self._sev_combo.get())
        hf = self._host_entry.get().strip().lower()
        filtered = [v for v in vulns if (not sf or v.severity == sf) and (not hf or hf in v.host.lower()) and id(v) not in self._fp_set]

        sc = sev_counts(vulns)
        self.stat_total.set_value(str(sc["total"])); self.stat_critical.set_value(str(sc["critical"]))
        self.stat_high.set_value(str(sc["high"])); self.stat_medium.set_value(str(sc["medium"]))
        self.stat_low.set_value(str(sc["low"]))

        risk = risk_score(vulns); color = risk_color(risk)
        desc = "Risque faible" if risk < 30 else "Risque modéré" if risk < 60 else "Risque élevé"
        self.risk_label.configure(text=f"{risk} / 100", text_color=color)
        self._risk_desc.configure(text=f"  {desc}")
        self.risk_bar.configure(progress_color=color); self.risk_bar.set(risk / 100)

        for w in self.vulns_scroll.winfo_children(): w.destroy()
        if not filtered:
            msg = "✅ Aucune vulnérabilité" if not vulns else "Aucun résultat pour ce filtre"
            self.empty_state(self.vulns_scroll, "✅" if not vulns else "🔍", msg); return
        for vuln in sorted(filtered, key=lambda v: (SEV_ORDER.get(v.severity, 9), -v.cvss)):
            self._vuln_card(vuln)

    def _vuln_card(self, vuln):
        t = get_theme()
        color, icon = SEV_COLOR.get(vuln.severity, t.info), SEV_ICON.get(vuln.severity, "•")
        card = ctk.CTkFrame(self.vulns_scroll, fg_color=t.bg_card, corner_radius=10)
        card.pack(fill="x", pady=4, padx=2)
        ctk.CTkFrame(card, fg_color=color, width=4, corner_radius=0).pack(side="left", fill="y")
        body = ctk.CTkFrame(card, fg_color="transparent"); body.pack(fill="x", padx=14, pady=10)

        top = ctk.CTkFrame(body, fg_color="transparent"); top.pack(fill="x")
        ctk.CTkLabel(top, text=f" {icon} {vuln.severity.upper()} ", font=("Segoe UI", 10, "bold"),
                     fg_color=color, corner_radius=4, text_color="#ffffff").pack(side="left")
        ctk.CTkLabel(top, text=f"  {vuln.name}", font=("Segoe UI", 13, "bold")).pack(side="left")
        cc = "#ef4444" if vuln.cvss >= 9 else "#f97316" if vuln.cvss >= 7 else "#f59e0b" if vuln.cvss >= 4 else "#22c55e"
        ctk.CTkLabel(top, text=f" CVSS {vuln.cvss} ", font=("Segoe UI", 10, "bold"),
                     fg_color=cc, corner_radius=4, text_color="#ffffff").pack(side="left", padx=8)
        ctk.CTkLabel(top, text=f"🖥️ {vuln.host}  🔌 {vuln.port}/{vuln.service}",
                     font=("Segoe UI", 10), text_color=t.text_muted).pack(side="right")

        ctk.CTkLabel(body, text=vuln.description, font=("Segoe UI", 11), text_color=t.text_secondary,
                     anchor="w", justify="left", wraplength=800).pack(fill="x", pady=(6, 0))

        footer = ctk.CTkFrame(body, fg_color="transparent"); footer.pack(fill="x", pady=(8, 0))
        rf = ctk.CTkFrame(footer, fg_color=t.bg_secondary, corner_radius=6)
        rf.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(rf, text=f"💡 {vuln.recommendation}", font=("Segoe UI", 10), text_color=t.text_muted,
                     anchor="w", justify="left", wraplength=700).pack(fill="x", padx=10, pady=6)
        bc = ctk.CTkFrame(footer, fg_color="transparent"); bc.pack(side="right", padx=(8, 0))
        if vuln.cve_list:
            cve = vuln.cve_list[0]
            ctk.CTkButton(bc, text=cve, height=26, width=110, font=("Segoe UI", 10), fg_color=t.info,
                          command=lambda c=cve: webbrowser.open(f"https://nvd.nist.gov/vuln/detail/{c}")).pack(pady=2)
        ctk.CTkButton(bc, text="Faux positif", height=26, width=110, font=("Segoe UI", 10),
                      fg_color=t.bg_hover, command=lambda v=vuln: self._mark_fp(v)).pack(pady=2)

    def _mark_fp(self, vuln): self._fp_set.add(id(vuln)); self.refresh_vulnerabilities()

    def _export_csv(self):
        vulns = self.app.vulnerabilities
        if not vulns: messagebox.showwarning("Attention", "Aucune vulnérabilité à exporter."); return
        try:
            import csv, os, datetime
            from modules.config import REPORTS_DIR
            path = REPORTS_DIR / f"vulns_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Sévérité","CVSS","Nom","Hôte","Port","Service","Description","Recommandation"])
                for v in vulns: w.writerow([v.severity, v.cvss, v.name, v.host, v.port, v.service, v.description, v.recommendation])
            messagebox.showinfo("Export OK", f"Exporté vers :\n{path}")
            webbrowser.open(f"file://{os.path.dirname(path)}")
        except Exception as e: messagebox.showerror("Erreur", str(e))
