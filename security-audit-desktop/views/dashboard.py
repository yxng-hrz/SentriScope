"""SENTRISCOPE — Dashboard"""
import time
import customtkinter as ctk
from tkinter import messagebox, filedialog
from modules import SystemMonitor, NetworkMonitor
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard, ProgressCard
from widgets.gauge import SecurityScoreGauge
from widgets.helpers import fmt_bytes


class DashboardPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        self._net_monitor = NetworkMonitor(history_size=30)
        self._monitoring = False
        self._activity = []

        btn_frame = self.page_header("Dashboard", "Vue d'ensemble de la sécurité")
        for txt, clr, cmd in [
            ("🔍 Scan rapide", t.accent, lambda: self.app.show_page("scan")),
            ("📄 Rapport", t.success, self.app.export_report),
            ("📸 Capture", t.info, self._capture_dashboard),
        ]:
            ctk.CTkButton(btn_frame, text=txt, height=36, font=("Segoe UI", 12),
                          fg_color=clr, command=cmd).pack(side="left", padx=4)

        # Stats cards
        sf = ctk.CTkFrame(self, fg_color="transparent")
        sf.pack(fill="x", pady=(0, 14))
        sf.grid_columnconfigure((0,1,2,3), weight=1)
        self.stat_hosts = StatsCard(sf, "Hôtes actifs", "0", t.accent, "🖥️", "après scan")
        self.stat_ports = StatsCard(sf, "Ports ouverts", "0", t.info, "🔌", "après scan")
        self.stat_vulns = StatsCard(sf, "Vulnérabilités", "0", t.warning, "⚠️", "après scan")
        self.stat_critical = StatsCard(sf, "Critiques", "0", t.danger, "🚨", "après scan")
        for i, c in enumerate([self.stat_hosts, self.stat_ports, self.stat_vulns, self.stat_critical]):
            c.grid(row=0, column=i, padx=4, sticky="nsew")

        # Body: 3 columns
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=2); body.grid_columnconfigure(1, weight=2); body.grid_columnconfigure(2, weight=1)

        # Col 0: Gauge + Compliance
        col0 = ctk.CTkFrame(body, fg_color="transparent")
        col0.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        gauge_sec = self.create_section("🛡️ Score de sécurité", col0)
        gauge_sec.pack(fill="x", pady=(0, 10))
        gf = ctk.CTkFrame(gauge_sec, fg_color="transparent")
        gf.pack(fill="x", padx=16, pady=(0, 16))
        gf.grid_columnconfigure(0, weight=1); gf.grid_columnconfigure(1, weight=1)
        self.score_gauge = SecurityScoreGauge(gf, size=150)
        self.score_gauge.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        info_frame = ctk.CTkFrame(gf, fg_color=t.bg_secondary, corner_radius=10)
        info_frame.grid(row=0, column=1, sticky="nsew")
        self._sys_rows = {}
        for key, label in [("os","💻 OS"),("host","🏠 Hostname"),("arch","⚙️ Arch"),
                           ("up","⏱️ Uptime"),("cpu","🔥 CPU"),("ram","💾 RAM")]:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(row, text=label, font=("Segoe UI", 10), text_color=t.text_muted,
                         width=70, anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(row, text="—", font=("Segoe UI", 10, "bold"),
                               text_color=t.text_primary, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self._sys_rows[key] = lbl

        # Compliance mini
        comp_sec = self.create_section("📋 Conformité", col0, "Détails →",
                                       lambda: self.app.show_page("compliance"))
        comp_sec.pack(fill="x", pady=(0, 10))
        ci = ctk.CTkFrame(comp_sec, fg_color="transparent")
        ci.pack(fill="x", padx=16, pady=(0, 14))
        sr = ctk.CTkFrame(ci, fg_color="transparent")
        sr.pack(fill="x", pady=(0, 8))
        sr.grid_columnconfigure((0,1), weight=1)

        self.comp_score_lbl, self.comp_score_bar = self._mini_metric(sr, 0, "Score", t)
        self.comp_mat_lbl, self.comp_mat_bar = self._mini_metric(sr, 1, "Maturité", t)
        self.fw_bars = {}

        # Col 1: Resources + Network
        col1 = ctk.CTkFrame(body, fg_color="transparent")
        col1.grid(row=0, column=1, sticky="nsew", padx=3)
        res_sec = self.create_section("📈 Ressources système", col1)
        res_sec.pack(fill="x", pady=(0, 10))
        ri = ctk.CTkFrame(res_sec, fg_color="transparent")
        ri.pack(fill="x", padx=16, pady=(0, 14))
        self.cpu_card = ProgressCard(ri, "CPU", t.accent, "🔥")
        self.mem_card = ProgressCard(ri, "Mémoire", t.info, "💾")
        self.disk_card = ProgressCard(ri, "Disque", t.warning, "💿")
        for c in [self.cpu_card, self.mem_card, self.disk_card]: c.pack(fill="x", pady=3)

        net_sec = self.create_section("🌐 Trafic réseau", col1)
        net_sec.pack(fill="x")
        ni = ctk.CTkFrame(net_sec, fg_color="transparent")
        ni.pack(fill="x", padx=16, pady=(0, 14))
        ni.grid_columnconfigure((0,1), weight=1)
        self.net_dl = StatsCard(ni, "Download", "0 B/s", t.success, "⬇️")
        self.net_ul = StatsCard(ni, "Upload", "0 B/s", t.warning, "⬆️")
        self.net_dl.grid(row=0, column=0, padx=(0,4), sticky="nsew")
        self.net_ul.grid(row=0, column=1, padx=(4,0), sticky="nsew")

        # Col 2: Priority actions + Activity
        col2 = ctk.CTkFrame(body, fg_color="transparent")
        col2.grid(row=0, column=2, sticky="nsew", padx=(6, 0))
        prio_sec = self.create_section("🎯 Actions prioritaires", col2,
                                        "Conformité →", lambda: self.app.show_page("compliance"))
        prio_sec.pack(fill="x", pady=(0, 8))
        self._prio_container = ctk.CTkFrame(prio_sec, fg_color="transparent")
        self._prio_container.pack(fill="x", padx=8, pady=(0, 10))
        ctk.CTkLabel(self._prio_container, text="Aucune action en attente",
                     font=("Segoe UI", 11), text_color=t.text_muted).pack(pady=12)

        act_sec = self.create_section("🕐 Activité récente", col2)
        act_sec.pack(fill="both", expand=True)
        self._activity_scroll = ctk.CTkScrollableFrame(act_sec, fg_color="transparent")
        self._activity_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        ctk.CTkLabel(self._activity_scroll, text="Aucune activité",
                     font=("Segoe UI", 11), text_color=t.text_muted).pack(pady=20)

        # Le monitoring est démarré par on_show (et arrêté par on_hide)
        self.update_info()

    def _mini_metric(self, parent, col, label, t):
        box = ctk.CTkFrame(parent, fg_color=t.bg_secondary, corner_radius=10)
        box.grid(row=0, column=col, padx=4, sticky="nsew")
        inner = ctk.CTkFrame(box, fg_color="transparent")
        inner.pack(padx=12, pady=10)
        ctk.CTkLabel(inner, text=label, font=("Segoe UI", 9), text_color=t.text_muted).pack(anchor="w")
        lbl = ctk.CTkLabel(inner, text="—", font=("Segoe UI", 22, "bold"), text_color=t.text_primary)
        lbl.pack(anchor="w")
        bar = ctk.CTkProgressBar(inner, height=5, corner_radius=3,
                                  progress_color=t.accent, fg_color=t.bg_card, width=100)
        bar.pack(anchor="w", pady=(4, 0)); bar.set(0)
        return lbl, bar

    def _start_monitoring(self):
        if not self._monitoring:
            self._monitoring = True
            self._net_monitor.add_callback(self._on_net_stats)
            self._net_monitor.start(interval=2.0)

    def _stop_monitoring(self):
        if self._monitoring:
            self._monitoring = False
            try:
                self._net_monitor.remove_callback(self._on_net_stats)
            except Exception:
                pass
            try:
                self._net_monitor.stop()
            except Exception:
                pass

    def _on_net_stats(self, stats):
        def _u():
            if not self.winfo_exists(): return
            self.net_dl.set_value(fmt_bytes(stats.bytes_recv_rate))
            self.net_ul.set_value(fmt_bytes(stats.bytes_sent_rate))
        self.after(0, _u)

    def update_info(self):
        if not self.winfo_exists(): return
        try:
            si = SystemMonitor.get_system_info()
            cpu = SystemMonitor.get_cpu_info()
            mem = SystemMonitor.get_memory_info()
            dsk = SystemMonitor.get_disk_info()
            plat = f"{si.get('platform','')} {si.get('platform_release','')}".strip()
            self._sys_rows["os"].configure(text=plat[:30] or "—")
            self._sys_rows["host"].configure(text=si.get("hostname","—")[:24])
            self._sys_rows["arch"].configure(text=si.get("architecture","—"))
            self._sys_rows["up"].configure(text=si.get("uptime","—"))
            cp, mp = cpu.get("percent",0), mem.get("percent",0)
            self._sys_rows["cpu"].configure(text=f"{cp:.0f}%")
            self._sys_rows["ram"].configure(text=f"{mp:.0f}%  ({mem.get('used',0)/1e9:.1f} GB)")
            self.cpu_card.set_value(f"{cp:.0f}%", cp)
            self.mem_card.set_value(f"{mem.get('used',0)/1e9:.1f} GB", mp)
            self.disk_card.set_value(f"{dsk.get('used',0)/1e9:.0f} GB", dsk.get("percent",0))
        except Exception: pass
        self.after(5000, self.update_info)  # 5s instead of 3s for perf

    def on_show(self):
        self._start_monitoring()
        self.update_stats(); self._update_compliance(); self._update_priority_actions()

    def on_hide(self):
        # Couper le thread NetworkMonitor quand on quitte le dashboard
        self._stop_monitoring()

    def update_stats(self):
        s = self.app.get_stats()
        self.stat_hosts.set_value(str(s["hosts"])); self.stat_ports.set_value(str(s["ports"]))
        self.stat_vulns.set_value(str(s["vulns"])); self.stat_critical.set_value(str(s["critical"]))
        self.score_gauge.calculate_from_vulns(getattr(self.app, "vulnerabilities", []))

    def _capture_dashboard(self):
        fp = filedialog.asksaveasfilename(defaultextension=".png",
            filetypes=[("PNG","*.png"),("JPEG","*.jpg")],
            initialfile=f"sentriscope_dashboard_{time.strftime('%Y%m%d_%H%M%S')}")
        if not fp: return
        try:
            from PIL import ImageGrab  # noqa: F401  -- vérifie que Pillow est dispo
        except ImportError:
            messagebox.showerror("Erreur", "Pillow non installé.\npip install Pillow")
            return
        self.app.update_idletasks()
        self.after(300, lambda: self._do_capture(fp))

    def _do_capture(self, fp):
        try:
            from PIL import ImageGrab
            x, y = self.app.winfo_rootx(), self.app.winfo_rooty()
            w, h = self.app.winfo_width(), self.app.winfo_height()
            ImageGrab.grab(bbox=(x, y, x+w, y+h)).save(fp)
            messagebox.showinfo("Capture sauvée", f"Dashboard exporté:\n{fp}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec:\n{e}")

    def _update_compliance(self):
        try:
            from modules.compliance import compliance_manager
            t = get_theme()
            score = compliance_manager.get_global_score()
            sc = t.success if score >= 70 else t.warning if score >= 40 else t.danger
            self.comp_score_lbl.configure(text=f"{score:.0f}%", text_color=sc)
            self.comp_score_bar.configure(progress_color=sc); self.comp_score_bar.set(score/100)
            mat = compliance_manager.get_global_maturity()
            mc = "#3b82f6" if mat>=4 else "#22c55e" if mat>=3 else "#eab308" if mat>=2 else "#f97316" if mat>=1 else "#6b7280"
            self.comp_mat_lbl.configure(text=f"{mat:.1f}/5", text_color=mc)
            self.comp_mat_bar.configure(progress_color=mc); self.comp_mat_bar.set(mat/5)
        except Exception: pass

    def _update_priority_actions(self):
        if not self.winfo_exists(): return
        t = get_theme()
        for w in self._prio_container.winfo_children(): w.destroy()
        try:
            from modules.compliance import compliance_manager, ComplianceStatus
            actions = compliance_manager.get_priority_actions(limit=5)
            vulns = getattr(self.app, "vulnerabilities", [])
            all_acts = []
            for v in vulns:
                if getattr(v, "severity", "") == "critical":
                    # Vulnerability uses .name, SecurityAlert uses .title — support both
                    label = getattr(v, "name", None) or getattr(v, "title", "") or "Vulnérabilité critique"
                    all_acts.append({'text': label[:35], 'detail': f"CVE · {getattr(v,'host','?')}",
                                     'color': t.danger, 'icon': "🚨", 'sort_key': 35})
            si = {ComplianceStatus.NON_COMPLIANT: ("❌", t.danger),
                  ComplianceStatus.PARTIAL: ("⚠️", t.warning),
                  ComplianceStatus.NOT_EVALUATED: ("⏳", t.text_muted)}
            for a in actions:
                ctrl = a['control']
                icon, color = si.get(ctrl.status, ("⏳", t.text_muted))
                cross = f" · 🔗{a['cross_impact']}" if a['cross_impact'] > 0 else ""
                all_acts.append({'text': f"{ctrl.id} — {ctrl.title[:28]}",
                                 'detail': f"{a['framework']}{cross}",
                                 'color': color, 'icon': icon, 'sort_key': a['sort_key']})
            all_acts.sort(key=lambda x: x['sort_key'], reverse=True)
            all_acts = all_acts[:5]
            if not all_acts:
                ctk.CTkLabel(self._prio_container, text="✅ Aucune action en attente",
                             font=("Segoe UI", 11), text_color=t.success).pack(pady=12)
                return
            for act in all_acts:
                row = ctk.CTkFrame(self._prio_container, fg_color=t.bg_secondary, corner_radius=6)
                row.pack(fill="x", pady=2)
                ctk.CTkFrame(row, fg_color=act['color'], width=3, corner_radius=0).pack(side="left", fill="y")
                ct = ctk.CTkFrame(row, fg_color="transparent")
                ct.pack(fill="x", padx=8, pady=5)
                tr = ctk.CTkFrame(ct, fg_color="transparent"); tr.pack(fill="x")
                ctk.CTkLabel(tr, text=act['icon'], font=("Segoe UI", 10)).pack(side="left")
                ctk.CTkLabel(tr, text=f" {act['text']}", font=("Segoe UI", 10, "bold"),
                             text_color=t.text_primary, anchor="w").pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(ct, text=act['detail'], font=("Segoe UI", 9),
                             text_color=t.text_muted, anchor="w").pack(anchor="w")
        except Exception:
            ctk.CTkLabel(self._prio_container, text="—", font=("Segoe UI", 11),
                         text_color=t.text_muted).pack(pady=12)

    def log_activity(self, msg: str, color: str = None):
        t = get_theme()
        self._activity.insert(0, (time.strftime("%H:%M:%S"), msg, color or t.text_secondary))
        self._activity = self._activity[:50]
        self._render_activity()

    def _render_activity(self):
        if not self.winfo_exists(): return
        t = get_theme()
        for w in self._activity_scroll.winfo_children(): w.destroy()
        if not self._activity:
            ctk.CTkLabel(self._activity_scroll, text="Aucune activité",
                         font=("Segoe UI", 11), text_color=t.text_muted).pack(pady=20)
            return
        for ts, msg, color in self._activity[:20]:
            row = ctk.CTkFrame(self._activity_scroll, fg_color=t.bg_secondary, corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=ts, font=("Consolas", 9), text_color=t.text_muted,
                         width=54).pack(side="left", padx=6, pady=4)
            ctk.CTkFrame(row, fg_color=color, width=2, corner_radius=1).pack(side="left", fill="y", pady=4)
            ctk.CTkLabel(row, text=msg, font=("Segoe UI", 10), text_color=t.text_secondary,
                         anchor="w", wraplength=160).pack(side="left", padx=6, pady=4, fill="x", expand=True)
