"""SENTRISCOPE — IDSPage"""
import threading
import customtkinter as ctk
from modules import intrusion_detector
from modules.geo_ip import geo_ip, GeoResult
from views.connections import GeoIPDetailWindow
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard

SEV_CLR = {"critical":"#ef4444", "high":"#f97316", "medium":"#f59e0b", "low":"#22c55e"}
SEV_ICO = {"critical":"🚨", "high":"⚠️", "medium":"🔔", "low":"ℹ️"}
TYPE_ICO = {"port_scan":"🔍", "brute_force":"🔐", "syn_flood":"🌊", "dns_tunneling":"📡", "suspicious_port":"🚪"}

class IDSPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        # Singleton partagé : la blacklist et les alertes survivent à la navigation
        self.ids = intrusion_detector
        self._auto_refresh = False; self._sev_filter = "Toutes"

        bf = self.page_header("IDS — Détection d'Intrusions", "Surveillance des comportements suspects en temps réel")
        self._auto_btn = ctk.CTkButton(bf, text="▶ Auto", height=36, font=("Segoe UI", 12),
                                        fg_color=t.bg_card, command=self._toggle_auto)
        self._auto_btn.pack(side="left", padx=4)
        ctk.CTkButton(bf, text="✅ Acquitter tout", height=36, font=("Segoe UI", 12),
                      fg_color=t.accent, command=self._acknowledge_all).pack(side="left", padx=4)
        ctk.CTkButton(bf, text="🧹 Effacer", height=36, font=("Segoe UI", 12),
                      fg_color=t.bg_card, command=self._clear).pack(side="left", padx=4)

        sf = ctk.CTkFrame(self, fg_color="transparent"); sf.pack(fill="x", pady=(0, 12))
        sf.grid_columnconfigure((0,1,2,3), weight=1)
        self.stat_total = StatsCard(sf, "Alertes", "0", t.accent, "🔔")
        self.stat_critical = StatsCard(sf, "Critiques", "0", "#ef4444", "🚨")
        self.stat_high = StatsCard(sf, "Hautes", "0", "#f97316", "⚠️")
        self.stat_blacklist = StatsCard(sf, "Blacklist", "0", t.danger, "🚫")
        for i, c in enumerate([self.stat_total, self.stat_critical, self.stat_high, self.stat_blacklist]):
            c.grid(row=0, column=i, padx=4, sticky="nsew")

        body = ctk.CTkFrame(self, fg_color="transparent"); body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=3); body.grid_columnconfigure(1, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent"); left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        flt = ctk.CTkFrame(left, fg_color=t.bg_card, corner_radius=10); flt.pack(fill="x", pady=(0, 8))
        fi = ctk.CTkFrame(flt, fg_color="transparent"); fi.pack(fill="x", padx=12, pady=8)
        ctk.CTkLabel(fi, text="Filtre :", font=("Segoe UI", 11), text_color=t.text_muted).pack(side="left")
        self._flt_combo = ctk.CTkComboBox(fi, width=140, height=30, state="readonly",
            values=["Toutes","Critiques","Hautes","Moyennes","Basses"], command=self._on_filter)
        self._flt_combo.pack(side="left", padx=8); self._flt_combo.set("Toutes")
        self._count_lbl = ctk.CTkLabel(fi, text="", font=("Segoe UI", 11), text_color=t.text_muted)
        self._count_lbl.pack(side="right")

        als = self.create_section("🔔 Alertes récentes"); als.pack(fill="both", expand=True)
        self.alerts_scroll = ctk.CTkScrollableFrame(als, fg_color="transparent")
        self.alerts_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        right = ctk.CTkFrame(body, fg_color="transparent"); right.grid(row=0, column=1, sticky="nsew")
        bls = self.create_section("🚫 Blacklist IP"); bls.pack(fill="x", pady=(0, 10))
        af = ctk.CTkFrame(bls, fg_color="transparent"); af.pack(fill="x", padx=12, pady=(0, 8))
        self.ip_entry = ctk.CTkEntry(af, height=34, placeholder_text="IP à bloquer…")
        self.ip_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(af, text="➕", width=36, height=34, command=self._add_bl).pack(side="right")
        self.blacklist_text = ctk.CTkTextbox(bls, height=200, fg_color=t.bg_secondary, font=("Consolas", 11))
        self.blacklist_text.pack(fill="x", padx=12, pady=(0, 12))

        tts = self.create_section("🛡️ Types détectés"); tts.pack(fill="x")
        tf = ctk.CTkFrame(tts, fg_color="transparent"); tf.pack(fill="x", padx=12, pady=(0, 12))
        for label in ["🔍 Port Scan","🔐 Brute Force","🌊 SYN Flood","📡 DNS Tunneling","🚪 Ports suspects"]:
            ctk.CTkLabel(tf, text=label, font=("Segoe UI", 11), text_color=t.text_secondary).pack(anchor="w", pady=2)

    def on_show(self):
        # Lance le feeder ConnectionMonitor → IDS s'il ne tourne pas déjà
        try:
            self.ids.start_feeder(interval=3.0)
        except Exception:
            pass
        self.refresh_ids()
    def _on_filter(self, _=None): self.refresh_ids()

    def _toggle_auto(self):
        t = get_theme(); self._auto_refresh = not self._auto_refresh
        if self._auto_refresh:
            self._auto_btn.configure(text="⏹ Auto ON", fg_color=t.success); self._auto_loop()
        else:
            self._auto_btn.configure(text="▶ Auto", fg_color=t.bg_card)

    def _auto_loop(self):
        if self._auto_refresh and self.winfo_exists(): self.refresh_ids(); self.after(3000, self._auto_loop)

    def refresh_ids(self):
        stats = self.ids.get_stats()
        self.stat_total.set_value(str(stats["total"])); self.stat_critical.set_value(str(stats["critical"]))
        self.stat_high.set_value(str(stats["high"])); self.stat_blacklist.set_value(str(len(self.ids.blacklist)))

        sev_map = {"Critiques":"critical", "Hautes":"high", "Moyennes":"medium", "Basses":"low"}
        sf = sev_map.get(self._flt_combo.get())
        alerts = self.ids.get_alerts(limit=100)
        if sf: alerts = [a for a in alerts if a.severity == sf]
        self._count_lbl.configure(text=f"{len(alerts)} alerte(s)")

        for w in self.alerts_scroll.winfo_children(): w.destroy()
        if not alerts: self.empty_state(self.alerts_scroll, "✅", "Aucune alerte")
        else:
            for a in reversed(alerts): self._alert_card(a)

        self.blacklist_text.delete("1.0", "end")
        for ip in sorted(self.ids.blacklist): self.blacklist_text.insert("end", f"🚫 {ip}\n")

    def _alert_card(self, alert):
        t = get_theme()
        color = SEV_CLR.get(alert.severity, t.info); icon = SEV_ICO.get(alert.severity, "•")
        ti = TYPE_ICO.get(alert.alert_type, "🔔")
        card = ctk.CTkFrame(self.alerts_scroll, fg_color=t.bg_card, corner_radius=8); card.pack(fill="x", pady=3)
        ctk.CTkFrame(card, fg_color=color, width=4, corner_radius=0).pack(side="left", fill="y")
        body = ctk.CTkFrame(card, fg_color="transparent"); body.pack(fill="x", padx=12, pady=8)

        top = ctk.CTkFrame(body, fg_color="transparent"); top.pack(fill="x")
        ctk.CTkLabel(top, text=f" {icon} {alert.severity.upper()} ", font=("Segoe UI", 9, "bold"),
                     fg_color=color, corner_radius=3, text_color="#ffffff").pack(side="left")
        ctk.CTkLabel(top, text=f"  {ti} {alert.title or alert.alert_type}",
                     font=("Segoe UI", 11, "bold")).pack(side="left")
        ts = alert.timestamp.split("T")[1][:8] if "T" in alert.timestamp else alert.timestamp
        ctk.CTkLabel(top, text=ts, font=("Consolas", 9), text_color=t.text_muted).pack(side="right")

        bot = ctk.CTkFrame(body, fg_color="transparent"); bot.pack(fill="x", pady=(4, 0))
        ctk.CTkLabel(bot, text=f"📍 {alert.source_ip}", font=("Segoe UI", 10, "bold"),
                     text_color=t.text_secondary).pack(side="left")
        geo_lbl = ctk.CTkLabel(bot, text="🌐 …", font=("Segoe UI", 10), text_color=t.text_muted, cursor="hand2")
        geo_lbl.pack(side="left", padx=10)
        ctk.CTkButton(bot, text="🔍 Détail IP", height=22, width=80, font=("Segoe UI", 9),
                      fg_color=t.bg_secondary, command=lambda ip=alert.source_ip: GeoIPDetailWindow(self, ip)).pack(side="right")

        src = alert.source_ip
        def _fetch():
            r = geo_ip.lookup(src)
            if card.winfo_exists(): card.after(0, lambda: _upd(r))
        def _upd(r):
            if not geo_lbl.winfo_exists(): return
            if r.is_private: geo_lbl.configure(text="🏠 Local")
            elif r.status == "success":
                geo_lbl.configure(text=r.location_str, text_color="#ef4444" if r.is_suspicious else t.text_secondary)
            else: geo_lbl.configure(text="❓ Inconnu")
        threading.Thread(target=_fetch, daemon=True).start()

    def _add_bl(self):
        ip = self.ip_entry.get().strip()
        if ip: self.ids.add_to_blacklist(ip); self.ip_entry.delete(0, "end"); self.refresh_ids()

    def _clear(self): self.ids.clear_alerts(); self.refresh_ids()
    def _acknowledge_all(self): self.ids.acknowledge_all(); self.refresh_ids()
