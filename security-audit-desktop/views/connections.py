"""SENTRISCOPE — ConnectionsPage + GeoIPDetailWindow"""
import os, threading, webbrowser
from typing import Dict
import customtkinter as ctk
from tkinter import messagebox
from modules import ConnectionMonitor, ReportGenerator
from modules.geo_ip import geo_ip, GeoResult
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard
from widgets.nav import CustomTreeview
from widgets.helpers import setup_tree_columns


class GeoIPDetailWindow(ctk.CTkToplevel):
    def __init__(self, parent, ip: str):
        super().__init__(parent)
        self.title(f"Géolocalisation — {ip}"); self.geometry("420x380"); self.resizable(False, False); self.grab_set()
        t = get_theme()
        header = ctk.CTkFrame(self, fg_color=t.bg_card, corner_radius=0); header.pack(fill="x")
        ctk.CTkLabel(header, text=f"🌍  {ip}", font=("", 18, "bold")).pack(side="left", padx=20, pady=16)
        self.status_lbl = ctk.CTkLabel(header, text="⏳ Requête en cours…", font=("", 11), text_color=t.text_muted)
        self.status_lbl.pack(side="right", padx=20)
        body = ctk.CTkFrame(self, fg_color="transparent"); body.pack(fill="both", expand=True, padx=20, pady=16)
        body.grid_columnconfigure(1, weight=1)
        self._lbls = {}
        for i, label in enumerate(["Pays","Ville","Région","ISP","Organisation","ASN","Coordonnées","Risque"]):
            ctk.CTkLabel(body, text=label, font=("", 11), text_color=t.text_muted, anchor="w").grid(row=i, column=0, sticky="w", pady=5)
            v = ctk.CTkLabel(body, text="—", font=("", 11, "bold"), anchor="w")
            v.grid(row=i, column=1, sticky="w", padx=20, pady=5)
            self._lbls[label] = v
        ctk.CTkButton(self, text="Fermer", height=36, command=self.destroy).pack(pady=(0, 16))
        threading.Thread(target=self._fetch, args=(ip,), daemon=True).start()

    def _fetch(self, ip):
        r = geo_ip.lookup(ip); self.after(0, lambda: self._apply(r))

    def _apply(self, r: GeoResult):
        t = get_theme()
        if r.is_private:
            self.status_lbl.configure(text="🏠 IP privée"); self._lbls["Pays"].configure(text="Réseau local"); return
        if r.status != "success":
            self.status_lbl.configure(text="❌ Échec"); return
        self.status_lbl.configure(text="✅ OK", text_color=t.success)
        self._lbls["Pays"].configure(text=f"{r.flag} {r.country} ({r.country_code})")
        self._lbls["Ville"].configure(text=r.city or "—")
        self._lbls["Région"].configure(text=r.region or "—")
        self._lbls["ISP"].configure(text=r.isp or "—")
        self._lbls["Organisation"].configure(text=r.org or "—")
        self._lbls["ASN"].configure(text=r.asn or "—")
        self._lbls["Coordonnées"].configure(text=f"{r.lat:.4f}, {r.lon:.4f}")
        self._lbls["Risque"].configure(
            text="⚠️ Pays à risque élevé" if r.is_suspicious else "✅ Pays standard",
            text_color=t.danger if r.is_suspicious else t.success)


class ConnectionsPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        self.auto_refresh = False
        self.connections_data = []
        self._geo_cache: Dict[str, GeoResult] = {}

        header = ctk.CTkFrame(self, fg_color="transparent"); header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="Connexions Réseau", font=("", 28, "bold")).pack(side="left")
        bf = ctk.CTkFrame(header, fg_color="transparent"); bf.pack(side="right")
        ctk.CTkButton(bf, text="📥 Export CSV", font=("", 12), height=35, fg_color=t.success,
                      hover_color="#059669", command=self.export_csv).pack(side="left", padx=5)
        self.geo_btn = ctk.CTkButton(bf, text="🌍 Géolocaliser", font=("", 12), height=35,
                                      fg_color=t.info, command=self.geolocate_all)
        self.geo_btn.pack(side="left", padx=5)
        self.auto_btn = ctk.CTkButton(bf, text="🔄 Auto-refresh: OFF", font=("", 12), height=35,
                                       fg_color=t.bg_card, command=self.toggle_auto_refresh)
        self.auto_btn.pack(side="left", padx=5)
        ctk.CTkButton(bf, text="🔃 Actualiser", font=("", 12), height=35, fg_color=t.accent,
                      command=self.refresh_connections).pack(side="left")

        sf = ctk.CTkFrame(self, fg_color="transparent"); sf.pack(fill="x", pady=(0, 15))
        sf.grid_columnconfigure((0,1,2,3,4,5), weight=1)
        self.stat_total = StatsCard(sf, "Total", "0", t.accent, "🔗")
        self.stat_established = StatsCard(sf, "Établies", "0", t.success, "✅")
        self.stat_listening = StatsCard(sf, "Écoute", "0", t.info, "👂")
        self.stat_time_wait = StatsCard(sf, "Time Wait", "0", t.warning, "⏳")
        self.stat_tcp = StatsCard(sf, "TCP", "0", t.accent, "📡")
        self.stat_external = StatsCard(sf, "Externes", "0", "#8b5cf6", "🌍")
        for i, c in enumerate([self.stat_total, self.stat_established, self.stat_listening,
                                self.stat_time_wait, self.stat_tcp, self.stat_external]):
            c.grid(row=0, column=i, padx=3, sticky="nsew")

        ff = ctk.CTkFrame(self, fg_color=t.bg_card, corner_radius=10); ff.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(ff, text="Filtres:", font=("", 12)).pack(side="left", padx=15, pady=10)
        self.filter_proto = ctk.CTkComboBox(ff, values=["Tous","TCP","UDP"], width=100, state="readonly",
                                             command=lambda _: self.refresh_connections())
        self.filter_proto.pack(side="left", padx=5); self.filter_proto.set("Tous")
        self.filter_status = ctk.CTkComboBox(ff, values=["Tous","ESTABLISHED","LISTEN","TIME_WAIT","CLOSE_WAIT"],
                                              width=150, state="readonly", command=lambda _: self.refresh_connections())
        self.filter_status.pack(side="left", padx=5); self.filter_status.set("Tous")
        self.filter_geo = ctk.CTkComboBox(ff, values=["Tous les pays","🏠 Local","⚠️ Suspects"],
                                           width=160, state="readonly", command=lambda _: self.refresh_connections())
        self.filter_geo.pack(side="left", padx=5); self.filter_geo.set("Tous les pays")
        self.search_entry = ctk.CTkEntry(ff, placeholder_text="Rechercher IP/Port/Processus/Pays…", width=220)
        self.search_entry.pack(side="left", padx=10, pady=10)
        self.search_entry.bind("<Return>", lambda e: self.refresh_connections())

        ts = self.create_section("📋 Connexions Actives"); ts.pack(fill="both", expand=True)
        tf = ctk.CTkFrame(ts, fg_color="transparent"); tf.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        cols = ("proto","local","local_port","remote","remote_port","status","geo","isp","process")
        self.conn_tree = CustomTreeview(tf, cols)
        setup_tree_columns(self.conn_tree, {
            "proto":("Proto",60), "local":("Adresse Locale",130), "local_port":("Port Local",80),
            "remote":("Adresse Distante",130), "remote_port":("Port Distant",80), "status":("Statut",100),
            "geo":("Localisation",180), "isp":("ISP",160), "process":("Processus",140)})
        self.conn_tree.pack(fill="both", expand=True)
        self.conn_tree.bind("<Double-1>", self._on_double_click)
        self.geo_status_lbl = ctk.CTkLabel(ts, font=("", 10), text_color=t.text_muted,
            text="💡 Double-cliquez sur une ligne pour voir le détail géo · Cliquez sur 🌍 Géolocaliser pour enrichir toutes les IPs")
        self.geo_status_lbl.pack(pady=(0, 8))

    def on_show(self): self.refresh_connections()

    def toggle_auto_refresh(self):
        t = get_theme(); self.auto_refresh = not self.auto_refresh
        if self.auto_refresh:
            self.auto_btn.configure(text="🔄 Auto-refresh: ON", fg_color=t.success); self.auto_refresh_loop()
        else:
            self.auto_btn.configure(text="🔄 Auto-refresh: OFF", fg_color=t.bg_card)

    def auto_refresh_loop(self):
        if self.auto_refresh and self.winfo_exists(): self.refresh_connections(); self.after(2000, self.auto_refresh_loop)

    def _on_double_click(self, event):
        sel = self.conn_tree.selection()
        if not sel: return
        vals = self.conn_tree.item(sel[0], "values")
        if len(vals) >= 5 and vals[3] not in ("-", ""): GeoIPDetailWindow(self, vals[3])

    def refresh_connections(self):
        for item in self.conn_tree.get_children(): self.conn_tree.delete(item)
        stats = ConnectionMonitor.get_connection_stats()
        self.stat_total.set_value(str(stats['total'])); self.stat_established.set_value(str(stats['established']))
        self.stat_listening.set_value(str(stats['listening'])); self.stat_time_wait.set_value(str(stats['time_wait']))
        self.stat_tcp.set_value(str(stats['tcp']))
        connections = ConnectionMonitor.get_connections(include_localhost=True)
        pf, sf, gf = self.filter_proto.get(), self.filter_status.get(), self.filter_geo.get()
        search = self.search_entry.get().lower()
        self.connections_data = []; ext = 0
        for conn in connections:
            if pf != "Tous" and conn.protocol != pf: continue
            if sf != "Tous" and conn.status != sf: continue
            geo = self._geo_cache.get(conn.remote_ip)
            geo_str = geo.location_str if geo else "—"; isp_str = geo.isp_str if geo else "—"
            if gf == "🏠 Local" and not (geo and geo.is_private): continue
            if gf == "⚠️ Suspects" and not (geo and geo.is_suspicious): continue
            if search and search not in f"{conn.local_ip} {conn.local_port} {conn.remote_ip} {conn.remote_port} {conn.process} {geo_str}".lower(): continue
            if conn.remote_ip and not geo_ip.is_private(conn.remote_ip): ext += 1
            self.connections_data.append(conn)
            tags = ("suspicious",) if geo and geo.is_suspicious else ()
            if tags: self.conn_tree.tag_configure("suspicious", foreground="#ef4444")
            self.conn_tree.insert("", "end", tags=tags, values=(
                conn.protocol, conn.local_ip, conn.local_port, conn.remote_ip,
                conn.remote_port or "-", conn.status, geo_str, isp_str, conn.process or f"PID:{conn.pid}"))
        self.stat_external.set_value(str(ext))

    def geolocate_all(self):
        ips = list({c.remote_ip for c in self.connections_data if c.remote_ip and c.remote_ip not in ("-","")})
        if not ips: messagebox.showinfo("Info", "Aucune IP distante à géolocaliser."); return
        self.geo_btn.configure(text="⏳ En cours…", state="disabled")
        self.geo_status_lbl.configure(text=f"🌍 Géolocalisation de {len(ips)} IPs en cours…")
        geo_ip.lookup_async(ips, on_result=lambda ip, r: self._geo_cache.update({ip: r}),
                            on_done=lambda: self.after(0, self._geo_done))

    def _geo_done(self):
        t = get_theme()
        self.geo_btn.configure(text="🌍 Géolocaliser", state="normal")
        suspects = sum(1 for r in self._geo_cache.values() if r.is_suspicious)
        msg = f"✅ {len(self._geo_cache)} IPs géolocalisées"
        if suspects: msg += f"  ·  ⚠️ {suspects} pays suspects"
        self.geo_status_lbl.configure(text=msg, text_color=t.danger if suspects else t.success)
        self.refresh_connections()

    def export_csv(self):
        if not self.connections_data:
            messagebox.showwarning("Attention", "Aucune connexion à exporter.\nActualisez d'abord la liste."); return
        try:
            fp = ReportGenerator().export_connections_csv(self.connections_data)
            messagebox.showinfo("Export réussi", f"Connexions exportées vers:\n{fp}")
            webbrowser.open(f"file://{os.path.dirname(fp)}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export:\n{e}")
