"""SENTRISCOPE — ScanPage"""
import time, threading
import customtkinter as ctk
from tkinter import messagebox
from typing import List
from modules import NetworkScanner, ScanResult, HostResult, VulnerabilityScanner, TOP_PORTS, COMMON_PORTS
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard
from widgets.nav import CustomTreeview
from widgets.helpers import setup_tree_columns

PRESETS = {"Mon réseau":"", "Localhost":"127.0.0.1", "192.168.0.x":"192.168.0.0/24",
           "192.168.1.x":"192.168.1.0/24", "10.0.0.x":"10.0.0.0/24"}

class ScanPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        self.scanner = NetworkScanner(timeout=1.0)
        self.scan_result = None
        self.is_scanning = False
        PRESETS["Mon réseau"] = self.scanner.get_network_range()

        btn_frame = self.page_header("Scan Réseau", "Découverte d'hôtes et analyse de ports")
        self._nmap_var = ctk.BooleanVar(value=False)
        self._nmap_avail = False
        try:
            from modules import NmapScanner as _NS
            _test = _NS()
            self._nmap_avail = _test.is_available()
        except Exception:
            pass
        nmap_lbl = "Mode Nmap" if self._nmap_avail else "Mode Nmap (non dispo)"
        ctk.CTkCheckBox(btn_frame, text=nmap_lbl, variable=self._nmap_var,
                        font=("Segoe UI", 12),
                        state="normal" if self._nmap_avail else "disabled").pack(side="left", padx=8)

        cfg = self.create_section("⚙️ Configuration du scan")
        cfg.pack(fill="x", pady=(0, 10))
        ci = ctk.CTkFrame(cfg, fg_color="transparent")
        ci.pack(fill="x", padx=16, pady=(0, 14))
        ci.grid_columnconfigure((0,1,2,3), weight=1)

        tf = ctk.CTkFrame(ci, fg_color="transparent")
        tf.grid(row=0, column=0, columnspan=2, padx=(0,8), sticky="ew")
        ctk.CTkLabel(tf, text="Cible", font=("Segoe UI", 11), text_color=t.text_muted).pack(anchor="w")
        er = ctk.CTkFrame(tf, fg_color="transparent"); er.pack(fill="x", pady=(4,0))
        self.target_entry = ctk.CTkEntry(er, height=38, placeholder_text="192.168.1.0/24  ou  192.168.1.1-254")
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0,6))
        self.target_entry.insert(0, self.scanner.get_network_range())
        self._preset_combo = ctk.CTkComboBox(er, width=130, height=38, state="readonly",
                                              values=list(PRESETS.keys()), command=self._apply_preset)
        self._preset_combo.pack(side="left"); self._preset_combo.set("Présets")

        pf = ctk.CTkFrame(ci, fg_color="transparent")
        pf.grid(row=0, column=2, padx=8, sticky="ew")
        ctk.CTkLabel(pf, text="Ports", font=("Segoe UI", 11), text_color=t.text_muted).pack(anchor="w")
        self.ports_combo = ctk.CTkComboBox(pf, height=38, state="readonly",
            values=["Top 20 ports","Top 100 ports","Tous (1-1024)","Personnalisé"],
            command=self._on_ports_change)
        self.ports_combo.pack(fill="x", pady=(4,0)); self.ports_combo.set("Top 20 ports")
        self._custom_ports_entry = ctk.CTkEntry(pf, height=34, placeholder_text="ex: 80,443,8080-8090")
        # Affiché uniquement si "Personnalisé" est sélectionné

        of = ctk.CTkFrame(ci, fg_color="transparent")
        of.grid(row=0, column=3, padx=(8,0), sticky="ew")
        ctk.CTkLabel(of, text="Timeout (s)", font=("Segoe UI", 11), text_color=t.text_muted).pack(anchor="w")
        self.timeout_entry = ctk.CTkEntry(of, height=38, placeholder_text="1.0")
        self.timeout_entry.pack(fill="x", pady=(4,0)); self.timeout_entry.insert(0, "1.0")

        br = ctk.CTkFrame(cfg, fg_color="transparent"); br.pack(fill="x", padx=16, pady=(0, 14))
        self.scan_btn = ctk.CTkButton(br, text="🚀  Démarrer le scan", font=("Segoe UI", 13, "bold"),
                                       height=42, fg_color=t.success, hover_color=t.accent_dark, command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(0,8))
        self.cancel_btn = ctk.CTkButton(br, text="⏹  Annuler", font=("Segoe UI", 13), height=42,
                                         fg_color=t.danger, state="disabled", command=self.cancel_scan)
        self.cancel_btn.pack(side="left")

        pf2 = ctk.CTkFrame(self, fg_color=t.bg_card, corner_radius=12); pf2.pack(fill="x", pady=(0, 10))
        pi = ctk.CTkFrame(pf2, fg_color="transparent"); pi.pack(fill="x", padx=16, pady=10)
        self.progress_label = ctk.CTkLabel(pi, text="En attente d'un scan…", font=("Segoe UI", 11), text_color=t.text_muted)
        self.progress_label.pack(side="left")
        self._pct_label = ctk.CTkLabel(pi, text="", font=("Segoe UI", 11, "bold"), text_color=t.accent)
        self._pct_label.pack(side="right")
        self.progress_bar = ctk.CTkProgressBar(pf2, height=6, corner_radius=3, progress_color=t.accent)
        self.progress_bar.pack(fill="x", padx=16, pady=(0, 10)); self.progress_bar.set(0)

        lf = ctk.CTkFrame(self, fg_color="transparent"); lf.pack(fill="x", pady=(0, 10))
        lf.grid_columnconfigure((0,1,2,3), weight=1)
        self._live_hosts = StatsCard(lf, "Hôtes actifs", "0", t.accent, "🖥️")
        self._live_ports = StatsCard(lf, "Ports ouverts", "0", t.info, "🔌")
        self._live_vulns = StatsCard(lf, "Vulnérabilités", "0", t.warning, "⚠️")
        self._live_dur = StatsCard(lf, "Durée", "0s", t.text_secondary, "⏱️")
        for i, c in enumerate([self._live_hosts, self._live_ports, self._live_vulns, self._live_dur]):
            c.grid(row=0, column=i, padx=4, sticky="nsew")
        self._hosts_found = self._ports_found = 0; self._scan_start = 0.0

        rs = self.create_section("📋 Résultats du scan"); rs.pack(fill="both", expand=True)
        tf2 = ctk.CTkFrame(rs, fg_color="transparent")
        tf2.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        self.results_tree = CustomTreeview(tf2, ("risk","ip","hostname","os","ports","latency"))
        setup_tree_columns(self.results_tree, {"risk":("Risque",70), "ip":("Adresse IP",130),
            "hostname":("Hostname",160), "os":("OS",120), "ports":("Ports ouverts",220), "latency":("Latence",80)})
        for tag, clr in [("critical","#ef4444"),("high","#f97316"),("safe","#22c55e")]:
            self.results_tree.tag_configure(tag, foreground=clr)
        self.results_tree.pack(fill="both", expand=True)
        self.results_tree.bind("<Double-1>", self.show_host_details)

    def _apply_preset(self, choice):
        v = PRESETS.get(choice, "")
        if v: self.target_entry.delete(0, "end"); self.target_entry.insert(0, v)

    def _on_ports_change(self, choice):
        if choice == "Personnalisé":
            self._custom_ports_entry.pack(fill="x", pady=(4, 0))
        else:
            self._custom_ports_entry.pack_forget()

    def get_ports(self) -> List[int]:
        choice = self.ports_combo.get()
        if choice == "Personnalisé":
            raw = self._custom_ports_entry.get().strip()
            if not raw:
                return TOP_PORTS
            ports: List[int] = []
            for part in raw.split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        lo, hi = part.split("-", 1)
                        ports.extend(range(int(lo.strip()), int(hi.strip()) + 1))
                    except ValueError:
                        pass
                else:
                    try:
                        ports.append(int(part))
                    except ValueError:
                        pass
            return sorted(set(p for p in ports if 1 <= p <= 65535)) or TOP_PORTS
        return {"Top 20 ports": TOP_PORTS, "Top 100 ports": COMMON_PORTS[:100],
                "Tous (1-1024)": list(range(1, 1025))}.get(choice, TOP_PORTS)

    def start_scan(self):
        if self.is_scanning: return
        target = self.target_entry.get().strip()
        if not target: messagebox.showwarning("Attention", "Veuillez entrer une cible."); return
        try: timeout = float(self.timeout_entry.get() or 1.0)
        except ValueError: timeout = 1.0
        self.is_scanning, self._hosts_found, self._ports_found = True, 0, 0
        self._scan_start = time.time()
        self.scan_btn.configure(state="disabled"); self.cancel_btn.configure(state="normal")
        self.progress_bar.set(0); self.progress_label.configure(text="Initialisation…"); self._pct_label.configure(text="")
        for c in [self._live_hosts, self._live_ports, self._live_vulns]: c.set_value("0")
        self._live_dur.set_value("0s")
        for item in self.results_tree.get_children(): self.results_tree.delete(item)
        ports = self.get_ports()
        use_nmap = self._nmap_var.get() and self._nmap_avail
        if use_nmap:
            from modules import NmapScanner
            nmap_sc = NmapScanner()
            ports_str = ",".join(str(p) for p in ports[:200])
            def _nmap_cb(msg):
                if self.winfo_exists():
                    self.after(0, lambda m=msg: self.progress_label.configure(text=str(m)[:80]))
            def _run():
                try:
                    result = nmap_sc.service_scan(target, ports=ports_str, callback=_nmap_cb)
                    self.after(0, lambda: self.on_scan_complete(result))
                except Exception as e:
                    self.after(0, lambda: self.on_scan_error(str(e)))
        else:
            self.scanner = NetworkScanner(timeout=timeout)
            def _run():
                try:
                    result = self.scanner.scan_network(target, ports, callback=self.update_progress, max_threads=50)
                    self.after(0, lambda: self.on_scan_complete(result))
                except Exception as e:
                    self.after(0, lambda: self.on_scan_error(str(e)))
        threading.Thread(target=_run, daemon=True).start()

    def cancel_scan(self):
        self.scanner.cancel(); self.progress_label.configure(text="Scan annulé"); self._pct_label.configure(text="")
        self.is_scanning = False; self.scan_btn.configure(state="normal"); self.cancel_btn.configure(state="disabled")

    def update_progress(self, current, total, ip, percent, result):
        def _upd():
            self.progress_bar.set(percent / 100)
            self.progress_label.configure(text=f"Analyse de {ip}  —  {current}/{total} hôtes")
            self._pct_label.configure(text=f"{percent}%")
            self._live_dur.set_value(f"{time.time() - self._scan_start:.0f}s")
            if result and result.is_up:
                self._hosts_found += 1; self._ports_found += len(result.ports)
                self._live_hosts.set_value(str(self._hosts_found))
                self._live_ports.set_value(str(self._ports_found))
                dangerous = {21, 23, 445, 3389, 3306, 5432, 6379, 27017}
                has_risk = any(p.port in dangerous for p in result.ports)
                tag, icon = ("critical","🔴") if has_risk else ("safe","🟢")
                ps = ", ".join(str(p.port) for p in result.ports[:6])
                if len(result.ports) > 6: ps += f" +{len(result.ports)-6}"
                self.results_tree.insert("", "end", tags=(tag,), values=(
                    icon, result.ip, result.hostname or "—", result.os_guess or "Inconnu", ps or "—",
                    f"{result.response_time:.0f} ms"))
        self.after(0, _upd)

    def on_scan_complete(self, result: ScanResult):
        self.scan_result, self.is_scanning = result, False
        self.scan_btn.configure(state="normal"); self.cancel_btn.configure(state="disabled")
        self.progress_bar.set(1.0)
        self.progress_label.configure(text=f"✅ Terminé — {result.hosts_up} hôtes, {result.total_open_ports} ports en {result.duration:.1f}s")
        self._pct_label.configure(text="100%"); self._live_dur.set_value(f"{result.duration:.1f}s")
        vr = VulnerabilityScanner().analyze_scan_results(result)
        vulns = vr["vulnerabilities"]; self._live_vulns.set_value(str(len(vulns)))
        self.app.update_scan_results(result, vulns)

        # ── Persister le scan dans l'historique SQLite ───────────────
        try:
            from modules.database import db as _db
            scan_type = "nmap" if (self._nmap_var.get() and self._nmap_avail) else "native"
            user_id = getattr(self.app.current_user, "id", None)
            if user_id is not None:
                _db.save_scan(
                    user_id=user_id,
                    target=getattr(result, "target", ""),
                    scan_type=scan_type,
                    hosts_scanned=getattr(result, "hosts_scanned", 0),
                    hosts_up=getattr(result, "hosts_up", 0),
                    open_ports=getattr(result, "total_open_ports", 0),
                    vulnerabilities=len(vulns),
                    duration=getattr(result, "duration", 0.0),
                    results=""  # le détail complet reste en mémoire pour la session
                )
        except Exception as e:
            # Ne pas bloquer l'affichage si l'historique échoue
            print(f"[scan] save_scan a échoué: {e}")

        if hasattr(self.app, "pages") and "dashboard" in self.app.pages:
            t = get_theme()
            self.app.pages["dashboard"].log_activity(f"Scan {result.hosts_up} hôtes · {len(vulns)} vulns",
                                                      t.success if not vulns else t.warning)
        messagebox.showinfo("Scan terminé",
            f"Hôtes actifs : {result.hosts_up}\nPorts ouverts : {result.total_open_ports}\n"
            f"Vulnérabilités : {len(vulns)}\n  • Critiques : {vr['stats']['critical']}\n"
            f"  • Hautes    : {vr['stats']['high']}\nDurée : {result.duration:.1f}s")

    def on_scan_error(self, error):
        self.is_scanning = False; self.scan_btn.configure(state="normal"); self.cancel_btn.configure(state="disabled")
        self.progress_label.configure(text=f"Erreur : {error}"); messagebox.showerror("Erreur de scan", error)

    def show_host_details(self, event):
        sel = self.results_tree.selection()
        if not sel: return
        ip = self.results_tree.item(sel[0])["values"][1]
        if self.scan_result:
            for host in self.scan_result.hosts:
                if host.ip == ip: self._host_dialog(host); break

    def _host_dialog(self, host: HostResult):
        t = get_theme()
        dlg = ctk.CTkToplevel(self); dlg.title(f"Hôte — {host.ip}"); dlg.geometry("640x520")
        dlg.transient(self); dlg.grab_set()
        hdr = ctk.CTkFrame(dlg, fg_color=t.bg_card, corner_radius=0); hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text=f"🖥️  {host.ip}", font=("Segoe UI", 18, "bold")).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text=host.hostname or "Hostname inconnu", font=("Segoe UI", 12), text_color=t.text_muted).pack(side="left")
        info = ctk.CTkFrame(dlg, fg_color=t.bg_secondary, corner_radius=0); info.pack(fill="x")
        ig = ctk.CTkFrame(info, fg_color="transparent"); ig.pack(fill="x", padx=20, pady=12)
        for label, val in [("OS détecté", host.os_guess or "Inconnu"), ("MAC", host.mac or "N/A"),
                           ("Latence", f"{host.response_time:.1f} ms"), ("Ports ouverts", str(len(host.ports)))]:
            col = ctk.CTkFrame(ig, fg_color="transparent"); col.pack(side="left", padx=20)
            ctk.CTkLabel(col, text=label, font=("Segoe UI", 10), text_color=t.text_muted).pack(anchor="w")
            ctk.CTkLabel(col, text=val, font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ctk.CTkLabel(dlg, text="Ports ouverts", font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=20, pady=(14, 4))
        pt = ctk.CTkTextbox(dlg, fg_color=t.bg_secondary, font=("Consolas", 11))
        pt.pack(fill="both", expand=True, padx=20, pady=(0, 8))
        dangerous = {21,22,23,25,80,443,445,3306,3389,5432,6379,27017,9200}
        for p in host.ports:
            r = "⚠️ " if p.port in dangerous else "   "
            line = f"{r}{p.port:<6}/{p.protocol}  {p.service:<16}"
            if p.version: line += f"  [{p.version[:40]}]"
            if p.banner: line += f"  · {p.banner[:50]}"
            pt.insert("end", line + "\n")
        ctk.CTkButton(dlg, text="Fermer", height=36, command=dlg.destroy).pack(pady=(0, 14))
