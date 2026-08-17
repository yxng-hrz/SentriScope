"""SENTRISCOPE — MonitorPage"""
import customtkinter as ctk
from modules import NetworkMonitor
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard
from widgets.helpers import fmt_bytes

class MonitorPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        self.monitor = NetworkMonitor(history_size=60)
        self.is_monitoring = False

        header = ctk.CTkFrame(self, fg_color="transparent"); header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="Monitoring Réseau", font=("", 28, "bold")).pack(side="left")
        self.status_label = ctk.CTkLabel(header, text="⏹️ Arrêté", font=("", 14), text_color=t.text_secondary)
        self.status_label.pack(side="right")
        self.toggle_btn = ctk.CTkButton(header, text="▶️  Démarrer", font=("", 14), height=40,
                                         fg_color=t.success, command=self.toggle_monitoring)
        self.toggle_btn.pack(side="right", padx=10)

        sf = ctk.CTkFrame(self, fg_color="transparent"); sf.pack(fill="x", pady=(0, 20))
        sf.grid_columnconfigure((0,1,2,3), weight=1)
        self.stat_download = StatsCard(sf, "Download", "0 B/s", t.success, "⬇️")
        self.stat_upload = StatsCard(sf, "Upload", "0 B/s", t.warning, "⬆️")
        self.stat_packets_in = StatsCard(sf, "Paquets In", "0/s", t.info, "📥")
        self.stat_packets_out = StatsCard(sf, "Paquets Out", "0/s", t.accent, "📤")
        for i, c in enumerate([self.stat_download, self.stat_upload, self.stat_packets_in, self.stat_packets_out]):
            c.grid(row=0, column=i, padx=5, sticky="nsew")

        hs = self.create_section("📊 Historique du Trafic"); hs.pack(fill="both", expand=True)
        self.history_text = ctk.CTkTextbox(hs, fg_color=t.bg_secondary, font=("Consolas", 11))
        self.history_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        hdr_line = f"{'Temps':<12} {'Download':<15} {'Upload':<15} {'Pkt In':<12} {'Pkt Out':<12} {'Erreurs':<10}"
        self.history_text.insert("1.0", hdr_line + "\n" + "=" * 80 + "\n")

    def toggle_monitoring(self):
        (self.stop_monitoring if self.is_monitoring else self.start_monitoring)()

    def start_monitoring(self):
        t = get_theme()
        self.is_monitoring = True
        self.toggle_btn.configure(text="⏹️  Arrêter", fg_color=t.danger)
        self.status_label.configure(text="🟢 En cours", text_color=t.success)
        self.monitor.add_callback(self.on_stats_update); self.monitor.start(interval=1.0)

    def stop_monitoring(self):
        t = get_theme()
        self.is_monitoring = False
        self.toggle_btn.configure(text="▶️  Démarrer", fg_color=t.success)
        self.status_label.configure(text="⏹️ Arrêté", text_color=t.text_secondary)
        self.monitor.remove_callback(self.on_stats_update); self.monitor.stop()

    def on_stats_update(self, stats):
        def update():
            if not self.winfo_exists(): return
            self.stat_download.set_value(fmt_bytes(stats.bytes_recv_rate))
            self.stat_upload.set_value(fmt_bytes(stats.bytes_sent_rate))
            self.stat_packets_in.set_value(f"{stats.packets_recv_rate:.0f}/s")
            self.stat_packets_out.set_value(f"{stats.packets_sent_rate:.0f}/s")
            line = (f"{stats.timestamp:<12} {fmt_bytes(stats.bytes_recv_rate):<15} "
                    f"{fmt_bytes(stats.bytes_sent_rate):<15} "
                    f"{stats.packets_recv_rate:<12.0f} {stats.packets_sent_rate:<12.0f} "
                    f"{stats.errors_in + stats.errors_out:<10}")
            self.history_text.insert("end", line + "\n"); self.history_text.see("end")
            # Trim : on garde les 2 premières lignes (header + séparateur)
            # et on supprime les plus anciennes lignes de données dès que
            # le buffer dépasse MAX_LINES, sans jamais cibler une ligne fixe.
            MAX_LINES = 100
            HEADER_LINES = 2
            total_lines = int(self.history_text.index('end-1c').split('.')[0])
            data_lines = total_lines - HEADER_LINES
            while data_lines > MAX_LINES:
                start = f"{HEADER_LINES + 1}.0"
                end   = f"{HEADER_LINES + 2}.0"
                self.history_text.delete(start, end)
                total_lines = int(self.history_text.index('end-1c').split('.')[0])
                data_lines = total_lines - HEADER_LINES
        self.after(0, update)
