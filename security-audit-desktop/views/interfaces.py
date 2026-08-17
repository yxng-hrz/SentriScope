"""SENTRISCOPE — InterfacesPage"""
from typing import Dict
import customtkinter as ctk
from modules import InterfaceMonitor
from widgets.base import BasePage, get_theme
from widgets.helpers import fmt_size

class InterfacesPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        header = ctk.CTkFrame(self, fg_color="transparent"); header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="Interfaces Réseau", font=("", 28, "bold")).pack(side="left")
        ctk.CTkButton(header, text="🔃 Actualiser", font=("", 12), height=35, fg_color=t.accent,
                      command=self.refresh_interfaces).pack(side="right")
        self.cards_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.cards_frame.pack(fill="both", expand=True)

    def on_show(self): self.refresh_interfaces()

    def refresh_interfaces(self):
        for w in self.cards_frame.winfo_children(): w.destroy()
        for iface in InterfaceMonitor.get_interfaces(): self._iface_card(iface)

    def _iface_card(self, iface: Dict):
        t = get_theme()
        card = ctk.CTkFrame(self.cards_frame, fg_color=t.bg_card, corner_radius=15)
        card.pack(fill="x", pady=8, padx=5)
        hdr = ctk.CTkFrame(card, fg_color="transparent"); hdr.pack(fill="x", padx=20, pady=(20, 15))
        sc = t.success if iface['is_up'] else t.danger
        ctk.CTkLabel(hdr, text=f"🔌 {iface['name']}", font=("", 18, "bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="🟢 Actif" if iface['is_up'] else "🔴 Inactif",
                     font=("", 12), text_color=sc).pack(side="right")
        info = ctk.CTkFrame(card, fg_color="transparent"); info.pack(fill="x", padx=20, pady=(0, 20))
        info.grid_columnconfigure((0,1,2), weight=1)
        sections = [
            ("Adresses", [f"IPv4: {iface['ipv4'] or 'N/A'}", f"Masque: {iface['netmask'] or 'N/A'}", f"MAC: {iface['mac'] or 'N/A'}"]),
            ("Statistiques", [f"Reçu: {fmt_size(iface['bytes_recv'])}", f"Envoyé: {fmt_size(iface['bytes_sent'])}", f"Vitesse: {iface['speed']} Mbps"]),
            ("Configuration", [f"MTU: {iface['mtu']}", f"Duplex: {iface['duplex']}", f"Type: {'Loopback' if iface['name'] == 'lo' else 'Ethernet'}"]),
        ]
        for col_idx, (title, items) in enumerate(sections):
            col = ctk.CTkFrame(info, fg_color=t.bg_secondary, corner_radius=10)
            col.grid(row=0, column=col_idx, padx=5, sticky="nsew")
            ctk.CTkLabel(col, text=title, font=("", 12, "bold")).pack(anchor="w", padx=15, pady=(15, 5))
            for item in items:
                ctk.CTkLabel(col, text=item, font=("", 11), text_color=t.text_secondary).pack(anchor="w", padx=15)
            ctk.CTkFrame(col, height=15, fg_color="transparent").pack()
