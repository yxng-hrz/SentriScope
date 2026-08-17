#!/usr/bin/env python3
"""SENTRISCOPE"""
import os, sys
from typing import Optional, Dict, List
import customtkinter as ctk
from tkinter import messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import db, User
from modules.config import theme_manager
from widgets import BasePage, get_theme, NavButton
from widgets.nav import NavSeparator
from views import LoginWindow

ctk.set_appearance_mode("dark" if theme_manager.is_dark() else "light")
ctk.set_default_color_theme("blue")


class SecurityAuditApp(ctk.CTk):
    def __init__(self, user: User):
        super().__init__()
        self.current_user = user
        self.scan_result = None
        self.vulnerabilities: List = []
        self.current_page: Optional[str] = None

        self.title("SENTRISCOPE")
        self.geometry("1550x920")
        self.minsize(1200, 700)

        theme = get_theme()
        self.configure(fg_color=theme.bg_primary)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        self.main_container = ctk.CTkFrame(self, fg_color=theme.bg_primary, corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nsew")

        self.pages: Dict[str, BasePage] = {}
        self._page_registry: Dict[str, tuple] = {}
        self._register_pages()
        self.show_page("dashboard")

    def _build_sidebar(self):
        theme = get_theme()
        self.sidebar = ctk.CTkFrame(self, width=260, fg_color=theme.bg_secondary, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Logo
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=16, pady=(20, 14))
        try:
            from PIL import Image
            lp = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
            img = ctk.CTkImage(light_image=Image.open(lp), size=(40, 40))
            ctk.CTkLabel(logo_frame, image=img, text="").pack(side="left")
        except Exception:
            ctk.CTkLabel(logo_frame, text="🛡️", font=("Segoe UI Emoji", 32)).pack(side="left")

        tf = ctk.CTkFrame(logo_frame, fg_color="transparent")
        tf.pack(side="left", padx=10)
        ctk.CTkLabel(tf, text="SENTRISCOPE", font=("Segoe UI", 16, "bold"),
                     text_color=theme.accent).pack(anchor="w")
        ctk.CTkLabel(tf, text="Security Platform", font=("Segoe UI", 10),
                     text_color=theme.text_muted).pack(anchor="w")

        # User badge
        uf = ctk.CTkFrame(self.sidebar, fg_color=theme.bg_card, corner_radius=10)
        uf.pack(fill="x", padx=14, pady=(0, 12))
        uc = ctk.CTkFrame(uf, fg_color="transparent")
        uc.pack(fill="x", padx=14, pady=10)
        av = ctk.CTkFrame(uc, fg_color=theme.accent, width=32, height=32, corner_radius=16)
        av.pack(side="left"); av.pack_propagate(False)
        ctk.CTkLabel(av, text=self.current_user.username[0].upper(),
                     font=("Segoe UI", 14, "bold"), text_color="#ffffff").place(relx=0.5, rely=0.5, anchor="center")
        ui = ctk.CTkFrame(uc, fg_color="transparent")
        ui.pack(side="left", padx=10)
        ctk.CTkLabel(ui, text=self.current_user.username, font=("Segoe UI", 12, "bold"),
                     text_color=theme.text_primary).pack(anchor="w")
        ctk.CTkLabel(ui, text="Connecté", font=("Segoe UI", 9),
                     text_color=theme.text_muted).pack(anchor="w")
        ctk.CTkFrame(uc, fg_color=theme.success, width=8, height=8, corner_radius=4).pack(side="right")

        ctk.CTkFrame(self.sidebar, fg_color=theme.border, height=1).pack(fill="x", padx=14)

        # Nav
        nav = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent")
        nav.pack(fill="both", expand=True, padx=8, pady=6)
        self.nav_buttons: Dict[str, NavButton] = {}

        groups = [
            ("Général", [("dashboard", "Dashboard", "📊")]),
            ("Réseau", [("scan", "Scan Réseau", "🔍"), ("monitor", "Monitoring", "📡"),
                        ("connections", "Connexions", "🔗"), ("interfaces", "Interfaces", "🔌")]),
            ("Sécurité", [("vulnerabilities", "Vulnérabilités", "⚠️"), ("ids", "IDS / Alertes", "🚨"),
                          ("password_policy", "Password Policy", "🔐"), ("processes", "Processus", "⚙️")]),
            ("Rapports & Conformité", [("reports", "Rapports", "📄"), ("compliance", "Conformité", "📋")]),
        ]
        for group_label, items in groups:
            NavSeparator(nav, group_label).pack(fill="x")
            for pid, label, icon in items:
                btn = NavButton(nav, text=label, icon=icon,
                                command=lambda p=pid: self.show_page(p))
                btn.pack(fill="x", pady=1)
                self.nav_buttons[pid] = btn

        ctk.CTkFrame(self.sidebar, fg_color=theme.border, height=1).pack(fill="x", padx=14)
        bottom = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bottom.pack(fill="x", padx=8, pady=6)
        btn_s = NavButton(bottom, text="Paramètres", icon="⚙️",
                          command=lambda: self.show_page("settings"))
        btn_s.pack(fill="x", pady=1)
        self.nav_buttons["settings"] = btn_s
        ctk.CTkButton(bottom, text="🚪  Déconnexion", font=("Segoe UI", 12), height=36,
                      corner_radius=8, fg_color="transparent", hover_color="#7f1d1d",
                      text_color=theme.text_muted, border_width=1, border_color=theme.border,
                      command=self.logout).pack(fill="x", padx=0, pady=(4, 8))

        self._sys_lbl = ctk.CTkLabel(self.sidebar, text="", font=("Segoe UI", 9),
                                     text_color=theme.text_muted)
        self._sys_lbl.pack(pady=(0, 8))
        self._update_sys()

    def logout(self):
        if messagebox.askyesno("Déconnexion", "Voulez-vous vous déconnecter ?"):
            self.destroy(); main()

    def _update_sys(self):
        try:
            from modules import SystemMonitor
            cpu = SystemMonitor.get_cpu_info()
            mem = SystemMonitor.get_memory_info()
            self._sys_lbl.configure(text=f"CPU {cpu['percent']:.0f}%  ·  RAM {mem['percent']:.0f}%")
        except Exception: pass
        if self.winfo_exists():
            self.after(5000, self._update_sys)  # 5s instead of 3s

    def _register_pages(self):
        self._page_registry = {
            "dashboard": ("views.dashboard", "DashboardPage"),
            "scan": ("views.scan", "ScanPage"),
            "monitor": ("views.monitor", "MonitorPage"),
            "connections": ("views.connections", "ConnectionsPage"),
            "processes": ("views.processes", "ProcessesPage"),
            "vulnerabilities": ("views.vulnerabilities", "VulnerabilitiesPage"),
            "ids": ("views.ids", "IDSPage"),
            "interfaces": ("views.interfaces", "InterfacesPage"),
            "password_policy": ("views.password_policy", "PasswordPolicyPage"),
            "reports": ("views.reports", "ReportsPage"),
            "compliance": ("views.compliance", "CompliancePage"),
            "settings": ("views.settings", "SettingsPage"),
        }

    def _get_page(self, page_id: str) -> Optional[BasePage]:
        if page_id in self.pages:
            return self.pages[page_id]
        if page_id not in self._page_registry:
            return None
        mod_path, cls_name = self._page_registry[page_id]
        import importlib
        mod = importlib.import_module(mod_path)
        page = getattr(mod, cls_name)(self.main_container, self)
        self.pages[page_id] = page
        return page

    def show_page(self, page_id: str):
        page = self._get_page(page_id)
        if page is None: return
        if self.current_page:
            prev = self.pages.get(self.current_page)
            if prev:
                prev.pack_forget(); prev.on_hide()
            if self.current_page in self.nav_buttons:
                self.nav_buttons[self.current_page].set_active(False)
        self.current_page = page_id
        page.pack(fill="both", expand=True, padx=12, pady=12)
        page.on_show()
        if page_id in self.nav_buttons:
            self.nav_buttons[page_id].set_active(True)

    def get_stats(self) -> Dict:
        hosts = ports = 0
        if self.scan_result:
            hosts = getattr(self.scan_result, "hosts_up", 0)
            ports = getattr(self.scan_result, "total_open_ports", 0)
        vulns = len(self.vulnerabilities)
        critical = sum(1 for v in self.vulnerabilities if v.severity == "critical")
        return {"hosts": hosts, "ports": ports, "vulns": vulns, "critical": critical}

    def update_scan_results(self, scan_result, vulnerabilities):
        self.scan_result = scan_result
        self.vulnerabilities = vulnerabilities
        crit = sum(1 for v in vulnerabilities if v.severity == "critical")
        if "vulnerabilities" in self.nav_buttons and crit > 0:
            self.nav_buttons["vulnerabilities"].set_badge(crit)
        if "dashboard" in self.pages:
            self.pages["dashboard"].update_stats()
        if "vulnerabilities" in self.pages:
            self.pages["vulnerabilities"].refresh_vulnerabilities()

    def export_report(self):
        if not self.scan_result:
            messagebox.showwarning("Attention", "Lancez d'abord un scan.")
            return
        self.show_page("reports")


def main():
    login = LoginWindow()
    login.mainloop()
    if login.user:
        app = SecurityAuditApp(login.user)
        app.mainloop()


if __name__ == "__main__":
    main()
