"""SENTRISCOPE — NavButton et CustomTreeview"""
import customtkinter as ctk
from tkinter import ttk
from typing import Callable, List
from widgets.base import get_theme


class NavButton(ctk.CTkButton):
    def __init__(self, parent, text: str, icon: str = "", command: Callable = None, **kw):
        t = get_theme()
        super().__init__(parent, text=f"  {icon}  {text}", font=("Segoe UI", 13),
                         height=40, anchor="w", fg_color="transparent",
                         text_color=t.text_secondary, hover_color=t.bg_hover,
                         corner_radius=8, command=command, **kw)
        self.active = False
        self._badge_count = 0

    def set_active(self, active: bool):
        t = get_theme()
        self.active = active
        self.configure(fg_color=t.accent if active else "transparent",
                       text_color="#ffffff" if active else t.text_secondary)

    def set_badge(self, count: int):
        self._badge_count = count
        base = self.cget("text").split(" 🔴")[0]
        self.configure(text=f"{base} 🔴{count}" if count > 0 else base)


class NavSeparator(ctk.CTkFrame):
    def __init__(self, parent, label: str = ""):
        t = get_theme()
        super().__init__(parent, fg_color="transparent")
        if label:
            ctk.CTkLabel(self, text=label.upper(), font=("Segoe UI", 9, "bold"),
                         text_color=t.text_muted).pack(anchor="w", padx=12, pady=(14, 2))
        else:
            ctk.CTkFrame(self, fg_color=t.border, height=1).pack(fill="x", padx=12, pady=8)


class CustomTreeview(ttk.Treeview):
    def __init__(self, parent, columns: List[str], **kw):
        t = get_theme()
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Custom.Treeview", background=t.bg_card, foreground=t.text_primary,
                     fieldbackground=t.bg_card, borderwidth=0, rowheight=40,
                     font=("Segoe UI", 11))
        s.configure("Custom.Treeview.Heading", background=t.bg_secondary,
                     foreground=t.text_muted, borderwidth=0, relief="flat",
                     font=("Segoe UI", 10, "bold"), padding=(10, 8))
        s.map("Custom.Treeview", background=[("selected", t.accent)],
              foreground=[("selected", "#ffffff")])
        s.map("Custom.Treeview.Heading", background=[("active", t.bg_secondary)])
        s.layout("Custom.Treeview", [("Custom.Treeview.treearea", {"sticky": "nswe"})])
        super().__init__(parent, columns=columns, show="headings",
                         style="Custom.Treeview", **kw)
        sb = ctk.CTkScrollbar(parent, command=self.yview, width=12)
        sb.pack(side="right", fill="y")
        self.configure(yscrollcommand=sb.set)
