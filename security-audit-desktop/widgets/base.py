"""SENTRISCOPE — Widgets de base partagés"""
import customtkinter as ctk
from modules.config import theme_manager


def get_theme():
    return theme_manager.get_theme()


class BasePage(ctk.CTkFrame):
    """Classe de base pour toutes les pages."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.setup_ui()

    def setup_ui(self):
        pass

    def on_show(self):
        pass

    def on_hide(self):
        pass

    def create_section(self, title: str, parent=None,
                       action_text: str = "", action_cmd=None) -> ctk.CTkFrame:
        t = get_theme()
        section = ctk.CTkFrame(parent or self, fg_color=t.bg_card, corner_radius=14)
        hdr = ctk.CTkFrame(section, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(16, 0))
        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left")
        ctk.CTkFrame(left, fg_color=t.accent, width=3, height=18, corner_radius=2).pack(side="left")
        ctk.CTkLabel(left, text=f"  {title}", font=("Segoe UI", 15, "bold"),
                     text_color=t.text_primary).pack(side="left")
        if action_text and action_cmd:
            ctk.CTkButton(hdr, text=action_text, height=28, font=("Segoe UI", 11),
                          fg_color=t.bg_secondary, hover_color=t.bg_hover,
                          command=action_cmd).pack(side="right")
        ctk.CTkFrame(section, height=1, fg_color=t.border).pack(fill="x", padx=20, pady=(12, 12))
        return section

    def page_header(self, title: str, subtitle: str = "") -> ctk.CTkFrame:
        t = get_theme()
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 18))
        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left")
        ctk.CTkLabel(left, text=title, font=("Segoe UI", 26, "bold"),
                     text_color=t.text_primary).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(left, text=subtitle, font=("Segoe UI", 12),
                         text_color=t.text_muted).pack(anchor="w")
        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right")
        return right

    def make_badge(self, parent, text: str, color: str) -> ctk.CTkLabel:
        return ctk.CTkLabel(parent, text=f" {text} ", font=("Segoe UI", 10, "bold"),
                            fg_color=color, corner_radius=4, text_color="#ffffff")

    def empty_state(self, parent, icon: str, text: str):
        t = get_theme()
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(expand=True, pady=50)
        ctk.CTkLabel(f, text=icon, font=("Segoe UI Emoji", 36)).pack()
        ctk.CTkLabel(f, text=text, font=("Segoe UI", 13), text_color=t.text_muted).pack(pady=(8, 0))
        return f
