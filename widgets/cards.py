"""SENTRISCOPE — Cartes de statistiques"""
import customtkinter as ctk
from widgets.base import get_theme


class StatsCard(ctk.CTkFrame):
    def __init__(self, parent, title: str, value: str = "0",
                 color: str = None, icon: str = "", subtitle: str = ""):
        t = get_theme()
        super().__init__(parent, fg_color=t.bg_card, corner_radius=14)
        self.color = color or t.accent
        ctk.CTkFrame(self, fg_color=self.color, width=4, corner_radius=0).pack(side="left", fill="y")
        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        top = ctk.CTkFrame(inner, fg_color="transparent")
        top.pack(fill="x")
        if icon:
            ctk.CTkLabel(top, text=icon, font=("Segoe UI Emoji", 16),
                         text_color=self.color).pack(side="left")
        ctk.CTkLabel(top, text=f"  {title}" if icon else title, font=("Segoe UI", 11),
                     text_color=t.text_muted).pack(side="left")
        self.value_label = ctk.CTkLabel(inner, text=value, font=("Segoe UI", 30, "bold"),
                                        text_color=self.color)
        self.value_label.pack(anchor="w", pady=(4, 0))
        self.sub_label = None
        if subtitle:
            self.sub_label = ctk.CTkLabel(inner, text=subtitle, font=("Segoe UI", 10),
                                          text_color=t.text_muted)
            self.sub_label.pack(anchor="w")

    def set_value(self, value: str, subtitle: str = ""):
        self.value_label.configure(text=value)
        if subtitle and self.sub_label:
            self.sub_label.configure(text=subtitle)

    def set_color(self, color: str):
        self.color = color
        self.value_label.configure(text_color=color)

    def flash(self):
        orig = self.cget("fg_color")
        self.configure(fg_color=self.color)
        self.after(120, lambda: self.configure(fg_color=orig))


class ProgressCard(ctk.CTkFrame):
    def __init__(self, parent, title: str, color: str = None, icon: str = ""):
        t = get_theme()
        super().__init__(parent, fg_color=t.bg_card, corner_radius=14)
        self.color = color or t.accent
        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        hdr = ctk.CTkFrame(inner, fg_color="transparent")
        hdr.pack(fill="x")
        if icon:
            ctk.CTkLabel(hdr, text=icon, font=("Segoe UI Emoji", 13),
                         text_color=self.color).pack(side="left")
        ctk.CTkLabel(hdr, text=f"  {title}" if icon else title, font=("Segoe UI", 11),
                     text_color=t.text_muted).pack(side="left")
        self.percent_label = ctk.CTkLabel(hdr, text="0%", font=("Segoe UI", 11, "bold"),
                                          text_color=self.color)
        self.percent_label.pack(side="right")
        self.value_label = ctk.CTkLabel(inner, text="0", font=("Segoe UI", 22, "bold"),
                                        text_color=self.color)
        self.value_label.pack(anchor="w", pady=(6, 6))
        self.progress = ctk.CTkProgressBar(inner, height=6, corner_radius=3,
                                           progress_color=self.color, fg_color=t.bg_secondary)
        self.progress.pack(fill="x")
        self.progress.set(0)

    def set_value(self, value: str, percent: float = 0):
        pct = max(0.0, min(100.0, percent))
        self.value_label.configure(text=value)
        self.percent_label.configure(text=f"{pct:.0f}%")
        self.progress.set(pct / 100)
        c = "#ef4444" if pct > 85 else "#f59e0b" if pct > 65 else self.color
        self.percent_label.configure(text_color=c)
        self.progress.configure(progress_color=c)
