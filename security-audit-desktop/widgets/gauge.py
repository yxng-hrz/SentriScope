"""SENTRISCOPE — Jauge de score de sécurité"""
import customtkinter as ctk
from widgets.base import get_theme


class SecurityScoreGauge(ctk.CTkFrame):
    def __init__(self, parent, size: int = 200):
        t = get_theme()
        super().__init__(parent, fg_color=t.bg_card, corner_radius=16)
        self.size, self.theme = size, t
        from tkinter import Canvas
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(container, text="Score de Sécurité", font=("Segoe UI", 14),
                     text_color=t.text_muted).pack(pady=(0, 10))
        cs = size + 20
        self.canvas = Canvas(container, width=cs, height=cs, bg=t.bg_card, highlightthickness=0)
        self.canvas.pack()
        self.score_label = ctk.CTkLabel(container, text="100", font=("Segoe UI", 42, "bold"),
                                        text_color=t.success)
        self.score_label.place(relx=0.5, rely=0.55, anchor="center")
        self.status_label = ctk.CTkLabel(container, text="Excellent", font=("Segoe UI", 13),
                                         text_color=t.text_secondary)
        self.status_label.pack(pady=(10, 0))
        self.draw_gauge(100)

    def _color(self, s):
        if s >= 80: return self.theme.success
        if s >= 60: return "#22d3ee"
        if s >= 40: return self.theme.warning
        return self.theme.danger

    def _status(self, s):
        if s >= 90: return "Excellent"
        if s >= 80: return "Très bon"
        if s >= 60: return "Acceptable"
        if s >= 40: return "À risque"
        return "Critique"

    def draw_gauge(self, score: int):
        self.canvas.delete("all")
        c = (self.size + 20) // 2
        r, th = self.size // 2 - 10, 12
        self.canvas.create_arc(c-r, c-r, c+r, c+r, start=135, extent=270,
                               style="arc", outline=self.theme.bg_secondary, width=th)
        color = self._color(score)
        ext = (score / 100) * 270
        if ext > 0:
            self.canvas.create_arc(c-r, c-r, c+r, c+r, start=135, extent=ext,
                                   style="arc", outline=color, width=th)
        self.score_label.configure(text=str(score), text_color=color)
        self.status_label.configure(text=self._status(score))

    def set_score(self, score: int):
        self.draw_gauge(max(0, min(100, score)))

    def calculate_from_vulns(self, vulns: list) -> int:
        if not vulns:
            self.set_score(100); return 100
        w = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3, 'info': 1}
        score = max(0, 100 - sum(w.get(getattr(v, 'severity', 'low'), 3) for v in vulns))
        self.set_score(score); return score
