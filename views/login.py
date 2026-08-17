"""SENTRISCOPE — LoginWindow"""
import os
import customtkinter as ctk
from modules.database import db
from widgets.base import get_theme


class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.user = None
        self.title("SENTRISCOPE - Connexion")
        self.geometry("500x650")
        self.resizable(False, False)
        theme = get_theme()
        self.configure(fg_color=theme.bg_primary)
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 500) // 2
        y = (self.winfo_screenheight() - 650) // 2
        self.geometry(f"500x650+{x}+{y}")
        self.setup_ui()

    def setup_ui(self):
        theme = get_theme()
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(expand=True, fill="both", padx=50, pady=40)

        try:
            from PIL import Image
            logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "logo.png")
            logo_image = Image.open(logo_path)
            logo_ctk = ctk.CTkImage(light_image=logo_image, dark_image=logo_image, size=(140, 140))
            ctk.CTkLabel(container, image=logo_ctk, text="").pack(pady=(10, 20))
        except Exception:
            ctk.CTkLabel(container, text="🛡️", font=("Segoe UI Emoji", 60)).pack(pady=(10, 20))

        ctk.CTkLabel(container, text="SENTRISCOPE", font=("Segoe UI", 32, "bold"), text_color=theme.accent).pack()
        ctk.CTkLabel(container, text="Security Audit Platform", font=("Segoe UI", 13), text_color=theme.text_muted).pack(pady=(4, 30))

        form = ctk.CTkFrame(container, fg_color=theme.bg_card, corner_radius=20)
        form.pack(fill="x", pady=10)
        fi = ctk.CTkFrame(form, fg_color="transparent")
        fi.pack(fill="x", padx=30, pady=30)

        ctk.CTkLabel(fi, text="Nom d'utilisateur", font=("Segoe UI", 13), text_color=theme.text_secondary).pack(anchor="w", pady=(0, 8))
        self.username_entry = ctk.CTkEntry(fi, height=48, font=("Segoe UI", 14), corner_radius=12,
                                            border_width=1, fg_color=theme.bg_secondary, border_color=theme.border,
                                            placeholder_text="Entrez votre nom d'utilisateur")
        self.username_entry.pack(fill="x")
        self.username_entry.insert(0, "admin")

        ctk.CTkLabel(fi, text="Mot de passe", font=("Segoe UI", 13), text_color=theme.text_secondary).pack(anchor="w", pady=(20, 8))
        self.password_entry = ctk.CTkEntry(fi, height=48, show="•", font=("Segoe UI", 14), corner_radius=12,
                                            border_width=1, fg_color=theme.bg_secondary, border_color=theme.border,
                                            placeholder_text="Entrez votre mot de passe")
        self.password_entry.pack(fill="x")
        self.password_entry.bind("<Return>", lambda e: self.login())

        self.error_label = ctk.CTkLabel(fi, text="", font=("Segoe UI", 12), text_color=theme.danger)
        self.error_label.pack(pady=(15, 0))

        ctk.CTkButton(fi, text="Se connecter", font=("Segoe UI", 15, "bold"), height=50, corner_radius=12,
                      fg_color=theme.accent, hover_color=theme.accent_dark, command=self.login).pack(fill="x", pady=(20, 0))

        ctk.CTkLabel(container, text="Compte par défaut: admin / admin",
                     font=("Segoe UI", 11), text_color=theme.text_muted).pack(pady=(25, 0))

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.error_label.configure(text="Veuillez remplir tous les champs")
            return
        user = db.authenticate(username, password)
        if user:
            self.user = user
            self.destroy()
        else:
            self.error_label.configure(text="❌ Identifiants incorrects")
            self.password_entry.delete(0, "end")
