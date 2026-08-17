"""SENTRISCOPE — ProcessesPage"""
import os, webbrowser
import customtkinter as ctk
from tkinter import messagebox
from modules import ProcessMonitor, ReportGenerator
from widgets.base import BasePage, get_theme
from widgets.cards import StatsCard
from widgets.nav import CustomTreeview
from widgets.helpers import setup_tree_columns

class ProcessesPage(BasePage):
    def setup_ui(self):
        t = get_theme()
        self.auto_refresh = False
        self.processes_data = []

        header = ctk.CTkFrame(self, fg_color="transparent"); header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="Processus Système", font=("", 28, "bold")).pack(side="left")
        bf = ctk.CTkFrame(header, fg_color="transparent"); bf.pack(side="right")
        ctk.CTkButton(bf, text="📥 Export CSV", font=("", 12), height=35, fg_color=t.success,
                      hover_color="#059669", command=self.export_csv).pack(side="left", padx=5)
        self.auto_btn = ctk.CTkButton(bf, text="🔄 Auto: OFF", font=("", 12), height=35,
                                       fg_color=t.bg_card, command=self.toggle_auto_refresh)
        self.auto_btn.pack(side="left", padx=5)
        ctk.CTkButton(bf, text="🔃 Actualiser", font=("", 12), height=35, fg_color=t.accent,
                      command=self.refresh_processes).pack(side="left")

        sf = ctk.CTkFrame(self, fg_color=t.bg_card, corner_radius=10); sf.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(sf, text="Trier par:", font=("", 12)).pack(side="left", padx=15, pady=10)
        self.sort_combo = ctk.CTkComboBox(sf, values=["CPU","Mémoire","Connexions","Nom"],
                                          width=120, state="readonly", command=lambda _: self.refresh_processes())
        self.sort_combo.pack(side="left", padx=5); self.sort_combo.set("CPU")
        self.search_entry = ctk.CTkEntry(sf, placeholder_text="Rechercher processus...", width=200)
        self.search_entry.pack(side="left", padx=10, pady=10)
        self.search_entry.bind("<Return>", lambda e: self.refresh_processes())

        ts = self.create_section("📋 Processus"); ts.pack(fill="both", expand=True)
        tf = ctk.CTkFrame(ts, fg_color="transparent"); tf.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        cols = ("pid","name","user","cpu","memory","conn","threads","status")
        self.proc_tree = CustomTreeview(tf, cols)
        setup_tree_columns(self.proc_tree, {
            "pid":("PID",70), "name":("Nom",200), "user":("Utilisateur",100), "cpu":("CPU %",70),
            "memory":("Mémoire",100), "conn":("Connexions",80), "threads":("Threads",70), "status":("Statut",80)})
        self.proc_tree.pack(fill="both", expand=True)

    def on_show(self): self.refresh_processes()

    def toggle_auto_refresh(self):
        t = get_theme(); self.auto_refresh = not self.auto_refresh
        if self.auto_refresh:
            self.auto_btn.configure(text="🔄 Auto: ON", fg_color=t.success); self.auto_refresh_loop()
        else:
            self.auto_btn.configure(text="🔄 Auto: OFF", fg_color=t.bg_card)

    def auto_refresh_loop(self):
        if self.auto_refresh and self.winfo_exists(): self.refresh_processes(); self.after(3000, self.auto_refresh_loop)

    def refresh_processes(self):
        for item in self.proc_tree.get_children(): self.proc_tree.delete(item)
        sort_map = {"CPU":"cpu", "Mémoire":"memory", "Connexions":"connections", "Nom":"name"}
        processes = ProcessMonitor.get_processes(sort_by=sort_map.get(self.sort_combo.get(), "cpu"),
                                                 limit=100, interval=0.1)
        search = self.search_entry.get().lower()
        self.processes_data = []
        for p in processes:
            if search and search not in p.name.lower(): continue
            self.processes_data.append(p)
            self.proc_tree.insert("", "end", values=(
                p.pid, p.name[:30], p.username[:15], f"{p.cpu_percent:.1f}%",
                f"{p.memory_mb:.1f} MB", p.connections, p.threads, p.status))

    def export_csv(self):
        if not self.processes_data:
            messagebox.showwarning("Attention", "Aucun processus à exporter.\nActualisez d'abord la liste."); return
        try:
            fp = ReportGenerator().export_processes_csv(self.processes_data)
            messagebox.showinfo("Export réussi", f"Processus exportés vers:\n{fp}")
            webbrowser.open(f"file://{os.path.dirname(fp)}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export:\n{e}")
