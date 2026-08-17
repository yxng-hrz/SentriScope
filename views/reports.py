"""SENTRISCOPE — ReportsPage"""
import os, webbrowser
from datetime import datetime
import customtkinter as ctk
from tkinter import messagebox, filedialog

from modules import ReportGenerator
from widgets.base import BasePage, get_theme
class ReportsPage(BasePage):
    """Page de génération de rapports"""
    
    def setup_ui(self):
        self.report_gen = ReportGenerator()
        
        # Titre
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            header, text="Rapports",
            font=("", 28, "bold")
        ).pack(side="left")
        
        # Options d'export
        options_section = self.create_section("📄 Générer un Rapport")
        options_section.pack(fill="x", pady=(0, 20))
        
        # Format
        format_frame = ctk.CTkFrame(options_section, fg_color="transparent")
        format_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        ctk.CTkLabel(format_frame, text="Format:", font=("", 13)).pack(side="left")
        
        self.format_var = ctk.StringVar(value="pdf")
        
        formats = [
            ("PDF Technique", "pdf"),
            ("PDF Exécutif", "pdf_exec"),
            ("HTML", "html"),
            ("JSON", "json"),
            ("CSV", "csv"),
            ("Texte", "txt"),
        ]
        for text, value in formats:
            ctk.CTkRadioButton(
                format_frame, text=text,
                variable=self.format_var, value=value,
                font=("", 12)
            ).pack(side="left", padx=10)
        
        # Boutons
        btn_frame = ctk.CTkFrame(options_section, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkButton(
            btn_frame, text="📥 Exporter",
            font=("", 14, "bold"), height=45,
            fg_color=get_theme().success,
            command=self.export_report
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            btn_frame, text="📂 Ouvrir dossier rapports",
            font=("", 14), height=45,
            fg_color=get_theme().accent,
            command=self.open_reports_folder
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            btn_frame, text="📄 Tous les formats",
            font=("", 14), height=45,
            fg_color=get_theme().info,
            command=self.export_all_formats
        ).pack(side="left")
        
        # Aperçu
        preview_section = self.create_section("👁️ Aperçu des données")
        preview_section.pack(fill="both", expand=True)
        
        self.preview_text = ctk.CTkTextbox(
            preview_section, 
            fg_color=get_theme().bg_secondary,
            font=("Consolas", 11)
        )
        self.preview_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    
    def on_show(self):
        self.update_preview()
    
    def update_preview(self):
        """Mettre à jour l'aperçu"""
        self.preview_text.delete("1.0", "end")
        
        stats = self.app.get_stats()
        scan_result = self.app.scan_result
        vulns = self.app.vulnerabilities
        
        preview = f"""╔══════════════════════════════════════════════════════════════════╗
║                    APERÇU DU RAPPORT                              ║
╚══════════════════════════════════════════════════════════════════╝

📊 STATISTIQUES GLOBALES
────────────────────────────────────────────────────────────────────
  • Hôtes découverts:     {stats['hosts']}
  • Ports ouverts:        {stats['ports']}
  • Vulnérabilités:       {stats['vulns']}
    - Critiques:          {stats['critical']}
    - Hautes:             {len([v for v in vulns if v.severity == 'high'])}
    - Moyennes:           {len([v for v in vulns if v.severity == 'medium'])}
    - Basses:             {len([v for v in vulns if v.severity == 'low'])}

"""
        
        if scan_result and hasattr(scan_result, 'hosts'):
            preview += """📡 HÔTES DÉCOUVERTS
────────────────────────────────────────────────────────────────────
"""
            for host in scan_result.hosts[:10]:
                ports_str = ', '.join([str(p.port) for p in host.ports[:5]])
                if len(host.ports) > 5:
                    ports_str += f" (+{len(host.ports)-5})"
                preview += f"  {host.ip:<15} {host.hostname or 'N/A':<20} [{ports_str}]\n"
            
            if len(scan_result.hosts) > 10:
                preview += f"\n  ... et {len(scan_result.hosts) - 10} autres hôtes\n"
        
        if vulns:
            preview += """
⚠️ TOP VULNÉRABILITÉS
────────────────────────────────────────────────────────────────────
"""
            for vuln in sorted(vulns, key=lambda v: v.cvss, reverse=True)[:10]:
                preview += f"  [{vuln.severity.upper():<8}] {vuln.name:<30} (CVSS: {vuln.cvss})\n"
                preview += f"             └─ {vuln.host}:{vuln.port}\n"
        
        if not scan_result and not vulns:
            preview += """
ℹ️  Aucune donnée disponible. Lancez un scan réseau pour générer un rapport.
"""
        
        # Conformité
        try:
            from modules.compliance import compliance_manager
            comp = compliance_manager.get_summary()
            preview += f"""
📋 CONFORMITÉ
────────────────────────────────────────────────────────────────────
  Score global:    {comp['global_score']:.0f}%
  Maturité:        {comp.get('global_maturity', 0):.1f}/5
"""
            for fw in comp.get('frameworks', []):
                preview += f"  • {fw['name']:<14} {fw['score']:>5.0f}%   ({fw['compliant']}✅ {fw['partial']}⚠️ {fw['non_compliant']}❌)\n"
        except Exception:
            pass
        
        self.preview_text.insert("1.0", preview)
    
    def export_report(self):
        """Exporter le rapport"""
        format_type = self.format_var.get()
        
        if not self.app.scan_result:
            messagebox.showwarning("Attention", "Aucune donnée à exporter.\nLancez d'abord un scan.")
            return
        
        # Déterminer extension et type de fichier
        if format_type in ('pdf', 'pdf_exec'):
            ext = 'pdf'
            ft = [('PDF', '*.pdf')]
        else:
            ext = format_type
            ft = {
                'html': [('HTML', '*.html')],
                'json': [('JSON', '*.json')],
                'csv': [('CSV', '*.csv')],
                'txt': [('Texte', '*.txt')]
            }[format_type]
        
        tag = "executive" if format_type == 'pdf_exec' else format_type
        filepath = filedialog.asksaveasfilename(
            defaultextension=f".{ext}",
            filetypes=ft,
            initialfile=f"sentriscope_{tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if not filepath:
            return
        
        try:
            import shutil
            fname = os.path.basename(filepath)
            if format_type == 'pdf':
                generated = self.report_gen.generate_pdf_report(
                    self.app.scan_result, self.app.vulnerabilities,
                    fname, executive=False)
            elif format_type == 'pdf_exec':
                generated = self.report_gen.generate_pdf_report(
                    self.app.scan_result, self.app.vulnerabilities,
                    fname, executive=True)
            elif format_type == 'html':
                generated = self.report_gen.generate_html_report(
                    self.app.scan_result, self.app.vulnerabilities, fname)
            elif format_type == 'json':
                generated = self.report_gen.generate_json_report(
                    self.app.scan_result, self.app.vulnerabilities, fname)
            elif format_type == 'csv':
                generated = self.report_gen.generate_csv_report(
                    self.app.scan_result, self.app.vulnerabilities, fname)
            else:
                generated = self.report_gen.generate_txt_report(
                    self.app.scan_result, self.app.vulnerabilities, fname)

            if generated and os.path.abspath(generated) != os.path.abspath(filepath):
                shutil.copy2(generated, filepath)

            messagebox.showinfo("Succès", f"Rapport exporté:\n{filepath}")
            
        except ImportError:
            messagebox.showerror("Erreur",
                "reportlab n'est pas installé.\n"
                "Exécutez: pip install reportlab")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export:\n{e}")
    
    def export_all_formats(self):
        """Exporter dans tous les formats"""
        if not self.app.scan_result:
            messagebox.showwarning("Attention", "Aucune donnée à exporter.")
            return
        
        try:
            files = self.report_gen.generate_all_formats(
                self.app.scan_result, self.app.vulnerabilities
            )
            
            msg = "Rapports générés:\n\n"
            for fmt, path in files.items():
                msg += f"• {fmt.upper()}: {os.path.basename(path)}\n"
            
            messagebox.showinfo("Succès", msg)
            self.open_reports_folder()
            
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
    
    def open_reports_folder(self):
        """Ouvrir le dossier des rapports"""
        from modules.config import REPORTS_DIR
        
        if os.path.exists(REPORTS_DIR):
            webbrowser.open(f"file://{REPORTS_DIR}")
        else:
            messagebox.showwarning("Attention", "Le dossier n'existe pas encore.")
