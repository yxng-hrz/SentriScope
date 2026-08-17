"""
Module de Génération de Rapports — SENTRISCOPE
Formats: HTML, PDF, JSON, CSV, TXT
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import asdict
import html

from modules.config import REPORTS_DIR

_TOOL_NAME = "SENTRISCOPE v2.9"


def _get_stats(scan_result, vulnerabilities: List) -> Dict:
    """Statistiques communes à tous les formats."""
    return {
        'hosts_scanned': getattr(scan_result, 'hosts_scanned', 0),
        'hosts_up': getattr(scan_result, 'hosts_up', 0),
        'total_ports': getattr(scan_result, 'total_open_ports', 0),
        'total_vulns': len(vulnerabilities),
        'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
        'high': len([v for v in vulnerabilities if v.severity == 'high']),
        'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
        'low': len([v for v in vulnerabilities if v.severity == 'low']),
    }


def _risk_score(stats: Dict) -> int:
    return min(100, stats['critical'] * 25 + stats['high'] * 15 +
               stats['medium'] * 8 + stats['low'] * 3)


def _get_compliance_summary() -> Optional[Dict]:
    """Récupère le résumé de conformité (si disponible)."""
    try:
        from modules.compliance import compliance_manager
        return compliance_manager.get_summary()
    except Exception:
        return None


class ReportGenerator:
    """Générateur de rapports multi-format"""
    
    def __init__(self):
        self.reports_dir = REPORTS_DIR
    
    def generate_html_report(self, scan_result, vulnerabilities: List,
                            filename: str = None) -> str:
        """Générer un rapport HTML complet"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{timestamp}.html"
        
        filepath = self.reports_dir / filename
        
        # Statistiques
        stats = {
            'hosts_up': scan_result.hosts_up if hasattr(scan_result, 'hosts_up') else 0,
            'total_ports': scan_result.total_open_ports if hasattr(scan_result, 'total_open_ports') else 0,
            'total_vulns': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
            'high': len([v for v in vulnerabilities if v.severity == 'high']),
            'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
            'low': len([v for v in vulnerabilities if v.severity == 'low'])
        }
        
        # Score de risque
        risk_score = min(100, stats['critical'] * 25 + stats['high'] * 15 + 
                        stats['medium'] * 8 + stats['low'] * 3)
        
        risk_color = '#10b981' if risk_score < 30 else '#f59e0b' if risk_score < 60 else '#ef4444'
        
        html_content = f'''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Sécurité - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3e 100%);
            color: #e2e8f0;
            min-height: 100vh;
            padding: 40px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        .header {{
            text-align: center;
            padding: 40px;
            background: rgba(26, 26, 62, 0.8);
            border-radius: 20px;
            margin-bottom: 30px;
            border: 1px solid rgba(102, 126, 234, 0.3);
        }}
        .header h1 {{
            font-size: 2.5em;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        .header .date {{ color: #94a3b8; font-size: 1.1em; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(26, 26, 62, 0.9);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            border: 1px solid rgba(102, 126, 234, 0.3);
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-card .label {{ color: #94a3b8; }}
        
        .risk-score {{
            background: rgba(26, 26, 62, 0.9);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 30px;
            border: 1px solid rgba(102, 126, 234, 0.3);
        }}
        .risk-score .score {{
            font-size: 4em;
            font-weight: bold;
            color: {risk_color};
        }}
        .risk-bar {{
            width: 100%;
            height: 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            margin-top: 20px;
            overflow: hidden;
        }}
        .risk-bar-fill {{
            height: 100%;
            width: {risk_score}%;
            background: linear-gradient(90deg, #10b981, #f59e0b, #ef4444);
            border-radius: 10px;
            transition: width 1s;
        }}
        
        .section {{
            background: rgba(26, 26, 62, 0.9);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            border: 1px solid rgba(102, 126, 234, 0.3);
        }}
        .section h2 {{
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(102, 126, 234, 0.3);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(102, 126, 234, 0.2);
        }}
        th {{
            background: rgba(102, 126, 234, 0.2);
            font-weight: 600;
        }}
        tr:hover {{ background: rgba(102, 126, 234, 0.1); }}
        
        .badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge-critical {{ background: #ef4444; color: white; }}
        .badge-high {{ background: #f97316; color: white; }}
        .badge-medium {{ background: #f59e0b; color: black; }}
        .badge-low {{ background: #10b981; color: white; }}
        .badge-info {{ background: #3b82f6; color: white; }}
        
        .vuln-card {{
            background: rgba(10, 10, 26, 0.5);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}
        .vuln-card.critical {{ border-color: #ef4444; }}
        .vuln-card.high {{ border-color: #f97316; }}
        .vuln-card.medium {{ border-color: #f59e0b; }}
        .vuln-card.low {{ border-color: #10b981; }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .vuln-title {{ font-size: 1.1em; font-weight: 600; }}
        .vuln-meta {{ color: #94a3b8; font-size: 0.9em; margin-bottom: 10px; }}
        .vuln-desc {{ margin-bottom: 15px; line-height: 1.6; }}
        .vuln-recommendation {{
            background: rgba(102, 126, 234, 0.1);
            padding: 15px;
            border-radius: 8px;
        }}
        .vuln-recommendation strong {{ color: #667eea; }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #64748b;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{ background: white; color: black; }}
            .section {{ border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SENTRISCOPE — Rapport de Sécurité</h1>
            <div class="date">Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</div>
            <div style="margin-top: 10px; color: #94a3b8;">
                Cible: {html.escape(scan_result.target if hasattr(scan_result, 'target') else 'N/A')} | 
                Durée: {scan_result.duration:.1f}s
            </div>
        </div>
        
        <div class="risk-score">
            <div class="score">{risk_score}/100</div>
            <div style="color: #94a3b8; margin-top: 10px;">Score de Risque Global</div>
            <div class="risk-bar"><div class="risk-bar-fill"></div></div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value" style="color: #667eea;">{stats['hosts_up']}</div>
                <div class="label">Hôtes Actifs</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #3b82f6;">{stats['total_ports']}</div>
                <div class="label">Ports Ouverts</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #ef4444;">{stats['critical']}</div>
                <div class="label">Critiques</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #f97316;">{stats['high']}</div>
                <div class="label">Hautes</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #f59e0b;">{stats['medium']}</div>
                <div class="label">Moyennes</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #10b981;">{stats['low']}</div>
                <div class="label">Basses</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📡 Hôtes Découverts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Adresse IP</th>
                        <th>Hostname</th>
                        <th>OS Détecté</th>
                        <th>Ports Ouverts</th>
                        <th>Latence</th>
                    </tr>
                </thead>
                <tbody>'''
        
        # Ajouter les hôtes
        hosts = scan_result.hosts if hasattr(scan_result, 'hosts') else []
        for host in hosts:
            ports_str = ', '.join([str(p.port) for p in host.ports[:10]])
            if len(host.ports) > 10:
                ports_str += f' (+{len(host.ports) - 10})'
            
            html_content += f'''
                    <tr>
                        <td>{html.escape(host.ip)}</td>
                        <td>{html.escape(host.hostname or '-')}</td>
                        <td>{html.escape(host.os_guess or 'Inconnu')}</td>
                        <td>{html.escape(ports_str) if ports_str else '-'}</td>
                        <td>{host.response_time:.1f} ms</td>
                    </tr>'''
        
        html_content += '''
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ Vulnérabilités Détectées</h2>'''
        
        # Trier par sévérité
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.severity, 5))
        
        for vuln in sorted_vulns:
            html_content += f'''
            <div class="vuln-card {vuln.severity}">
                <div class="vuln-header">
                    <span class="vuln-title">{html.escape(vuln.name)}</span>
                    <span class="badge badge-{vuln.severity}">{vuln.severity.upper()} - CVSS {vuln.cvss}</span>
                </div>
                <div class="vuln-meta">
                    🖥️ {html.escape(vuln.host)} | 🔌 Port {vuln.port} ({html.escape(vuln.service)})
                </div>
                <div class="vuln-desc">{html.escape(vuln.description)}</div>
                <div class="vuln-recommendation">
                    <strong>💡 Recommandation:</strong> {html.escape(vuln.recommendation)}
                </div>
            </div>'''
        
        if not vulnerabilities:
            html_content += '''
            <div style="text-align: center; padding: 40px; color: #10b981;">
                ✅ Aucune vulnérabilité majeure détectée
            </div>'''
        
        # Section conformité
        comp = _get_compliance_summary()
        if comp:
            html_content += f'''
        <div class="section">
            <h2>📋 Conformité</h2>
            <div style="text-align:center; margin-bottom:20px;">
                <span style="font-size:2.5em; font-weight:bold; color:{
                    '#10b981' if comp['global_score'] >= 70 else '#f59e0b' if comp['global_score'] >= 40 else '#ef4444'
                };">{comp['global_score']:.0f}%</span>
                <span style="color:#94a3b8; margin-left:10px;">Score global</span>
                <span style="font-size:1.5em; font-weight:bold; margin-left:30px; color:#667eea;">
                    {comp.get('global_maturity', 0):.1f}/5</span>
                <span style="color:#94a3b8; margin-left:10px;">Maturité</span>
            </div>
            <table>
                <thead><tr>
                    <th>Référentiel</th><th>Score</th><th>Conformes</th>
                    <th>Partiels</th><th>Non conformes</th><th>À évaluer</th>
                </tr></thead><tbody>'''
            for fw in comp.get('frameworks', []):
                sc = '#10b981' if fw['score'] >= 70 else '#f59e0b' if fw['score'] >= 40 else '#ef4444'
                html_content += f'''
                    <tr>
                        <td><strong>{fw['name']}</strong></td>
                        <td style="color:{sc}; font-weight:bold;">{fw['score']:.0f}%</td>
                        <td>{fw['compliant']}</td><td>{fw['partial']}</td>
                        <td>{fw['non_compliant']}</td><td>{fw['not_evaluated']}</td>
                    </tr>'''
            html_content += '''
                </tbody></table>
        </div>'''
        
        html_content += f'''
        
        <div class="footer">
            <p>SENTRISCOPE v2.9 — Security Audit Platform</p>
            <p style="margin-top: 5px;">⚠️ Ce rapport est fourni à titre informatif. 
            Une analyse approfondie par un expert en sécurité est recommandée.</p>
        </div>
    </div>
</body>
</html>'''
        
        # Sauvegarder
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def generate_json_report(self, scan_result, vulnerabilities: List,
                            filename: str = None) -> str:
        """Générer un rapport JSON"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{timestamp}.json"
        
        filepath = self.reports_dir / filename
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': _TOOL_NAME,
                'target': scan_result.target if hasattr(scan_result, 'target') else '',
                'duration': scan_result.duration if hasattr(scan_result, 'duration') else 0
            },
            'summary': {
                'hosts_scanned': scan_result.hosts_scanned if hasattr(scan_result, 'hosts_scanned') else 0,
                'hosts_up': scan_result.hosts_up if hasattr(scan_result, 'hosts_up') else 0,
                'total_open_ports': scan_result.total_open_ports if hasattr(scan_result, 'total_open_ports') else 0,
                'vulnerabilities': {
                    'total': len(vulnerabilities),
                    'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
                    'high': len([v for v in vulnerabilities if v.severity == 'high']),
                    'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
                    'low': len([v for v in vulnerabilities if v.severity == 'low'])
                }
            },
            'hosts': [],
            'vulnerabilities': []
        }
        
        # Ajouter les hôtes
        if hasattr(scan_result, 'hosts'):
            for host in scan_result.hosts:
                host_data = {
                    'ip': host.ip,
                    'hostname': host.hostname,
                    'mac': host.mac,
                    'os': host.os_guess,
                    'response_time_ms': host.response_time,
                    'ports': [
                        {
                            'port': p.port,
                            'protocol': p.protocol,
                            'state': p.state,
                            'service': p.service,
                            'version': p.version
                        } for p in host.ports
                    ]
                }
                report['hosts'].append(host_data)
        
        # Ajouter les vulnérabilités
        for vuln in vulnerabilities:
            report['vulnerabilities'].append(vuln.to_dict())
        
        # Ajouter la conformité
        comp = _get_compliance_summary()
        if comp:
            report['compliance'] = comp
        
        # Sauvegarder
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def generate_csv_report(self, scan_result, vulnerabilities: List,
                           filename: str = None) -> str:
        """Générer un rapport CSV complet"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{timestamp}.csv"
        
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')  # Délimiteur ; pour Excel FR
            
            # En-tête
            writer.writerow([
                'Type', 'IP', 'Hostname', 'OS', 'Port', 'Protocol',
                'Service', 'Severity', 'CVSS', 'Vulnerability', 
                'Description', 'Recommendation', 'CVEs'
            ])
            
            # Données des hôtes
            if hasattr(scan_result, 'hosts'):
                for host in scan_result.hosts:
                    if host.ports:
                        for port in host.ports:
                            # Trouver la vulnérabilité correspondante
                            vuln = next(
                                (v for v in vulnerabilities 
                                 if v.host == host.ip and v.port == port.port),
                                None
                            )
                            
                            writer.writerow([
                                'host',
                                host.ip,
                                host.hostname or '',
                                host.os_guess or '',
                                port.port,
                                port.protocol,
                                port.service,
                                vuln.severity if vuln else '',
                                vuln.cvss if vuln else '',
                                vuln.name if vuln else '',
                                vuln.description if vuln else '',
                                vuln.recommendation if vuln else '',
                                ', '.join(vuln.cve_list) if vuln else ''
                            ])
                    else:
                        writer.writerow([
                            'host',
                            host.ip,
                            host.hostname or '',
                            host.os_guess or '',
                            '', '', '', '', '', '', '', '', ''
                        ])
        
        return str(filepath)
    
    def export_hosts_csv(self, scan_result, filename: str = None) -> str:
        """Exporter uniquement les hôtes en CSV"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"hosts_{timestamp}.csv"
        
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            
            writer.writerow([
                'IP', 'Hostname', 'MAC', 'OS', 'Latence (ms)', 
                'Ports Ouverts', 'Services'
            ])
            
            if hasattr(scan_result, 'hosts'):
                for host in scan_result.hosts:
                    ports_list = ', '.join([str(p.port) for p in host.ports])
                    services_list = ', '.join([p.service for p in host.ports if p.service])
                    
                    writer.writerow([
                        host.ip,
                        host.hostname or '',
                        host.mac or '',
                        host.os_guess or '',
                        f"{host.response_time:.1f}",
                        ports_list,
                        services_list
                    ])
        
        return str(filepath)
    
    def export_vulnerabilities_csv(self, vulnerabilities: List, 
                                   filename: str = None) -> str:
        """Exporter uniquement les vulnérabilités en CSV"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"vulnerabilities_{timestamp}.csv"
        
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            
            writer.writerow([
                'Sévérité', 'CVSS', 'Hôte', 'Port', 'Service',
                'Nom', 'Description', 'Recommandation', 'CVEs', 'Détecté le'
            ])
            
            # Trier par sévérité
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_vulns = sorted(vulnerabilities, 
                                  key=lambda v: severity_order.get(v.severity, 5))
            
            for vuln in sorted_vulns:
                writer.writerow([
                    vuln.severity.upper(),
                    vuln.cvss,
                    vuln.host,
                    vuln.port,
                    vuln.service,
                    vuln.name,
                    vuln.description,
                    vuln.recommendation,
                    ', '.join(vuln.cve_list) if vuln.cve_list else '',
                    vuln.detected_at
                ])
        
        return str(filepath)
    
    def export_connections_csv(self, connections: List, filename: str = None) -> str:
        """Exporter les connexions réseau en CSV"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"connections_{timestamp}.csv"
        
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            
            writer.writerow([
                'Protocole', 'IP Locale', 'Port Local', 
                'IP Distante', 'Port Distant', 'État', 'PID', 'Processus'
            ])
            
            for conn in connections:
                if hasattr(conn, 'to_dict'):
                    c = conn.to_dict()
                else:
                    c = conn
                
                writer.writerow([
                    c.get('protocol', ''),
                    c.get('local_ip', ''),
                    c.get('local_port', ''),
                    c.get('remote_ip', ''),
                    c.get('remote_port', ''),
                    c.get('status', ''),
                    c.get('pid', ''),
                    c.get('process', '')
                ])
        
        return str(filepath)
    
    def export_processes_csv(self, processes: List, filename: str = None) -> str:
        """Exporter les processus en CSV"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"processes_{timestamp}.csv"
        
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            
            writer.writerow([
                'PID', 'Nom', 'Utilisateur', 'CPU %', 'Mémoire %',
                'Mémoire (MB)', 'Connexions', 'Threads', 'Statut', 'Démarré'
            ])
            
            for proc in processes:
                writer.writerow([
                    proc.pid,
                    proc.name,
                    proc.username,
                    f"{proc.cpu_percent:.1f}",
                    f"{proc.memory_percent:.1f}",
                    f"{proc.memory_mb:.1f}",
                    proc.connections,
                    proc.threads,
                    proc.status,
                    proc.created
                ])
        
        return str(filepath)
    
    def export_alerts_csv(self, alerts: List, filename: str = None) -> str:
        """Exporter les alertes IDS en CSV"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"alerts_{timestamp}.csv"
        
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            
            writer.writerow([
                'Sévérité', 'Type', 'Titre', 'IP Source', 
                'IP Destination', 'Port', 'Description', 'Timestamp', 'Acquitté'
            ])
            
            for alert in alerts:
                if hasattr(alert, 'to_dict'):
                    a = alert.to_dict()
                else:
                    a = alert
                
                writer.writerow([
                    a.get('severity', '').upper(),
                    a.get('alert_type', ''),
                    a.get('title', ''),
                    a.get('source_ip', ''),
                    a.get('destination_ip', ''),
                    a.get('destination_port', ''),
                    a.get('description', ''),
                    a.get('timestamp', ''),
                    'Oui' if a.get('acknowledged') else 'Non'
                ])
        
        return str(filepath)
    
    def generate_txt_report(self, scan_result, vulnerabilities: List,
                           filename: str = None) -> str:
        """Générer un rapport texte"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{timestamp}.txt"
        
        filepath = self.reports_dir / filename
        
        lines = []
        lines.append("=" * 70)
        lines.append("          SENTRISCOPE — RAPPORT DE SÉCURITÉ")
        lines.append("=" * 70)
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Cible: {scan_result.target if hasattr(scan_result, 'target') else 'N/A'}")
        lines.append(f"Durée du scan: {scan_result.duration:.1f}s" if hasattr(scan_result, 'duration') else "")
        lines.append("")
        
        # Résumé
        lines.append("-" * 70)
        lines.append("RÉSUMÉ")
        lines.append("-" * 70)
        lines.append(f"Hôtes scannés: {scan_result.hosts_scanned if hasattr(scan_result, 'hosts_scanned') else 0}")
        lines.append(f"Hôtes actifs: {scan_result.hosts_up if hasattr(scan_result, 'hosts_up') else 0}")
        lines.append(f"Ports ouverts: {scan_result.total_open_ports if hasattr(scan_result, 'total_open_ports') else 0}")
        lines.append(f"Vulnérabilités: {len(vulnerabilities)}")
        lines.append(f"  - Critiques: {len([v for v in vulnerabilities if v.severity == 'critical'])}")
        lines.append(f"  - Hautes: {len([v for v in vulnerabilities if v.severity == 'high'])}")
        lines.append(f"  - Moyennes: {len([v for v in vulnerabilities if v.severity == 'medium'])}")
        lines.append(f"  - Basses: {len([v for v in vulnerabilities if v.severity == 'low'])}")
        lines.append("")
        
        # Hôtes
        lines.append("-" * 70)
        lines.append("HÔTES DÉCOUVERTS")
        lines.append("-" * 70)
        
        if hasattr(scan_result, 'hosts'):
            for host in scan_result.hosts:
                lines.append(f"\n[{host.ip}]")
                lines.append(f"  Hostname: {host.hostname or 'N/A'}")
                lines.append(f"  OS: {host.os_guess or 'Inconnu'}")
                lines.append(f"  Latence: {host.response_time:.1f} ms")
                lines.append(f"  Ports ouverts:")
                for port in host.ports:
                    lines.append(f"    - {port.port}/{port.protocol} ({port.service})")
                    if port.version:
                        lines.append(f"      Version: {port.version}")
        
        lines.append("")
        
        # Vulnérabilités
        lines.append("-" * 70)
        lines.append("VULNÉRABILITÉS")
        lines.append("-" * 70)
        
        for vuln in sorted(vulnerabilities, key=lambda v: 
                          {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(v.severity, 4)):
            lines.append(f"\n[{vuln.severity.upper()}] {vuln.name}")
            lines.append(f"  Hôte: {vuln.host}:{vuln.port} ({vuln.service})")
            lines.append(f"  CVSS: {vuln.cvss}")
            lines.append(f"  Description: {vuln.description}")
            lines.append(f"  Recommandation: {vuln.recommendation}")
            if vuln.cve_list:
                lines.append(f"  CVEs: {', '.join(vuln.cve_list)}")
        
        if not vulnerabilities:
            lines.append("\nAucune vulnérabilité majeure détectée.")
        
        # Conformité
        comp = _get_compliance_summary()
        if comp:
            lines.append("")
            lines.append("-" * 70)
            lines.append("CONFORMITÉ")
            lines.append("-" * 70)
            lines.append(f"Score global: {comp['global_score']:.0f}%")
            lines.append(f"Maturité globale: {comp.get('global_maturity', 0):.1f}/5")
            for fw in comp.get('frameworks', []):
                lines.append(f"\n  [{fw['name']}] Score: {fw['score']:.0f}%")
                lines.append(f"    Conformes: {fw['compliant']} | Partiels: {fw['partial']} | "
                             f"Non conformes: {fw['non_compliant']} | À évaluer: {fw['not_evaluated']}")
        
        lines.append("")
        lines.append("=" * 70)
        lines.append("Fin du rapport — " + _TOOL_NAME)
        lines.append("=" * 70)
        
        # Sauvegarder
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        return str(filepath)
    
    # ── PDF ─────────────────────────────────────────────────────────────────────

    def generate_pdf_report(self, scan_result, vulnerabilities: List,
                            filename: str = None, executive: bool = False) -> str:
        """
        Générer un rapport PDF.
        executive=True  → Synthèse direction (1-2 pages)
        executive=False → Rapport technique détaillé
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm, cm
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

        if not filename:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            tag = "executive" if executive else "technical"
            filename = f"sentriscope_{tag}_{ts}.pdf"

        filepath = self.reports_dir / filename
        stats = _get_stats(scan_result, vulnerabilities)
        risk = _risk_score(stats)
        comp = _get_compliance_summary()

        # ── Couleurs ────────────────────────────────────────────
        ACCENT   = HexColor("#667eea")
        SUCCESS  = HexColor("#10b981")
        WARNING  = HexColor("#f59e0b")
        DANGER   = HexColor("#ef4444")
        DARK_BG  = HexColor("#1a1a2e")
        MUTED    = HexColor("#94a3b8")
        DARK_TXT = HexColor("#1e293b")
        LIGHT_BG = HexColor("#f1f5f9")

        def risk_color(score):
            if score < 30: return SUCCESS
            if score < 60: return WARNING
            return DANGER

        def sev_color(sev):
            return {'critical': DANGER, 'high': HexColor("#f97316"),
                    'medium': WARNING, 'low': SUCCESS}.get(sev, MUTED)

        # ── Styles ──────────────────────────────────────────────
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle('Title_Custom', parent=styles['Title'],
                                   fontSize=24, textColor=ACCENT,
                                   spaceAfter=6, alignment=TA_CENTER))
        styles.add(ParagraphStyle('Subtitle', parent=styles['Normal'],
                                   fontSize=11, textColor=MUTED,
                                   alignment=TA_CENTER, spaceAfter=20))
        styles.add(ParagraphStyle('SectionTitle', parent=styles['Heading2'],
                                   fontSize=14, textColor=ACCENT,
                                   spaceBefore=16, spaceAfter=8,
                                   borderPadding=(0, 0, 4, 0)))
        styles.add(ParagraphStyle('Body', parent=styles['Normal'],
                                   fontSize=9, textColor=DARK_TXT,
                                   leading=13))
        styles.add(ParagraphStyle('Small', parent=styles['Normal'],
                                   fontSize=8, textColor=MUTED))
        styles.add(ParagraphStyle('Footer', parent=styles['Normal'],
                                   fontSize=7, textColor=MUTED,
                                   alignment=TA_CENTER))
        styles.add(ParagraphStyle('BigNumber', parent=styles['Normal'],
                                   fontSize=28, textColor=ACCENT,
                                   alignment=TA_CENTER, leading=32))

        doc = SimpleDocTemplate(
            str(filepath), pagesize=A4,
            topMargin=20*mm, bottomMargin=20*mm,
            leftMargin=18*mm, rightMargin=18*mm)

        elements = []

        # ── Page de titre / Header ──────────────────────────────
        elements.append(Spacer(1, 15*mm))
        elements.append(Paragraph("🛡️ SENTRISCOPE", styles['Title_Custom']))
        tag_text = "Synthèse exécutive" if executive else "Rapport technique de sécurité"
        elements.append(Paragraph(tag_text, styles['Subtitle']))
        elements.append(Paragraph(
            f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} — "
            f"Cible : {getattr(scan_result, 'target', 'N/A')}",
            styles['Subtitle']))
        elements.append(HRFlowable(width="100%", color=ACCENT, thickness=1,
                                    spaceAfter=10))

        # ── Score de risque ─────────────────────────────────────
        rc = risk_color(risk)
        score_data = [
            [Paragraph(f'<font size="28" color="{rc.hexval()}">{risk}/100</font>',
                        styles['BigNumber'])],
            [Paragraph("Score de risque global", styles['Small'])],
        ]
        score_table = Table(score_data, colWidths=[170*mm])
        score_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (0, 0), 12),
            ('BOTTOMPADDING', (0, -1), (0, -1), 12),
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
            ('ROUNDEDCORNERS', [6, 6, 6, 6]),
        ]))
        elements.append(score_table)
        elements.append(Spacer(1, 8*mm))

        # ── Stats cards ─────────────────────────────────────────
        card_data = [[
            Paragraph(f'<font size="18" color="{ACCENT.hexval()}">{stats["hosts_up"]}</font>'
                      f'<br/><font size="8" color="{MUTED.hexval()}">Hôtes</font>',
                      styles['Body']),
            Paragraph(f'<font size="18" color="{HexColor("#3b82f6").hexval()}">{stats["total_ports"]}</font>'
                      f'<br/><font size="8" color="{MUTED.hexval()}">Ports</font>',
                      styles['Body']),
            Paragraph(f'<font size="18" color="{DANGER.hexval()}">{stats["critical"]}</font>'
                      f'<br/><font size="8" color="{MUTED.hexval()}">Critiques</font>',
                      styles['Body']),
            Paragraph(f'<font size="18" color="{WARNING.hexval()}">{stats["total_vulns"]}</font>'
                      f'<br/><font size="8" color="{MUTED.hexval()}">Vulnérabilités</font>',
                      styles['Body']),
        ]]
        card_table = Table(card_data, colWidths=[42.5*mm]*4)
        card_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('ROUNDEDCORNERS', [6, 6, 6, 6]),
        ]))
        elements.append(card_table)
        elements.append(Spacer(1, 6*mm))

        # ── Conformité ──────────────────────────────────────────
        if comp:
            elements.append(Paragraph("📋 Conformité", styles['SectionTitle']))
            comp_header = ['Référentiel', 'Score', 'Conformes', 'Partiels',
                           'Non conf.', 'À évaluer']
            comp_rows = [comp_header]
            for fw in comp.get('frameworks', []):
                comp_rows.append([
                    fw['name'],
                    f"{fw['score']:.0f}%",
                    str(fw['compliant']),
                    str(fw['partial']),
                    str(fw['non_compliant']),
                    str(fw['not_evaluated']),
                ])
            comp_rows.append([
                'GLOBAL',
                f"{comp['global_score']:.0f}%",
                '', '', '', ''
            ])
            ct = Table(comp_rows, colWidths=[35*mm, 22*mm, 22*mm, 22*mm, 22*mm, 22*mm])
            ct.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                ('BACKGROUND', (0, -1), (-1, -1), LIGHT_BG),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(ct)
            elements.append(Spacer(1, 6*mm))

        # ── Mode exécutif : top vulnérabilités seulement ────────
        if executive:
            top_vulns = sorted(vulnerabilities,
                               key=lambda v: v.cvss, reverse=True)[:5]
            if top_vulns:
                elements.append(Paragraph("⚠️ Top vulnérabilités", styles['SectionTitle']))
                tv_data = [['Sévérité', 'CVSS', 'Hôte', 'Port', 'Vulnérabilité']]
                for v in top_vulns:
                    tv_data.append([
                        v.severity.upper(), str(v.cvss),
                        v.host, str(v.port), v.name[:45]
                    ])
                tv = Table(tv_data, colWidths=[22*mm, 15*mm, 30*mm, 18*mm, 85*mm])
                tv.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(tv)

            elements.append(Spacer(1, 15*mm))
            elements.append(Paragraph(
                f"Rapport généré par {_TOOL_NAME}",
                styles['Footer']))

        # ── Mode technique : détail complet ─────────────────────
        else:
            # Hôtes
            hosts = getattr(scan_result, 'hosts', [])
            if hosts:
                elements.append(Paragraph("📡 Hôtes découverts", styles['SectionTitle']))
                h_data = [['IP', 'Hostname', 'OS', 'Ports ouverts', 'Latence']]
                for host in hosts:
                    ports_str = ', '.join([str(p.port) for p in host.ports[:8]])
                    if len(host.ports) > 8:
                        ports_str += f' (+{len(host.ports)-8})'
                    h_data.append([
                        host.ip,
                        (host.hostname or '—')[:20],
                        (host.os_guess or '—')[:18],
                        ports_str or '—',
                        f"{host.response_time:.0f}ms"
                    ])
                ht = Table(h_data, colWidths=[30*mm, 30*mm, 28*mm, 55*mm, 17*mm])
                ht.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, LIGHT_BG]),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(ht)
                elements.append(Spacer(1, 6*mm))

            # Vulnérabilités détaillées
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_vulns = sorted(vulnerabilities,
                                   key=lambda v: sev_order.get(v.severity, 9))

            if sorted_vulns:
                elements.append(Paragraph("⚠️ Vulnérabilités détaillées",
                                           styles['SectionTitle']))
                for vuln in sorted_vulns:
                    sc = sev_color(vuln.severity)
                    v_data = [
                        [Paragraph(
                            f'<font color="{sc.hexval()}"><b>[{vuln.severity.upper()}]</b></font> '
                            f'<b>{vuln.name}</b>  —  CVSS {vuln.cvss}',
                            styles['Body'])],
                        [Paragraph(
                            f'<font color="{MUTED.hexval()}">'
                            f'Hôte: {vuln.host}:{vuln.port} ({vuln.service})'
                            f'</font>', styles['Body'])],
                        [Paragraph(vuln.description, styles['Body'])],
                        [Paragraph(
                            f'<font color="{ACCENT.hexval()}"><b>Recommandation:</b></font> '
                            f'{vuln.recommendation}', styles['Body'])],
                    ]
                    if vuln.cve_list:
                        v_data.append([Paragraph(
                            f'<font color="{MUTED.hexval()}">CVE: {", ".join(vuln.cve_list)}</font>',
                            styles['Small'])])

                    vt = Table(v_data, colWidths=[170*mm])
                    vt.setStyle(TableStyle([
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 0), (-1, -1), 3),
                        ('BOTTOMPADDING', (0, -1), (-1, -1), 6),
                        ('LINEBELOW', (0, -1), (-1, -1), 0.5, HexColor("#e2e8f0")),
                    ]))
                    elements.append(vt)
                    elements.append(Spacer(1, 2*mm))

            elif not vulnerabilities:
                elements.append(Spacer(1, 8*mm))
                elements.append(Paragraph(
                    "✅ Aucune vulnérabilité majeure détectée.",
                    styles['Body']))

            # Footer
            elements.append(Spacer(1, 15*mm))
            elements.append(HRFlowable(width="100%", color=MUTED, thickness=0.5))
            elements.append(Spacer(1, 3*mm))
            elements.append(Paragraph(
                f"Rapport généré par {_TOOL_NAME} — "
                f"Ce rapport est fourni à titre informatif.",
                styles['Footer']))

        doc.build(elements)
        return str(filepath)

    def generate_all_formats(self, scan_result, vulnerabilities: List,
                            base_name: str = None) -> Dict[str, str]:
        """Générer le rapport dans tous les formats"""
        if not base_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = f"security_report_{timestamp}"
        
        results = {
            'html': self.generate_html_report(scan_result, vulnerabilities, f"{base_name}.html"),
            'json': self.generate_json_report(scan_result, vulnerabilities, f"{base_name}.json"),
            'csv': self.generate_csv_report(scan_result, vulnerabilities, f"{base_name}.csv"),
            'txt': self.generate_txt_report(scan_result, vulnerabilities, f"{base_name}.txt"),
        }
        try:
            results['pdf'] = self.generate_pdf_report(
                scan_result, vulnerabilities, f"{base_name}.pdf")
            results['pdf_exec'] = self.generate_pdf_report(
                scan_result, vulnerabilities, f"{base_name}_executive.pdf",
                executive=True)
        except ImportError:
            pass  # reportlab non installé
        return results
