"""Module de Détection de Vulnérabilités et IDS"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from datetime import datetime
from collections import defaultdict
import threading, re, time
from modules.config import VULNERABILITY_DB, IDS_SIGNATURES, SUSPICIOUS_PORTS


@dataclass
class Vulnerability:
    host: str; port: int; service: str; name: str
    severity: str; cvss: float; description: str; recommendation: str
    cve_list: List[str] = field(default_factory=list)
    detected_at: str = ""
    def __post_init__(self):
        if not self.detected_at: self.detected_at = datetime.now().isoformat()
    def to_dict(self) -> Dict:
        return {k: getattr(self, k) for k in
                ('host','port','service','name','severity','cvss','description',
                 'recommendation','cve_list','detected_at')}


@dataclass
class SecurityAlert:
    alert_type: str; severity: str; source_ip: str
    destination_ip: str = ""; destination_port: int = 0
    title: str = ""; description: str = ""
    details: Dict = field(default_factory=dict)
    timestamp: str = ""; acknowledged: bool = False
    def __post_init__(self):
        if not self.timestamp: self.timestamp = datetime.now().isoformat()
    def to_dict(self) -> Dict:
        return {k: getattr(self, k) for k in
                ('alert_type','severity','source_ip','destination_ip','destination_port',
                 'title','description','details','timestamp','acknowledged')}


class VulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def analyze_host(self, host) -> List[Vulnerability]:
        vulns = []
        for pr in host.ports:
            p = pr.port
            if p in VULNERABILITY_DB:
                vi = VULNERABILITY_DB[p]
                if vi['severity'] == 'info': continue
                vulns.append(Vulnerability(
                    host=host.ip, port=p, service=pr.service, name=vi['name'],
                    severity=vi['severity'], cvss=vi['cvss'], description=vi['description'],
                    recommendation=vi['recommendation'], cve_list=vi.get('cve', [])))
            if p in SUSPICIOUS_PORTS:
                vulns.append(Vulnerability(
                    host=host.ip, port=p, service=SUSPICIOUS_PORTS[p],
                    name=f"Port suspect: {SUSPICIOUS_PORTS[p]}", severity="high", cvss=7.0,
                    description=f"Le port {p} est associé au malware/backdoor {SUSPICIOUS_PORTS[p]}",
                    recommendation="Investiguer immédiatement ce port et le processus associé."))
            if pr.banner:
                vulns.extend(self._analyze_banner(host.ip, pr))
        self.vulnerabilities.extend(vulns)
        return vulns

    def _analyze_banner(self, ip: str, pr) -> List[Vulnerability]:
        vulns = []
        banner = pr.banner.lower()
        obsolete = [
            (r'openssh[_\s-]([456]\.\d)', 'OpenSSH obsolète', 'high', 7.5),
            (r'apache/2\.2', 'Apache 2.2 obsolète', 'medium', 5.0),
            (r'apache/2\.0', 'Apache 2.0 obsolète', 'high', 7.0),
            (r'nginx/1\.[0-9]\.', 'Nginx obsolète', 'medium', 5.0),
            (r'php/5\.[0-4]', 'PHP 5.x obsolète', 'critical', 9.0),
            (r'mysql\s*5\.[0-5]', 'MySQL 5.x ancien', 'medium', 5.0),
            (r'iis/[567]\.', 'IIS obsolète', 'high', 7.0),
            (r'vsftpd\s*2\.[0-2]', 'vsftpd vulnérable', 'critical', 9.8),
            (r'proftpd\s*1\.[23]\.', 'ProFTPD vulnérable', 'high', 7.5),
            (r'openssl[/\s]0\.9', 'OpenSSL 0.9 vulnérable', 'critical', 9.0),
            (r'openssl[/\s]1\.0\.0', 'OpenSSL 1.0.0 vulnérable', 'critical', 9.0),
        ]
        for pat, name, sev, cvss in obsolete:
            if re.search(pat, banner):
                vulns.append(Vulnerability(
                    host=ip, port=pr.port, service=pr.service, name=name,
                    severity=sev, cvss=cvss,
                    description=f"Version obsolète détectée: {banner[:100]}",
                    recommendation="Mettre à jour vers la dernière version stable."))
        sensitive = [
            (r'debug', 'Mode debug activé', 'medium'),
            (r'root@', 'Utilisateur root exposé', 'high'),
            (r'password', 'Mot de passe potentiellement exposé', 'high'),
        ]
        for pat, name, sev in sensitive:
            if re.search(pat, banner):
                vulns.append(Vulnerability(
                    host=ip, port=pr.port, service=pr.service,
                    name=f"Information sensible: {name}", severity=sev,
                    cvss=6.0 if sev == 'medium' else 7.5,
                    description="La bannière contient potentiellement des informations sensibles.",
                    recommendation="Configurer le service pour masquer les informations sensibles."))
        return vulns

    def analyze_scan_results(self, scan_result) -> Dict:
        all_vulns = []
        for host in scan_result.hosts:
            all_vulns.extend(self.analyze_host(host))
        sc = defaultdict(int)
        for v in all_vulns: sc[v.severity] += 1
        return {
            'vulnerabilities': all_vulns,
            'stats': {**dict(sc), 'total': len(all_vulns), 'by_host': {}, 'by_port': defaultdict(int)}
        }

    def get_risk_score(self) -> int:
        w = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
        return min(100, sum(w.get(v.severity, 1) for v in self.vulnerabilities))

    def clear(self): self.vulnerabilities = []


class IntrusionDetector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.alerts: List[SecurityAlert] = []
        self._callbacks: List[Callable] = []
        self._lock = threading.Lock()
        self._port_scan_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': None})
        self._connection_tracker = defaultdict(list)
        self._syn_tracker = defaultdict(list)
        self._dns_tracker = defaultdict(list)
        self.blacklist: set = set()
        self.max_alerts = 1000

        # Feeder thread (ConnectionMonitor → analyze_connection)
        self._feeder_running = False
        self._feeder_thread: Optional[threading.Thread] = None
        self._seen_remote_keys: set = set()

    def add_callback(self, cb):
        with self._lock:
            if cb not in self._callbacks: self._callbacks.append(cb)

    def analyze_connection(self, source_ip, dest_ip, dest_port, protocol='TCP', flags='') -> Optional[SecurityAlert]:
        now = datetime.now()
        alert = None
        if source_ip in self.blacklist:
            alert = SecurityAlert(alert_type='blacklist_connection', severity='critical',
                                  source_ip=source_ip, destination_ip=dest_ip,
                                  destination_port=dest_port, title='Connexion depuis IP blacklistée',
                                  description=f'Tentative depuis IP blacklistée: {source_ip}')
            self._add_alert(alert); return alert
        if dest_port in SUSPICIOUS_PORTS:
            alert = SecurityAlert(alert_type='suspicious_port', severity='high',
                                  source_ip=source_ip, destination_ip=dest_ip,
                                  destination_port=dest_port,
                                  title=f'Accès port suspect ({SUSPICIOUS_PORTS[dest_port]})',
                                  description=f'Connexion vers port {dest_port} ({SUSPICIOUS_PORTS[dest_port]})')
            self._add_alert(alert)
        # Port scan detection
        tk = self._port_scan_tracker[source_ip]
        if tk['first_seen'] is None: tk['first_seen'] = now
        tk['ports'].add(dest_port)
        if (now - tk['first_seen']).seconds > IDS_SIGNATURES['port_scan']['window']:
            tk['ports'] = {dest_port}; tk['first_seen'] = now
        if len(tk['ports']) >= IDS_SIGNATURES['port_scan']['threshold']:
            alert = SecurityAlert(alert_type='port_scan', severity='high', source_ip=source_ip,
                                  destination_ip=dest_ip, title='Port scan détecté',
                                  description=f'Port scan depuis {source_ip}: {len(tk["ports"])} ports',
                                  details={'ports_scanned': len(tk['ports'])})
            self._add_alert(alert); tk['ports'] = set()
        # SYN flood
        if protocol == 'TCP' and 'S' in flags and 'A' not in flags:
            self._syn_tracker[source_ip].append(now)
            w = IDS_SIGNATURES['syn_flood']['window']
            self._syn_tracker[source_ip] = [t for t in self._syn_tracker[source_ip] if (now-t).seconds < w]
            if len(self._syn_tracker[source_ip]) >= IDS_SIGNATURES['syn_flood']['threshold']:
                alert = SecurityAlert(alert_type='syn_flood', severity='critical', source_ip=source_ip,
                                      destination_ip=dest_ip, title='SYN Flood détecté',
                                      description=f'SYN Flood depuis {source_ip}',
                                      details={'syn_count': len(self._syn_tracker[source_ip])})
                self._add_alert(alert); self._syn_tracker[source_ip] = []
        # DNS tunneling
        if dest_port == 53:
            self._dns_tracker[source_ip].append(now)
            w = IDS_SIGNATURES['dns_tunnel']['window']
            self._dns_tracker[source_ip] = [t for t in self._dns_tracker[source_ip] if (now-t).seconds < w]
            if len(self._dns_tracker[source_ip]) >= IDS_SIGNATURES['dns_tunnel']['threshold']:
                alert = SecurityAlert(alert_type='dns_tunneling', severity='high', source_ip=source_ip,
                                      destination_ip=dest_ip, destination_port=53,
                                      title='DNS Tunneling potentiel',
                                      description=f'Activité DNS suspecte depuis {source_ip}',
                                      details={'dns_queries': len(self._dns_tracker[source_ip])})
                self._add_alert(alert); self._dns_tracker[source_ip] = []
        return alert

    def analyze_failed_login(self, source_ip, username='', service='') -> Optional[SecurityAlert]:
        now = datetime.now()
        self._connection_tracker[source_ip].append(now)
        w = IDS_SIGNATURES['brute_force']['window']
        self._connection_tracker[source_ip] = [t for t in self._connection_tracker[source_ip] if (now-t).seconds < w]
        if len(self._connection_tracker[source_ip]) >= IDS_SIGNATURES['brute_force']['threshold']:
            alert = SecurityAlert(alert_type='brute_force', severity='critical', source_ip=source_ip,
                                  title='Attaque Brute Force détectée',
                                  description=f'Tentatives répétées depuis {source_ip}',
                                  details={'attempts': len(self._connection_tracker[source_ip])})
            self._add_alert(alert); self._connection_tracker[source_ip] = []
            return alert
        return None

    def _add_alert(self, alert):
        with self._lock:
            if len(self.alerts) >= self.max_alerts: self.alerts.pop(0)
            self.alerts.append(alert)
            for cb in self._callbacks:
                try: cb(alert)
                except: pass

    def get_alerts(self, severity=None, alert_type=None, limit=100):
        alerts = self.alerts.copy()
        if severity: alerts = [a for a in alerts if a.severity == severity]
        if alert_type: alerts = [a for a in alerts if a.alert_type == alert_type]
        return alerts[-limit:]

    def get_stats(self) -> Dict:
        counts = defaultdict(int)
        for a in self.alerts: counts[a.severity] += 1
        return {'total': len(self.alerts), 'critical': counts['critical'],
                'high': counts['high'], 'medium': counts['medium'], 'low': counts['low'],
                'unacknowledged': sum(1 for a in self.alerts if not a.acknowledged)}

    def acknowledge_alert(self, idx):
        if 0 <= idx < len(self.alerts): self.alerts[idx].acknowledged = True

    def acknowledge_all(self):
        for a in self.alerts: a.acknowledged = True

    def add_to_blacklist(self, ip): self.blacklist.add(ip)
    def remove_from_blacklist(self, ip): self.blacklist.discard(ip)
    def clear_alerts(self):
        with self._lock: self.alerts = []

    # ── Feeder : alimente l'IDS depuis ConnectionMonitor ──────────────
    def start_feeder(self, interval: float = 3.0):
        """
        Démarre un thread qui lit les connexions actives toutes `interval` secondes
        et alimente le moteur IDS. Détecte naturellement port scans (plusieurs ports
        depuis une même IP) et accès aux ports suspects.
        """
        if self._feeder_running:
            return
        self._feeder_running = True

        def _loop():
            # Import local pour éviter une dépendance circulaire au chargement
            from modules.monitor import ConnectionMonitor
            while self._feeder_running:
                try:
                    for c in ConnectionMonitor.get_connections(include_localhost=False):
                        if not c.remote_ip or c.remote_ip in ('*', ''):
                            continue
                        # Dédupliquer pour ne pas re-trigger en boucle sur les mêmes flux
                        key = (c.remote_ip, c.local_port, c.remote_port, c.protocol)
                        if key in self._seen_remote_keys:
                            continue
                        self._seen_remote_keys.add(key)
                        # Garder le set borné
                        if len(self._seen_remote_keys) > 5000:
                            self._seen_remote_keys.clear()
                        self.analyze_connection(
                            source_ip=c.remote_ip,
                            dest_ip=c.local_ip,
                            dest_port=c.local_port,
                            protocol=c.protocol,
                            flags=''
                        )
                except Exception:
                    # Le feeder ne doit jamais faire crasher le thread
                    pass
                # Sleep "annulable"
                for _ in range(int(interval * 10)):
                    if not self._feeder_running:
                        break
                    time.sleep(0.1)

        self._feeder_thread = threading.Thread(target=_loop, daemon=True)
        self._feeder_thread.start()

    def stop_feeder(self):
        self._feeder_running = False
        if self._feeder_thread:
            self._feeder_thread.join(timeout=2)
            self._feeder_thread = None


# Singleton global — partagé par toute l'application
intrusion_detector = IntrusionDetector()
