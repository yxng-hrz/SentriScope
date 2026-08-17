"""Configuration et constantes de l'application"""
import os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Callable

APP_DIR = Path(__file__).parent.parent
DATA_DIR = APP_DIR / "data"
REPORTS_DIR = APP_DIR / "reports"
CONFIG_FILE = DATA_DIR / "settings.json"
DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# ── Thème ─────────────────────────────────────────────────────

@dataclass
class Theme:
    name: str = "dark"
    bg_primary: str = "#0a0a1a"; bg_secondary: str = "#12122a"
    bg_card: str = "#1a1a3e"; bg_hover: str = "#252550"
    accent: str = "#667eea"; accent_light: str = "#818cf8"; accent_dark: str = "#4f46e5"
    success: str = "#10b981"; warning: str = "#f59e0b"; danger: str = "#ef4444"; info: str = "#3b82f6"
    text_primary: str = "#ffffff"; text_secondary: str = "#94a3b8"; text_muted: str = "#64748b"
    border: str = "#2d2d5a"; border_light: str = "#3d3d7a"

DARK_THEME = Theme(
    name="dark", bg_primary="#0a0f1a", bg_secondary="#111827",
    bg_card="#1a2332", bg_hover="#243044",
    accent="#10b981", accent_light="#34d399", accent_dark="#059669",
    success="#22c55e", warning="#f59e0b", danger="#ef4444", info="#3b82f6",
    text_primary="#f1f5f9", text_secondary="#94a3b8", text_muted="#64748b",
    border="#1e3a5f", border_light="#2d4a6f",
)
LIGHT_THEME = DARK_THEME  # Single theme for now


class ThemeManager:
    _instance = None
    _callbacks: List[Callable] = []

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized: return
        self._initialized = True
        self._callbacks = []
        self.current_theme = self._load_theme()

    def _load_theme(self) -> Theme:
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f:
                    if json.load(f).get('theme') == 'light':
                        return LIGHT_THEME
        except Exception: pass
        return DARK_THEME

    def _save_theme(self):
        try:
            config = {}
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, 'r') as f: config = json.load(f)
            config['theme'] = self.current_theme.name
            with open(CONFIG_FILE, 'w') as f: json.dump(config, f, indent=2)
        except Exception: pass

    def toggle_theme(self) -> Theme:
        self.current_theme = LIGHT_THEME if self.current_theme.name == "dark" else DARK_THEME
        self._save_theme(); self._notify(); return self.current_theme

    def set_theme(self, name: str) -> Theme:
        self.current_theme = LIGHT_THEME if name == "light" else DARK_THEME
        self._save_theme(); self._notify(); return self.current_theme

    def get_theme(self) -> Theme: return self.current_theme
    def is_dark(self) -> bool: return self.current_theme.name == "dark"

    def add_callback(self, cb: Callable):
        if cb not in self._callbacks: self._callbacks.append(cb)

    def remove_callback(self, cb: Callable):
        if cb in self._callbacks: self._callbacks.remove(cb)

    def _notify(self):
        for cb in self._callbacks:
            try: cb(self.current_theme)
            except: pass

theme_manager = ThemeManager()
THEME = theme_manager.get_theme()

# ── Ports & Services ──────────────────────────────────────────

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 194, 201, 443, 445, 465, 514, 515, 520, 521, 587, 631, 636,
    873, 902, 989, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049,
    2082, 2083, 2086, 2087, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4369,
    5000, 5001, 5060, 5222, 5432, 5672, 5900, 5901, 5984, 6379, 6443, 6660, 6661,
    6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 7001, 7002, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9090, 9092, 9200, 9300, 9418, 9999, 10000, 11211, 15672,
    27017, 27018, 27019, 28017, 50000, 50070,
]
TOP_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,27017]

SERVICE_NAMES: Dict[int, str] = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",67:"DHCP",68:"DHCP",
    69:"TFTP",80:"HTTP",110:"POP3",111:"RPC",119:"NNTP",123:"NTP",135:"MSRPC",
    137:"NetBIOS-NS",138:"NetBIOS-DGM",139:"NetBIOS-SSN",143:"IMAP",161:"SNMP",
    162:"SNMP-Trap",179:"BGP",194:"IRC",443:"HTTPS",445:"SMB",465:"SMTPS",514:"Syslog",
    515:"LPD",587:"SMTP-SUB",631:"IPP",636:"LDAPS",873:"Rsync",902:"VMware",993:"IMAPS",
    995:"POP3S",1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",1434:"MSSQL-UDP",1521:"Oracle",
    1723:"PPTP",1883:"MQTT",2049:"NFS",2181:"Zookeeper",2375:"Docker",2376:"Docker-TLS",
    3000:"Node.js",3128:"Squid",3306:"MySQL",3389:"RDP",3690:"SVN",4369:"EPMD",
    5000:"UPnP",5060:"SIP",5222:"XMPP",5432:"PostgreSQL",5672:"AMQP",5900:"VNC",
    5984:"CouchDB",6379:"Redis",6443:"K8s-API",7001:"WebLogic",8000:"HTTP-Alt",
    8008:"HTTP-Alt",8080:"HTTP-Proxy",8081:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Alt",
    9000:"SonarQube",9090:"Prometheus",9092:"Kafka",9200:"Elasticsearch",9300:"ES-Transport",
    9418:"Git",10000:"Webmin",11211:"Memcached",15672:"RabbitMQ-Mgmt",27017:"MongoDB",
    27018:"MongoDB",27019:"MongoDB",50000:"SAP",50070:"HDFS",
}

# ── Vulnérabilités ────────────────────────────────────────────

def _vuln(name, sev, cvss, desc, rec, cve=None):
    return {"name":name,"severity":sev,"cvss":cvss,"description":desc,"recommendation":rec,"cve":cve or []}

VULNERABILITY_DB: Dict[int, Dict] = {
    21:  _vuln("FTP Service Exposed","high",7.5,"FTP transmet les données et identifiants en clair.","Utilisez SFTP ou FTPS. Désactivez l'accès anonyme.",["CVE-2010-4221","CVE-2015-3306"]),
    22:  _vuln("SSH Service","info",0,"SSH est sécurisé mais doit être bien configuré.","Désactivez root login. Utilisez des clés SSH."),
    23:  _vuln("Telnet Service (CRITICAL)","critical",9.8,"Telnet transmet TOUT en clair. Extrêmement dangereux.","Désactivez Telnet IMMÉDIATEMENT. Utilisez SSH.",["CVE-2020-10188"]),
    25:  _vuln("SMTP Open Relay Risk","medium",5.0,"SMTP mal configuré peut servir de relais spam.","Configurez l'authentification SMTP."),
    53:  _vuln("DNS Service Exposed","medium",5.0,"DNS exposé peut être utilisé pour amplification DDoS.","Restreignez les requêtes récursives.",["CVE-2020-1350"]),
    110: _vuln("POP3 Unencrypted","high",7.0,"POP3 transmet les emails en clair.","Utilisez POP3S (port 995)."),
    135: _vuln("Microsoft RPC","high",7.5,"RPC Windows est une cible fréquente d'exploits.","Bloquez le port 135 pour le trafic externe.",["CVE-2003-0352","CVE-2008-4250"]),
    139: _vuln("NetBIOS Session","high",7.0,"NetBIOS expose des informations système.","Désactivez NetBIOS sur les interfaces publiques."),
    143: _vuln("IMAP Unencrypted","high",7.0,"IMAP transmet les emails en clair.","Utilisez IMAPS (port 993)."),
    161: _vuln("SNMP Community String","high",7.5,"SNMP avec community string par défaut est critique.","Changez les community strings. Utilisez SNMPv3.",["CVE-2012-3268"]),
    445: _vuln("SMB Service (CRITICAL)","critical",9.8,"SMB est la cible majeure de ransomwares (WannaCry, EternalBlue).","Bloquez SMB externe. Désactivez SMBv1. Appliquez les patches.",["CVE-2017-0144","CVE-2020-0796"]),
    512: _vuln("R-Services (rexec)","critical",9.0,"R-Services sont obsolètes et non sécurisés.","Désactivez tous les R-Services. Utilisez SSH."),
    1433:_vuln("MSSQL Exposed","critical",9.0,"SQL Server exposé sur Internet est critique.","N'exposez JAMAIS SQL Server. Utilisez VPN.",["CVE-2020-0618"]),
    1521:_vuln("Oracle DB Exposed","critical",9.0,"Oracle Database exposée.","Restreignez l'accès. Utilisez un firewall applicatif.",["CVE-2012-1675"]),
    2375:_vuln("Docker API Unprotected","critical",10.0,"Docker API sans TLS = accès root complet.","Utilisez TLS (port 2376). N'exposez jamais sur Internet."),
    3306:_vuln("MySQL Exposed","critical",9.0,"MySQL exposé sur Internet.","Bind à localhost. Utilisez des mots de passe forts.",["CVE-2012-2122"]),
    3389:_vuln("RDP Service (CRITICAL)","critical",9.8,"RDP est la cible n°1 des attaques brute-force et ransomwares.","N'exposez JAMAIS RDP. Utilisez VPN + NLA.",["CVE-2019-0708","CVE-2019-1181"]),
    5432:_vuln("PostgreSQL Exposed","critical",8.0,"PostgreSQL exposé sur Internet.","Configurez pg_hba.conf correctement."),
    5900:_vuln("VNC Remote Access","critical",9.0,"VNC a souvent un chiffrement faible ou absent.","Utilisez VNC uniquement via VPN/SSH tunnel.",["CVE-2019-15678"]),
    6379:_vuln("Redis NO AUTH (CRITICAL)","critical",10.0,"Redis sans auth = accès complet aux données + RCE possible.","Activez AUTH. Bind à localhost. Ne jamais exposer.",["CVE-2015-4335"]),
    9200:_vuln("Elasticsearch NO AUTH","critical",9.0,"Elasticsearch sans auth expose toutes les données.","Activez X-Pack Security. N'exposez jamais.",["CVE-2015-1427"]),
    11211:_vuln("Memcached Exposed","critical",9.0,"Memcached peut être utilisé pour amplification DDoS.","Bind à localhost. Désactivez UDP.",["CVE-2018-1000115"]),
    27017:_vuln("MongoDB NO AUTH (CRITICAL)","critical",10.0,"MongoDB sans auth = toutes les bases accessibles.","Activez auth. Bind à 127.0.0.1. Jamais sur Internet."),
}

# ── Signatures IDS ────────────────────────────────────────────

IDS_SIGNATURES = {
    "port_scan":   {"threshold":15, "window":60, "severity":"high",     "description":"Port scan détecté"},
    "brute_force": {"threshold":10, "window":60, "severity":"critical", "description":"Attaque brute-force détectée"},
    "syn_flood":   {"threshold":100,"window":10, "severity":"critical", "description":"SYN Flood détecté"},
    "dns_tunnel":  {"threshold":50, "window":60, "severity":"high",     "description":"DNS Tunneling potentiel"},
}

SUSPICIOUS_PORTS = {
    31337:"Back Orifice",12345:"NetBus",27374:"SubSeven",1234:"Backdoor",
    4444:"Metasploit",5555:"Android ADB",6666:"Backdoor/IRC",
    6667:"IRC (souvent malware)",31338:"Back Orifice",54321:"Backdoor",
}
