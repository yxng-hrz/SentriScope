"""
SENTRISCOPE - Security Audit Platform - Modules (lazy loading)
"""
import importlib as _importlib

# ── Eager: léger, nécessaire au démarrage ──────────────────────
from modules.config import (
    THEME, COMMON_PORTS, TOP_PORTS, SERVICE_NAMES, VULNERABILITY_DB,
    theme_manager, ThemeManager, DARK_THEME, LIGHT_THEME
)
from modules.database import Database, User, db

# ── Lazy: chargé uniquement au premier accès ───────────────────
_LAZY_MAP = {
    # scanner
    'NetworkScanner': 'modules.scanner', 'PortScanner': 'modules.scanner',
    'ServiceDetector': 'modules.scanner', 'HostResult': 'modules.scanner',
    'PortResult': 'modules.scanner', 'ScanResult': 'modules.scanner',
    'NmapScanner': 'modules.scanner', 'nmap_scanner': 'modules.scanner',
    # monitor
    'NetworkMonitor': 'modules.monitor', 'ConnectionMonitor': 'modules.monitor',
    'SystemMonitor': 'modules.monitor', 'ProcessMonitor': 'modules.monitor',
    'InterfaceMonitor': 'modules.monitor', 'NetworkStats': 'modules.monitor',
    'ConnectionInfo': 'modules.monitor',
    'ProcessInfo': 'modules.monitor',
    # security
    'VulnerabilityScanner': 'modules.security', 'IntrusionDetector': 'modules.security',
    'Vulnerability': 'modules.security', 'SecurityAlert': 'modules.security',
    'intrusion_detector': 'modules.security',
    # reports
    'ReportGenerator': 'modules.reports',
    # email
    'EmailService': 'modules.email_service', 'email_service': 'modules.email_service',
    # compliance
    'ComplianceManager': 'modules.compliance', 'ComplianceFramework': 'modules.compliance',
    'ComplianceControl': 'modules.compliance', 'ComplianceStatus': 'modules.compliance',
    'MaturityLevel': 'modules.compliance', 'CROSS_MAP': 'modules.compliance',
    'compliance_manager': 'modules.compliance',
    # geo_ip
    'GeoIPService': 'modules.geo_ip', 'GeoResult': 'modules.geo_ip',
    'geo_ip': 'modules.geo_ip',
}

def __getattr__(name):
    if name in _LAZY_MAP:
        mod = _importlib.import_module(_LAZY_MAP[name])
        return getattr(mod, name)
    raise AttributeError(f"module 'modules' has no attribute {name!r}")

__all__ = [
    # Config
    'THEME', 'COMMON_PORTS', 'TOP_PORTS', 'SERVICE_NAMES', 'VULNERABILITY_DB',
    'theme_manager', 'ThemeManager', 'DARK_THEME', 'LIGHT_THEME',
    # Scanner
    'NetworkScanner', 'PortScanner', 'ServiceDetector', 'HostResult', 'PortResult', 'ScanResult',
    'NmapScanner', 'nmap_scanner',
    # Monitor
    'NetworkMonitor', 'ConnectionMonitor', 'SystemMonitor', 'ProcessMonitor',
    'InterfaceMonitor', 'NetworkStats', 'ConnectionInfo', 'ProcessInfo',
    # Security
    'VulnerabilityScanner', 'IntrusionDetector', 'Vulnerability', 'SecurityAlert',
    'intrusion_detector',
    # Reports
    'ReportGenerator',
    # Database & Auth
    'Database', 'User', 'db',
    # Email
    'EmailService', 'email_service',
    # Compliance
    'ComplianceManager', 'ComplianceFramework', 'ComplianceControl', 'ComplianceStatus',
    'MaturityLevel', 'CROSS_MAP',
    'compliance_manager',
    # Geo IP
    'GeoIPService', 'GeoResult', 'geo_ip',
]
