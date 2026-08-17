"""
SENTRISCOPE — Views (lazy loading)
"""
import importlib as _importlib

# Seul le login est chargé immédiatement (nécessaire avant l'app)
from views.login import LoginWindow

_LAZY_MAP = {
    'DashboardPage':       'views.dashboard',
    'ScanPage':            'views.scan',
    'MonitorPage':         'views.monitor',
    'ConnectionsPage':     'views.connections',
    'GeoIPDetailWindow':   'views.connections',
    'ProcessesPage':       'views.processes',
    'VulnerabilitiesPage': 'views.vulnerabilities',
    'IDSPage':             'views.ids',
    'InterfacesPage':      'views.interfaces',
    'ReportsPage':         'views.reports',
    'CompliancePage':      'views.compliance',
    'SettingsPage':        'views.settings',
    'PasswordPolicyPage':  'views.password_policy',
}

def __getattr__(name):
    if name in _LAZY_MAP:
        mod = _importlib.import_module(_LAZY_MAP[name])
        return getattr(mod, name)
    raise AttributeError(f"module 'views' has no attribute {name!r}")

__all__ = [
    "LoginWindow",
    "DashboardPage", "ScanPage", "MonitorPage", "ConnectionsPage",
    "GeoIPDetailWindow", "ProcessesPage", "VulnerabilitiesPage",
    "IDSPage", "InterfacesPage", "ReportsPage", "CompliancePage",
    "SettingsPage", "PasswordPolicyPage",
]
