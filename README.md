# SENTRISCOPE v2.9 — Security Audit Platform

## Installation

```bash
pip install -r requirements.txt
```

## Lancement

```bash
python main.py
```

**Compte par défaut** : `admin` / `admin`

## Changements v2.9

### Bugs corrigés
- **`views/dashboard.py`** : `v.title` → `v.name` sur `Vulnerability` (les vulns critiques apparaissent désormais dans le panneau « Actions prioritaires »)
- **`views/dashboard.py`** : `NetworkMonitor` désormais arrêté dans `on_hide()` (plus de thread orphelin quand on quitte le dashboard)
- **`views/dashboard.py`** : import `ImageGrab` dédupliqué dans `_capture_dashboard`
- **`modules/monitor.py`** : suppression du `d, h, m = up.days, *divmod(...)` dont les variables n'étaient pas utilisées
- **`modules/scanner.py`** : `_parse_target` valide les octets 0-255 et rejette les ranges inversés (`192.168.1.300-500` lève une `ValueError` propre)
- **`modules/scanner.py`** : tous les `except:` nus remplacés par des exceptions précises (`socket.error`, `subprocess.SubprocessError`, etc.)
- **`modules/database.py`** : context manager `_conn()` partout — plus de fuite de connexion si une exception lève
- **`modules/database.py`** : `update_user(**{})` retourne `True` (no-op légitime, pas une erreur)
- **`modules/compliance.py`** : `_load_data()` passe de O(N²) à O(N) via dict lookup
- **`widgets/helpers.py`** : `setup_tree_columns` fixe `stretch=False`, `anchor`, `minwidth=40`
- **`views/monitor.py`** : trim du buffer d'historique réécrit (boucle qui supprime les plus vieilles lignes de données, pas une ligne fixe)

### Nouveau
- **IDS désormais fonctionnel** : `IntrusionDetector` est un singleton (`intrusion_detector` exporté depuis `modules`), et un thread feeder lit `ConnectionMonitor` toutes les 3 s pour alimenter le moteur. La blacklist persiste entre navigations.
- **Historique de scan persisté** : chaque scan terminé est sauvegardé dans `scan_history` (table SQLite déjà existante, simplement appelée depuis `views/scan.py:on_scan_complete`)
- **`SystemStats` retiré** du lazy map de `modules/__init__.py` (était listé mais la classe n'existe plus depuis v2.7)
- **Versions cohérentes** : v2.9 partout (main.py, reports.py, README, _TOOL_NAME)

## Structure

```
├── main.py                 # Point d'entrée
├── modules/
│   ├── config.py           # Thème, ports, vulnérabilités
│   ├── database.py         # SQLite (users, scans, settings) — context manager
│   ├── scanner.py          # Scan réseau + Nmap
│   ├── security.py         # Vulnérabilités + IDS (singleton + feeder)
│   ├── monitor.py          # Monitoring système/réseau
│   ├── compliance.py       # ISO 27001, RGPD, CIS, NIS2
│   ├── reports.py          # Export HTML/PDF/JSON/CSV/TXT
│   ├── email_service.py    # SMTP auto-détection
│   ├── geo_ip.py           # Géolocalisation IP
│   └── password_policy.py  # Audit politique mots de passe
├── views/                  # Pages UI (lazy loaded)
└── widgets/                # Composants réutilisables
    ├── helpers.py          # Fonctions partagées
    ├── base.py, cards.py, gauge.py, nav.py
```
