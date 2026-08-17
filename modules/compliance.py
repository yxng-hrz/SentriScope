"""
Module de Conformité - SENTRISCOPE
Checklists: ISO 27001, RGPD (aspects techniques), CIS Controls
+ Niveaux de maturité CMMI, mapping croisé inter-frameworks
Focalisé sur la sécurité informatique et réseaux uniquement
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from enum import Enum
import json
from pathlib import Path


# ════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════

class ComplianceStatus(Enum):
    """Statut d'un contrôle de conformité"""
    NOT_EVALUATED = "Non évalué"
    COMPLIANT = "Conforme"
    PARTIAL = "Partiel"
    NON_COMPLIANT = "Non conforme"
    NOT_APPLICABLE = "N/A"


class MaturityLevel(Enum):
    """Niveau de maturité CMMI"""
    NOT_ASSESSED = ("Non évalué", 0, "⬜")
    INITIAL      = ("Initial",    1, "🔴")
    MANAGED      = ("Géré",       2, "🟠")
    DEFINED      = ("Défini",     3, "🟡")
    MEASURED     = ("Mesuré",     4, "🟢")
    OPTIMIZED    = ("Optimisé",   5, "🔵")

    def __init__(self, label: str, level: int, icon: str):
        self.label = label
        self.level = level
        self.icon = icon


# ════════════════════════════════════════════════════════════════
# Dataclasses
# ════════════════════════════════════════════════════════════════

@dataclass
class ComplianceControl:
    """Un contrôle de conformité"""
    id: str
    category: str
    title: str
    description: str
    status: ComplianceStatus = ComplianceStatus.NOT_EVALUATED
    maturity: MaturityLevel = MaturityLevel.NOT_ASSESSED
    notes: str = ""
    last_checked: str = ""

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'status': self.status.value,
            'maturity': self.maturity.name,
            'notes': self.notes,
            'last_checked': self.last_checked
        }


@dataclass
class ComplianceFramework:
    """Un framework de conformité complet"""
    id: str
    name: str
    version: str
    description: str
    controls: List[ComplianceControl] = field(default_factory=list)

    @property
    def total_controls(self) -> int:
        return len(self.controls)

    @property
    def compliant_count(self) -> int:
        return len([c for c in self.controls if c.status == ComplianceStatus.COMPLIANT])

    @property
    def partial_count(self) -> int:
        return len([c for c in self.controls if c.status == ComplianceStatus.PARTIAL])

    @property
    def non_compliant_count(self) -> int:
        return len([c for c in self.controls if c.status == ComplianceStatus.NON_COMPLIANT])

    @property
    def not_evaluated_count(self) -> int:
        return len([c for c in self.controls if c.status == ComplianceStatus.NOT_EVALUATED])

    @property
    def compliance_score(self) -> float:
        """Score de conformité en pourcentage (pondéré par maturité)"""
        applicable = [c for c in self.controls if c.status != ComplianceStatus.NOT_APPLICABLE]
        if not applicable:
            return 0.0

        score = 0.0
        for c in applicable:
            if c.status == ComplianceStatus.COMPLIANT:
                if c.maturity.level >= 1:
                    score += 0.6 + (c.maturity.level - 1) * 0.1
                else:
                    score += 1.0
            elif c.status == ComplianceStatus.PARTIAL:
                score += 0.3

        return (score / len(applicable)) * 100

    @property
    def avg_maturity(self) -> float:
        """Niveau de maturité moyen (0-5)"""
        assessed = [c for c in self.controls
                    if c.maturity != MaturityLevel.NOT_ASSESSED
                    and c.status != ComplianceStatus.NOT_APPLICABLE]
        if not assessed:
            return 0.0
        return sum(c.maturity.level for c in assessed) / len(assessed)

    def get_controls_by_category(self) -> Dict[str, List[ComplianceControl]]:
        """Grouper les contrôles par catégorie"""
        categories = {}
        for control in self.controls:
            if control.category not in categories:
                categories[control.category] = []
            categories[control.category].append(control)
        return categories


# ════════════════════════════════════════════════════════════════
# Contrôles NIS2 — Directive (UE) 2022/2555
# Articles 21 (mesures de gestion des risques) et 23 (notification)
# ════════════════════════════════════════════════════════════════

NIS2_CONTROLS = [
    # Art. 21(2)(a) — Politiques de sécurité
    ComplianceControl("NIS2-21.a.1", "Gouvernance", "Analyse des risques", "Politique d'analyse des risques et de sécurité des SI"),
    ComplianceControl("NIS2-21.a.2", "Gouvernance", "Politique de sécurité SI", "Politique globale de sécurité des systèmes d'information"),
    ComplianceControl("NIS2-21.a.3", "Gouvernance", "Responsabilité de la direction", "Approbation et supervision des mesures par la direction"),

    # Art. 21(2)(b) — Gestion des incidents
    ComplianceControl("NIS2-21.b.1", "Incidents", "Procédures de gestion d'incidents", "Processus de détection, analyse et réponse aux incidents"),
    ComplianceControl("NIS2-21.b.2", "Incidents", "Classification des incidents", "Grille de classification par impact et sévérité"),

    # Art. 21(2)(c) — Continuité d'activité
    ComplianceControl("NIS2-21.c.1", "Continuité", "Gestion de la continuité", "PCA/PRA documenté, testé et mis à jour"),
    ComplianceControl("NIS2-21.c.2", "Continuité", "Gestion des sauvegardes", "Sauvegardes régulières et tests de restauration"),
    ComplianceControl("NIS2-21.c.3", "Continuité", "Gestion de crise", "Procédures de gestion de crise cyber"),

    # Art. 21(2)(d) — Sécurité de la chaîne d'approvisionnement
    ComplianceControl("NIS2-21.d.1", "Supply chain", "Évaluation des fournisseurs", "Évaluation sécurité des fournisseurs critiques"),
    ComplianceControl("NIS2-21.d.2", "Supply chain", "Clauses contractuelles", "Exigences de sécurité dans les contrats fournisseurs"),
    ComplianceControl("NIS2-21.d.3", "Supply chain", "Suivi des sous-traitants", "Surveillance continue de la chaîne d'approvisionnement"),

    # Art. 21(2)(e) — Acquisition, développement, maintenance
    ComplianceControl("NIS2-21.e.1", "Développement", "Sécurité dans l'acquisition", "Exigences de sécurité à l'achat de SI"),
    ComplianceControl("NIS2-21.e.2", "Développement", "Développement sécurisé", "Pratiques de développement sécurisé (DevSecOps)"),
    ComplianceControl("NIS2-21.e.3", "Développement", "Gestion des vulnérabilités", "Divulgation et traitement des vulnérabilités"),

    # Art. 21(2)(f) — Évaluation de l'efficacité
    ComplianceControl("NIS2-21.f.1", "Évaluation", "Tests de sécurité", "Tests réguliers d'efficacité des mesures de cybersécurité"),
    ComplianceControl("NIS2-21.f.2", "Évaluation", "Audits de sécurité", "Audits internes et externes périodiques"),

    # Art. 21(2)(g) — Cyber-hygiène et formation
    ComplianceControl("NIS2-21.g.1", "Formation", "Cyber-hygiène", "Pratiques de base de cyber-hygiène documentées"),
    ComplianceControl("NIS2-21.g.2", "Formation", "Formation cybersécurité", "Programme de sensibilisation et formation du personnel"),

    # Art. 21(2)(h) — Cryptographie
    ComplianceControl("NIS2-21.h.1", "Cryptographie", "Politique de chiffrement", "Politique d'utilisation du chiffrement et de l'encryption"),

    # Art. 21(2)(i) — RH, contrôle d'accès, gestion des actifs
    ComplianceControl("NIS2-21.i.1", "Contrôle d'accès", "Sécurité RH", "Vérifications à l'embauche et procédures de départ"),
    ComplianceControl("NIS2-21.i.2", "Contrôle d'accès", "Contrôle d'accès logique", "Politique de gestion des identités et des accès"),
    ComplianceControl("NIS2-21.i.3", "Contrôle d'accès", "Gestion des actifs", "Inventaire et classification des actifs informationnels"),

    # Art. 21(2)(j) — MFA et authentification
    ComplianceControl("NIS2-21.j.1", "Authentification", "MFA / authentification forte", "Authentification multi-facteurs ou continue déployée"),
    ComplianceControl("NIS2-21.j.2", "Authentification", "Communications sécurisées", "Voix, vidéo et texte sécurisés en cas d'urgence"),

    # Art. 23 — Obligations de notification
    ComplianceControl("NIS2-23.1", "Notification", "Alerte précoce 24h", "Capacité de notification initiale sous 24h au CSIRT"),
    ComplianceControl("NIS2-23.2", "Notification", "Notification d'incident 72h", "Notification détaillée sous 72h avec évaluation d'impact"),
    ComplianceControl("NIS2-23.3", "Notification", "Rapport final 1 mois", "Rapport final dans un délai d'un mois après notification"),
    ComplianceControl("NIS2-23.4", "Notification", "Registre des incidents", "Tenue d'un registre des incidents significatifs"),
]


# ════════════════════════════════════════════════════════════════
# Matrice de mapping croisé inter-frameworks
# ════════════════════════════════════════════════════════════════

_RAW_MAPPINGS: List[Tuple[str, ...]] = [
    # ── Contrôle d'accès ────────────────────────────────────────
    ("A.9.1",  "RGPD-32.3", "CIS-6.1"),
    ("A.9.2",  "CIS-5.1"),
    ("A.9.3",  "CIS-5.4"),
    ("A.9.4",  "CIS-5.2"),
    ("A.9.5",  "CIS-5.3"),

    # ── Cryptographie ───────────────────────────────────────────
    ("A.10.1", "RGPD-32.2", "CIS-3.2", "CIS-3.3"),
    ("A.10.2", "RGPD-32.2"),

    # ── Sécurité opérationnelle ─────────────────────────────────
    ("A.12.2", "CIS-10.1", "CIS-10.2"),
    ("A.12.3", "RGPD-32.6", "CIS-11.1", "CIS-11.2", "CIS-11.3"),
    ("A.12.4", "CIS-8.1",  "CIS-8.2", "CIS-8.3"),
    ("A.12.5", "RGPD-32.7", "CIS-7.1", "CIS-7.2", "CIS-7.3"),

    # ── Sécurité réseau ─────────────────────────────────────────
    ("A.13.1", "CIS-12.1"),
    ("A.13.2", "CIS-12.2"),
    ("A.13.3", "CIS-12.3", "CIS-12.4"),

    # ── Développement sécurisé ──────────────────────────────────
    ("A.14.2", "RGPD-25.2"),

    # ── Incidents ───────────────────────────────────────────────
    ("A.16.1", "RGPD-33.1", "CIS-17.1"),
    ("A.16.2", "RGPD-33.2"),
    ("A.16.3", "CIS-17.2"),
    ("A.16.4", "CIS-17.3"),

    # ── Continuité / Disponibilité ──────────────────────────────
    ("A.17.1", "RGPD-32.5"),

    # ── Privacy by Design ───────────────────────────────────────
    ("RGPD-25.1", "CIS-3.1"),

    # ── Violations / Logs ───────────────────────────────────────
    ("RGPD-33.3", "CIS-8.3"),

    # ── Email / Web ─────────────────────────────────────────────
    ("CIS-9.1", "CIS-9.2"),

    # ── NIS2 → ISO 27001 ────────────────────────────────────────
    ("NIS2-21.a.1", "A.12.6"),
    ("NIS2-21.a.2", "A.9.1"),
    ("NIS2-21.b.1", "A.16.1", "CIS-17.1", "RGPD-33.1"),
    ("NIS2-21.b.2", "A.16.2"),
    ("NIS2-21.c.1", "A.17.1", "RGPD-32.5"),
    ("NIS2-21.c.2", "A.12.3", "CIS-11.1", "CIS-11.2"),
    ("NIS2-21.c.3", "A.17.2"),
    ("NIS2-21.d.1", "A.14.1"),
    ("NIS2-21.e.1", "A.14.1"),
    ("NIS2-21.e.2", "A.14.2", "RGPD-25.2"),
    ("NIS2-21.e.3", "A.12.5", "CIS-7.1", "CIS-7.2"),
    ("NIS2-21.f.1", "RGPD-32.7", "CIS-7.1"),
    ("NIS2-21.f.2", "A.12.6"),
    ("NIS2-21.g.1", "CIS-4.1"),
    ("NIS2-21.h.1", "A.10.1", "RGPD-32.2", "CIS-3.2"),
    ("NIS2-21.i.1", "A.9.2", "CIS-5.1"),
    ("NIS2-21.i.2", "A.9.1", "RGPD-32.3", "CIS-6.1"),
    ("NIS2-21.i.3", "CIS-1.1", "CIS-2.1"),
    ("NIS2-21.j.1", "CIS-6.1"),
    ("NIS2-23.1", "A.16.2", "RGPD-33.2"),
    ("NIS2-23.2", "RGPD-33.2"),
    ("NIS2-23.4", "RGPD-33.3", "CIS-8.3"),
]


def _build_cross_map() -> Dict[str, List[str]]:
    """Construit le dictionnaire bidirectionnel de correspondances."""
    mapping: Dict[str, set] = {}
    for group in _RAW_MAPPINGS:
        ids = list(group)
        for cid in ids:
            if cid not in mapping:
                mapping[cid] = set()
            mapping[cid].update(i for i in ids if i != cid)
    return {k: sorted(v) for k, v in mapping.items()}


CROSS_MAP: Dict[str, List[str]] = _build_cross_map()


# ════════════════════════════════════════════════════════════════
# Contrôles ISO 27001:2022
# ════════════════════════════════════════════════════════════════

ISO_27001_CONTROLS = [
    ComplianceControl("A.9.1", "Contrôle d'accès", "Politique de contrôle d'accès", "Règles de contrôle d'accès documentées et appliquées"),
    ComplianceControl("A.9.2", "Contrôle d'accès", "Gestion des accès utilisateurs", "Processus d'enregistrement et révocation des accès"),
    ComplianceControl("A.9.3", "Contrôle d'accès", "Droits d'accès privilégiés", "Gestion et contrôle des comptes à privilèges"),
    ComplianceControl("A.9.4", "Contrôle d'accès", "Gestion des mots de passe", "Politique de mots de passe robustes"),
    ComplianceControl("A.9.5", "Contrôle d'accès", "Revue des droits d'accès", "Revue périodique des droits d'accès"),
    ComplianceControl("A.10.1", "Cryptographie", "Politique cryptographique", "Politique d'utilisation du chiffrement"),
    ComplianceControl("A.10.2", "Cryptographie", "Gestion des clés", "Cycle de vie des clés cryptographiques"),
    ComplianceControl("A.11.1", "Sécurité physique", "Périmètre de sécurité", "Zones sécurisées définies et protégées"),
    ComplianceControl("A.11.2", "Sécurité physique", "Contrôle d'accès physique", "Contrôle des entrées aux zones sensibles"),
    ComplianceControl("A.11.3", "Sécurité physique", "Sécurité du câblage", "Protection des câbles réseau et électriques"),
    ComplianceControl("A.12.1", "Sécurité opérationnelle", "Procédures documentées", "Procédures d'exploitation documentées"),
    ComplianceControl("A.12.2", "Sécurité opérationnelle", "Protection anti-malware", "Antivirus/EDR déployé et à jour"),
    ComplianceControl("A.12.3", "Sécurité opérationnelle", "Sauvegardes", "Politique de sauvegarde et tests de restauration"),
    ComplianceControl("A.12.4", "Sécurité opérationnelle", "Journalisation", "Logs d'événements activés et surveillés"),
    ComplianceControl("A.12.5", "Sécurité opérationnelle", "Gestion des vulnérabilités", "Scans de vulnérabilités et patch management"),
    ComplianceControl("A.12.6", "Sécurité opérationnelle", "Audit des systèmes", "Audits de sécurité réguliers"),
    ComplianceControl("A.13.1", "Sécurité réseau", "Contrôles réseau", "Firewalls et contrôles réseau en place"),
    ComplianceControl("A.13.2", "Sécurité réseau", "Sécurité des services", "Services réseau sécurisés (TLS, VPN)"),
    ComplianceControl("A.13.3", "Sécurité réseau", "Segmentation réseau", "Séparation des réseaux (VLAN, DMZ)"),
    ComplianceControl("A.13.4", "Sécurité réseau", "Transfert d'information", "Sécurisation des échanges de données"),
    ComplianceControl("A.14.1", "Développement", "Exigences de sécurité", "Sécurité intégrée dans les spécifications"),
    ComplianceControl("A.14.2", "Développement", "Développement sécurisé", "Pratiques de développement sécurisé (OWASP)"),
    ComplianceControl("A.14.3", "Développement", "Tests de sécurité", "Tests de sécurité avant mise en production"),
    ComplianceControl("A.16.1", "Incidents", "Procédures d'incident", "Procédures de gestion des incidents de sécurité"),
    ComplianceControl("A.16.2", "Incidents", "Signalement", "Processus de signalement des incidents"),
    ComplianceControl("A.16.3", "Incidents", "Réponse aux incidents", "Capacité de réponse aux incidents"),
    ComplianceControl("A.16.4", "Incidents", "Analyse post-incident", "Retour d'expérience après incidents"),
    ComplianceControl("A.17.1", "Continuité", "Plan de continuité", "PCA/PRA documenté et testé"),
    ComplianceControl("A.17.2", "Continuité", "Redondance", "Systèmes critiques redondants"),
]


# ════════════════════════════════════════════════════════════════
# Contrôles RGPD — Aspects techniques
# ════════════════════════════════════════════════════════════════

RGPD_CONTROLS = [
    ComplianceControl("RGPD-32.1", "Sécurité technique", "Pseudonymisation", "Capacité de pseudonymiser les données"),
    ComplianceControl("RGPD-32.2", "Sécurité technique", "Chiffrement", "Chiffrement des données personnelles"),
    ComplianceControl("RGPD-32.3", "Sécurité technique", "Confidentialité des systèmes", "Contrôles d'accès aux systèmes"),
    ComplianceControl("RGPD-32.4", "Sécurité technique", "Intégrité des systèmes", "Protection contre les modifications non autorisées"),
    ComplianceControl("RGPD-32.5", "Sécurité technique", "Disponibilité", "Haute disponibilité et résilience"),
    ComplianceControl("RGPD-32.6", "Sécurité technique", "Restauration", "Capacité de restauration rapide"),
    ComplianceControl("RGPD-32.7", "Sécurité technique", "Tests de sécurité", "Tests réguliers des mesures de sécurité"),
    ComplianceControl("RGPD-33.1", "Violations", "Détection des violations", "Capacité de détecter les fuites de données"),
    ComplianceControl("RGPD-33.2", "Violations", "Notification 72h", "Processus de notification à la CNIL sous 72h"),
    ComplianceControl("RGPD-33.3", "Violations", "Documentation", "Registre des violations de données"),
    ComplianceControl("RGPD-25.1", "Privacy by Design", "Minimisation par défaut", "Collecte minimale de données par défaut"),
    ComplianceControl("RGPD-25.2", "Privacy by Design", "Sécurité dès la conception", "Sécurité intégrée dès la conception"),
    ComplianceControl("RGPD-17.1", "Droits techniques", "Effacement technique", "Capacité d'effacer les données sur demande"),
    ComplianceControl("RGPD-20.1", "Droits techniques", "Export des données", "Capacité d'exporter les données (portabilité)"),
]


# ════════════════════════════════════════════════════════════════
# Contrôles CIS v8
# ════════════════════════════════════════════════════════════════

CIS_CONTROLS = [
    ComplianceControl("CIS-1.1", "Inventaire", "Inventaire des actifs matériels", "Liste à jour de tous les équipements"),
    ComplianceControl("CIS-1.2", "Inventaire", "Détection des actifs non autorisés", "Détection automatique des nouveaux équipements"),
    ComplianceControl("CIS-2.1", "Inventaire", "Inventaire logiciel", "Liste à jour de tous les logiciels installés"),
    ComplianceControl("CIS-2.2", "Inventaire", "Logiciels autorisés", "Liste blanche des logiciels approuvés"),
    ComplianceControl("CIS-3.1", "Protection données", "Classification des données", "Données classifiées par sensibilité"),
    ComplianceControl("CIS-3.2", "Protection données", "Chiffrement au repos", "Données sensibles chiffrées sur disque"),
    ComplianceControl("CIS-3.3", "Protection données", "Chiffrement en transit", "Communications chiffrées (TLS)"),
    ComplianceControl("CIS-4.1", "Configuration", "Baselines de sécurité", "Configurations sécurisées standardisées"),
    ComplianceControl("CIS-4.2", "Configuration", "Durcissement réseau", "Équipements réseau durcis"),
    ComplianceControl("CIS-4.3", "Configuration", "Durcissement serveurs", "Serveurs durcis selon CIS Benchmarks"),
    ComplianceControl("CIS-5.1", "Comptes", "Inventaire des comptes", "Liste de tous les comptes utilisateurs"),
    ComplianceControl("CIS-5.2", "Comptes", "Comptes par défaut désactivés", "Comptes par défaut supprimés/désactivés"),
    ComplianceControl("CIS-5.3", "Comptes", "Comptes dormants", "Comptes inactifs désactivés automatiquement"),
    ComplianceControl("CIS-5.4", "Comptes", "Comptes privilégiés", "Comptes admin limités et surveillés"),
    ComplianceControl("CIS-6.1", "Accès", "MFA activé", "Authentification multi-facteurs déployée"),
    ComplianceControl("CIS-6.2", "Accès", "SSO centralisé", "Authentification centralisée (AD, LDAP)"),
    ComplianceControl("CIS-7.1", "Vulnérabilités", "Scans automatisés", "Scans de vulnérabilités réguliers"),
    ComplianceControl("CIS-7.2", "Vulnérabilités", "Patch management", "Correctifs appliqués dans les délais"),
    ComplianceControl("CIS-7.3", "Vulnérabilités", "Vulnérabilités critiques", "Vulnérabilités critiques corrigées sous 48h"),
    ComplianceControl("CIS-8.1", "Logs", "Collecte des logs", "Logs collectés sur tous les systèmes"),
    ComplianceControl("CIS-8.2", "Logs", "SIEM centralisé", "Logs centralisés et corrélés"),
    ComplianceControl("CIS-8.3", "Logs", "Rétention des logs", "Logs conservés selon la politique"),
    ComplianceControl("CIS-9.1", "Email/Web", "Filtrage email", "Antispam et anti-phishing actifs"),
    ComplianceControl("CIS-9.2", "Email/Web", "Filtrage web", "Proxy web avec filtrage URL"),
    ComplianceControl("CIS-10.1", "Anti-malware", "EDR/Antivirus", "Solution anti-malware sur tous les postes"),
    ComplianceControl("CIS-10.2", "Anti-malware", "Signatures à jour", "Mises à jour automatiques des signatures"),
    ComplianceControl("CIS-11.1", "Sauvegarde", "Sauvegardes automatisées", "Sauvegardes régulières automatiques"),
    ComplianceControl("CIS-11.2", "Sauvegarde", "Tests de restauration", "Tests de restauration périodiques"),
    ComplianceControl("CIS-11.3", "Sauvegarde", "Sauvegardes hors site", "Copies de sauvegarde externalisées"),
    ComplianceControl("CIS-12.1", "Réseau", "Firewall périmétrique", "Firewall en bordure de réseau"),
    ComplianceControl("CIS-12.2", "Réseau", "IDS/IPS", "Détection/prévention d'intrusion"),
    ComplianceControl("CIS-12.3", "Réseau", "Segmentation", "Réseaux segmentés par zone"),
    ComplianceControl("CIS-12.4", "Réseau", "Wifi sécurisé", "Réseaux wifi avec WPA3/802.1X"),
    ComplianceControl("CIS-17.1", "Incidents", "Plan de réponse", "Plan de réponse aux incidents documenté"),
    ComplianceControl("CIS-17.2", "Incidents", "Équipe de réponse", "Équipe de réponse identifiée et formée"),
    ComplianceControl("CIS-17.3", "Incidents", "Exercices", "Exercices de simulation réguliers"),
]


# ════════════════════════════════════════════════════════════════
# ComplianceManager
# ════════════════════════════════════════════════════════════════

class ComplianceManager:
    """Gestionnaire de conformité SENTRISCOPE"""

    def __init__(self, data_dir: Path = None):
        if data_dir is None:
            data_dir = Path(__file__).parent.parent / "data"
        self.data_dir = data_dir
        self.data_dir.mkdir(exist_ok=True)
        self.frameworks: Dict[str, ComplianceFramework] = {}
        self._init_frameworks()

    def _init_frameworks(self):
        self.frameworks['iso27001'] = ComplianceFramework(
            id='iso27001', name='ISO 27001', version='2022',
            description="Sécurité de l'information - Contrôles techniques",
            controls=[ComplianceControl(**c.__dict__) for c in ISO_27001_CONTROLS]
        )
        self.frameworks['rgpd'] = ComplianceFramework(
            id='rgpd', name='RGPD', version='2018',
            description='Protection des données - Aspects techniques',
            controls=[ComplianceControl(**c.__dict__) for c in RGPD_CONTROLS]
        )
        self.frameworks['cis'] = ComplianceFramework(
            id='cis', name='CIS Controls', version='v8',
            description='Critical Security Controls',
            controls=[ComplianceControl(**c.__dict__) for c in CIS_CONTROLS]
        )
        self.frameworks['nis2'] = ComplianceFramework(
            id='nis2', name='NIS2', version='2022/2555',
            description='Directive européenne — Sécurité des réseaux et SI',
            controls=[ComplianceControl(**c.__dict__) for c in NIS2_CONTROLS]
        )
        self._load_data()

    # ── Persistance ─────────────────────────────────────────────

    def _load_data(self):
        data_file = self.data_dir / "compliance_data.json"
        if data_file.exists():
            try:
                with open(data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                status_map = {s.value: s for s in ComplianceStatus}
                maturity_map = {m.name: m for m in MaturityLevel}

                for framework_id, controls_data in data.items():
                    if framework_id in self.frameworks:
                        # Index par id pour passer de O(N²) à O(N)
                        controls_by_id = {c.id: c for c in self.frameworks[framework_id].controls}
                        for ctrl_id, saved in controls_data.items():
                            control = controls_by_id.get(ctrl_id)
                            if control is None:
                                continue
                            control.status = status_map.get(
                                saved.get('status', 'Non évalué'),
                                ComplianceStatus.NOT_EVALUATED
                            )
                            control.maturity = maturity_map.get(
                                saved.get('maturity', 'NOT_ASSESSED'),
                                MaturityLevel.NOT_ASSESSED
                            )
                            control.notes = saved.get('notes', '')
                            control.last_checked = saved.get('last_checked', '')
            except Exception as e:
                print(f"Erreur chargement compliance: {e}")

    def save_data(self):
        data = {}
        for framework_id, framework in self.frameworks.items():
            data[framework_id] = {}
            for control in framework.controls:
                data[framework_id][control.id] = {
                    'status': control.status.value,
                    'maturity': control.maturity.name,
                    'notes': control.notes,
                    'last_checked': control.last_checked
                }

        data_file = self.data_dir / "compliance_data.json"
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ── Accès aux données ───────────────────────────────────────

    def get_framework(self, framework_id: str) -> Optional[ComplianceFramework]:
        return self.frameworks.get(framework_id)

    def get_all_frameworks(self) -> List[ComplianceFramework]:
        return list(self.frameworks.values())

    def update_control(self, framework_id: str, control_id: str,
                       status: ComplianceStatus = None,
                       maturity: MaturityLevel = None,
                       notes: str = None,
                       checked_by: str = None) -> bool:
        framework = self.frameworks.get(framework_id)
        if not framework:
            return False

        for control in framework.controls:
            if control.id == control_id:
                if status is not None:
                    control.status = status
                if maturity is not None:
                    control.maturity = maturity
                if notes is not None:
                    control.notes = notes
                control.last_checked = datetime.now().strftime('%Y-%m-%d %H:%M')
                self.save_data()
                return True
        return False

    # ── Mapping croisé ──────────────────────────────────────────

    def get_mapped_controls(self, control_id: str) -> List[Tuple[str, str, ComplianceControl]]:
        """
        Retourne les contrôles liés dans les autres frameworks.
        Résultat : [(framework_id, framework_name, control), ...]
        """
        mapped_ids = CROSS_MAP.get(control_id, [])
        results = []
        for fid, fw in self.frameworks.items():
            for ctrl in fw.controls:
                if ctrl.id in mapped_ids:
                    results.append((fid, fw.name, ctrl))
        return results

    # ── Scores & résumé ─────────────────────────────────────────

    def get_global_score(self) -> float:
        total_score = 0
        count = 0
        for framework in self.frameworks.values():
            if framework.total_controls > 0:
                total_score += framework.compliance_score
                count += 1
        return total_score / count if count > 0 else 0

    def get_global_maturity(self) -> float:
        levels = []
        for fw in self.frameworks.values():
            avg = fw.avg_maturity
            if avg > 0:
                levels.append(avg)
        return sum(levels) / len(levels) if levels else 0.0

    def get_summary(self) -> Dict:
        summary = {
            'global_score': self.get_global_score(),
            'global_maturity': self.get_global_maturity(),
            'frameworks': []
        }
        for framework in self.frameworks.values():
            summary['frameworks'].append({
                'id': framework.id,
                'name': framework.name,
                'score': framework.compliance_score,
                'maturity': framework.avg_maturity,
                'total': framework.total_controls,
                'compliant': framework.compliant_count,
                'partial': framework.partial_count,
                'non_compliant': framework.non_compliant_count,
                'not_evaluated': framework.not_evaluated_count
            })
        return summary

    def get_priority_actions(self, limit: int = 5) -> List[Dict]:
        """
        Retourne les actions prioritaires :
        Non conformes > Partiels > Non évalués.
        Pondéré par impact transversal (nb de mappings croisés).
        """
        actions = []
        for fw in self.frameworks.values():
            for ctrl in fw.controls:
                if ctrl.status in (ComplianceStatus.NON_COMPLIANT,
                                   ComplianceStatus.PARTIAL,
                                   ComplianceStatus.NOT_EVALUATED):
                    if ctrl.status == ComplianceStatus.NON_COMPLIANT:
                        weight = 3
                    elif ctrl.status == ComplianceStatus.PARTIAL:
                        weight = 2
                    else:
                        weight = 1

                    cross_count = len(CROSS_MAP.get(ctrl.id, []))
                    actions.append({
                        'framework': fw.name,
                        'framework_id': fw.id,
                        'control': ctrl,
                        'weight': weight,
                        'cross_impact': cross_count,
                        'sort_key': (weight * 10) + cross_count
                    })

        actions.sort(key=lambda a: a['sort_key'], reverse=True)
        return actions[:limit]


# Instance globale
compliance_manager = ComplianceManager()
