"""
attack/oauth_consent/app_registration.py — Définition d'une "app malveillante"
==============================================================================

Modélise l'enregistrement d'une application OAuth malveillante. En
condition réelle, l'attaquant enregistre une app multi-tenant sur
Azure AD (gratuit, self-service) ou Google Workspace Marketplace.

Ici on catalogue les configurations "dangereuses" pour le labo, avec
les scopes qui donnent le plus de pouvoir à l'attaquant.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from typing import List


@dataclass
class MaliciousApp:
    """
    Représente une app OAuth malveillante.

    Attributs :
        name             : nom affiché à l'utilisateur (doit être crédible)
        client_id        : ID unique (en labo : généré aléatoirement)
        tenant_id        : "common" (multi-tenant) en labo
        redirect_uri     : URL de callback (en labo : localhost)
        scope_string     : scopes OAuth en string séparée par espaces
        publisher_domain : domaine du publisher (default "unverified")
        is_admin_consent : True si admin consent workflow, False si user consent
        homepage_url     : URL affichée dans l'écran de consentement
        privacy_url      : URL de la fausse "politique de confidentialité"
        scopes           : liste des scopes OAuth demandés (pour rétrocompatibilité)
        publisher        : nom du publisher affiché
        icon             : emoji affiché dans la popup de consentement
    """

    name: str
    client_id: str
    redirect_uri: str
    scope_string: str = ""
    tenant_id: str = "common"
    publisher_domain: str = "unverified"
    is_admin_consent: bool = False
    homepage_url: str = "https://contoso-prod-suite.com"
    privacy_url: str = "https://contoso-prod-suite.com/privacy"
    scopes: list[str] = field(default_factory=list)
    publisher: str = "Contoso Inc."
    icon: str = "📊"

    def __post_init__(self):
        if self.scopes and not self.scope_string:
            self.scope_string = " ".join(self.scopes)
        elif self.scope_string and not self.scopes:
            self.scopes = self.scope_string.split(" ")


# ---------------------------------------------------------------------- #
# Catalogue d'apps "template" prêtes à l'emploi
# ---------------------------------------------------------------------- #

# Scopes Microsoft Graph les plus dangereux (par ordre de privilège)
DANGEROUS_MS_SCOPES = {
    "Mail.Read":           "Lire tous les mails de la victime",
    "Mail.ReadWrite":      "Lire, écrire, supprimer des mails",
    "Mail.Send":           "Envoyer des mails en tant que la victime (BEC)",
    "Files.ReadWrite.All": "Lire/écrire tous les fichiers OneDrive/SharePoint",
    "offline_access":      "Obtenir un refresh token durable (90 jours)",
    "User.Read":           "Lire le profil de base",
    "Calendars.ReadWrite": "Accéder au calendrier (préparation d'attaque)",
    "Contacts.ReadWrite":  "Vol de carnet d'adresses (futures cibles)",
    "Notes.ReadWrite.All": "Vol de notes OneNote",
    "Directory.Read.All":  "Énumérer l'annuaire de l'entreprise",
}

DANGEROUS_GOOGLE_SCOPES = {
    "https://www.googleapis.com/auth/gmail.readonly":     "Lire Gmail",
    "https://www.googleapis.com/auth/gmail.send":        "Envoyer des mails",
    "https://www.googleapis.com/auth/drive":             "Accès complet Drive",
    "https://www.googleapis.com/auth/calendar":          "Accès Calendar",
    "https://www.googleapis.com/auth/contacts":          "Carnet d'adresses",
    "https://www.googleapis.com/auth/photoslibrary.readonly": "Google Photos",
    "openid email profile":                              "Info de base",
}


# Apps "template" — chacune incarne un scénario d'attaque distinct
APP_TEMPLATES: list[MaliciousApp] = [
    MaliciousApp(
        name="SharePoint Analytics Pro",
        client_id="11111111-1111-1111-1111-111111111111",
        redirect_uri="http://localhost:9000/auth/callback",
        homepage_url="https://sharepoint-analytics-pro.com",
        privacy_url="https://sharepoint-analytics-pro.com/privacy",
        scopes=["User.Read", "Files.ReadWrite.All", "Mail.Read", "offline_access"],
        publisher="Productivity Labs",
        icon="📊",
    ),
    MaliciousApp(
        name="Calendar Sync Assistant",
        client_id="22222222-2222-2222-2222-222222222222",
        redirect_uri="http://localhost:9000/auth/callback",
        homepage_url="https://calendar-sync-assistant.io",
        privacy_url="https://calendar-sync-assistant.io/policy",
        scopes=["User.Read", "Calendars.ReadWrite", "Contacts.ReadWrite", "offline_access"],
        publisher="Schedule Solutions LLC",
        icon="📅",
    ),
    MaliciousApp(
        name="Mail Defender Plus",
        client_id="33333333-3333-3333-3333-333333333333",
        redirect_uri="http://localhost:9000/auth/callback",
        homepage_url="https://mail-defender-plus.com",
        privacy_url="https://mail-defender-plus.com/privacy",
        scopes=["User.Read", "Mail.Read", "Mail.ReadWrite", "offline_access"],
        publisher="SecureMail Corp",
        icon="🛡️",
    ),
    MaliciousApp(
        name="OneDrive Backup Wizard",
        client_id="44444444-4444-4444-4444-444444444444",
        redirect_uri="http://localhost:9000/auth/callback",
        homepage_url="https://onedrive-backup-wizard.com",
        privacy_url="https://onedrive-backup-wizard.com/legal",
        scopes=["User.Read", "Files.ReadWrite.All", "Notes.ReadWrite.All", "offline_access"],
        publisher="Cloud Backup Co",
        icon="☁️",
    ),
    MaliciousApp(
        name="HR Document Portal",
        client_id="55555555-5555-5555-5555-555555555555",
        redirect_uri="http://localhost:9000/auth/callback",
        homepage_url="https://hr-doc-portal.com",
        privacy_url="https://hr-doc-portal.com/policy",
        scopes=["User.Read", "Directory.Read.All", "Mail.Read", "offline_access"],
        publisher="HR Cloud Services",
        icon="📋",
    ),
]



def list_apps() -> list[MaliciousApp]:
    """Retourne tous les templates d'app disponibles."""
    return APP_TEMPLATES


def get_default_app() -> MaliciousApp:
    """Retourne le template par défaut (le plus dévastateur)."""
    return APP_TEMPLATES[0]


def generate_random_app(
    name: str = "Contoso Productivity Suite",
    redirect_uri: str = "http://localhost:9000/auth/callback",
) -> MaliciousApp:
    """
    Génère une app aléatoire avec un client_id UUID v4.
    Utile pour des opérations "burn-after-use" en labo.
    """
    return MaliciousApp(
        name=name,
        client_id=str(uuid.uuid4()),
        redirect_uri=redirect_uri,
        homepage_url="https://contoso-prod-suite.com",
        privacy_url="https://contoso-prod-suite.com/privacy",
        scopes=["User.Read", "Mail.Read", "Files.ReadWrite.All", "offline_access"],
        publisher="Contoso Inc.",
        icon="🚀",
    )


# --- Presets de classe (contrat attacks_all) ---------------------------
_MALICIOUS_APP_PRESETS = {
    "SHAREPOINT_ANALYTICS": MaliciousApp(
        name="SharePoint Analytics Pro",
        client_id=str(uuid.uuid4()),
        redirect_uri="https://attacker.invalid/callback",
        scope_string="Mail.Read Mail.ReadWrite Files.ReadWrite.All offline_access openid profile",
    ),
}
for _name, _app in _MALICIOUS_APP_PRESETS.items():
    setattr(MaliciousApp, _name, _app)
