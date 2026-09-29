"""
attack/oauth_consent — Illicit OAuth Consent Grant (ILoveYou.pdf)
================================================================

Implémente l'attaque "Illicit Consent" : au lieu de voler le password,
on pousse l'utilisateur à autoriser une application OAuth tierce
malveillante avec des scopes dangereux (Mail.Read, Files.ReadWrite,
offline_access). L'attaquant obtient un **refresh token durable**
sans jamais avoir le mot de passe.

Pourquoi c'est dévastateur :
- Le password n'est jamais transmis à l'attaquant
- Marche même avec FIDO2 activé
- Refresh token peut durer 90 jours (Microsoft) / 7-30 jours (Google)
- Accès mailbox → pivot BEC (Business Email Compromise)
- Accès fichiers → vol de données, ransomware
- Marche via une simple URL de consentement (l'utilisateur clique)

Contre-mesures Blue Team (phase 2) :
- Bloquer le consent user-facing (forcer admin consent workflow)
- Bloquer les apps multi-tenant
- Bloquer les scopes dangereux en self-service
- Alerter sur les nouveaux consent grants
- Conditional Access : bloquer les apps non-approuvées
- Microsoft Defender for Cloud Apps : détecter les consent attacks

Architecture du module :
- `mock_provider.py` : serveur FastAPI qui imite Entra ID pour le labo
- `app_registration.py` : génère la config d'une "app malveillante"
- `consent_url.py` : produit l'URL d'attaque
- `token_exfil.py` : récupère et stocke les tokens

Usage typique (en labo isolé) :
    # Terminal 1 : démarrer le mock provider
    python -m attack.oauth_consent.mock_provider

    # Terminal 2 : générer l'URL d'attaque
    python -c "from attack.oauth_consent import generate_attack_url; print(generate_attack_url())"
"""

from .app_registration import MaliciousApp, get_default_app, list_apps
from .consent_url import build_consent_url, generate_attack_url
from .token_exfil import (
    CapturedToken,
    TokenExfilEndpoint,
    clear_tokens,
    get_token,
    list_tokens,
    mint_token_from_code,
    register_token_routes,
    store_token,
)

__all__ = [
    "CapturedToken",
    "MaliciousApp",
    "TokenExfilEndpoint",
    "build_consent_url",
    "clear_tokens",
    "generate_attack_url",
    "get_default_app",
    "get_token",
    "list_apps",
    "list_tokens",
    "mint_token_from_code",
    "register_token_routes",
    "store_token",
]
