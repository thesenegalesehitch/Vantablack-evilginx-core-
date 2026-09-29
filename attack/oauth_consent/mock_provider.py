"""
attack/oauth_consent/mock_provider.py — Mock OAuth provider (labo uniquement)
============================================================================

Ce module lance un serveur FastAPI qui imite le comportement d'Entra ID
et Google OAuth pour le flow Authorization Code Grant. UNIQUEMENT POUR LABO.

Endpoints imités :
    GET  /oauth/authorize  → écran de consentement (HTML) Allow / Deny
    POST /oauth/token      → échange code contre access_token JWT + refresh_token

Support PKCE : vérifie code_challenge (méthodes plain ou S256) si présent.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from datetime import datetime
from typing import Any, Optional

import uvicorn
import jwt as pyjwt
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .app_registration import APP_TEMPLATES, get_default_app
from .consent_url import build_consent_url

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] OAUTH_MOCK: %(message)s",
)
logger = logging.getLogger("oauth.mock")

app = FastAPI(title="Vantablack OAuth Mock Provider (labo)")

_MOCK_JWT_SECRET = "vantablack-mock-jwt-secret-key"
_MOCK_JWT_ALGO = "HS256"

_PENDING_CODES: dict[str, dict[str, Any]] = {}
_PENDING_PKCE: dict[str, dict[str, str]] = {}


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #

def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _mint_mock_jwt(sub: str, scopes: str, ttl_seconds: int, extra: Optional[dict] = None) -> str:
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
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, _MOCK_JWT_SECRET, algorithm=_MOCK_JWT_ALGO)


def _pkce_check(code: str, code_verifier: Optional[str]) -> bool:
    info = _PENDING_PKCE.get(code)
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


# ---------------------------------------------------------------------- #
# GET /oauth/authorize — affiche la popup de consentement Allow / Deny
# ---------------------------------------------------------------------- #

@app.get("/oauth/authorize")
async def authorize(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(""),
    state: str = Query(""),
    response_type: str = Query("code"),
    code_challenge: str = Query(""),
    code_challenge_method: str = Query("S256"),
    prompt: str = Query("consent"),
):
    """Affiche l'écran de consentement factice (Microsoft-like / Google-like)."""
    if response_type != "code":
        raise HTTPException(400, "response_type must be 'code'")

    app_obj = next((a for a in APP_TEMPLATES if a.client_id == client_id), None)
    if app_obj is None:
        app_obj = get_default_app()
        app_obj.client_id = client_id
    app_obj.redirect_uri = redirect_uri
    if scope:
        app_obj.scope_string = scope
        app_obj.scopes = scope.split(" ")

    session_id = secrets.token_urlsafe(16)
    _PENDING_CODES[session_id] = {
        "client_id": client_id,
        "scope": scope or app_obj.scope_string,
        "state": state,
        "redirect_uri": redirect_uri,
        "app_name": app_obj.name,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    scopes_list = (scope or app_obj.scope_string).split(" ")
    scopes_html = "\n".join(
        f"<li><strong>{html_escape(s)}</strong></li>"
        for s in scopes_list if s
    )

    is_unverified = app_obj.publisher_domain == "unverified"
    warning_block = (
        '<div style="background:#fff4ce;border-left:4px solid #fcd116;'
        'padding:12px;margin:16px 0;font-size:13px">'
        '⚠️ This app has not been verified by Microsoft or Google. '
        'Only consent if you trust the publisher.</div>'
    ) if is_unverified else ""

    consent_banner = (
        '<div style="background:#e7f3ff;border-left:4px solid #0078d4;'
        'padding:12px;margin:16px 0;font-size:13px">'
        '🔐 <strong>Admin consent requested</strong>: This app requires '
        'permissions that only an administrator can grant.</div>'
    ) if app_obj.is_admin_consent else ""

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Permissions requested — {html_escape(app_obj.name)}</title>
  <style>
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #f5f5f5; margin: 0; padding: 40px 20px;
      display: flex; justify-content: center; align-items: flex-start;
      min-height: 100vh;
    }}
    .card {{
      background: #fff; max-width: 520px; width: 100%;
      box-shadow: 0 2px 12px rgba(0,0,0,0.10);
      padding: 32px; border-radius: 8px;
    }}
    h1 {{ font-size: 20px; font-weight: 600; margin: 0 0 24px; color:#201f1e; }}
    .app {{
      display: flex; align-items: center; gap: 12px;
      padding: 12px 0; border-bottom: 1px solid #edebe9;
    }}
    .app-icon {{
      width: 48px; height: 48px; background: #0078d4; color: #fff;
      border-radius: 6px; display: flex; align-items: center; justify-content: center;
      font-size: 24px;
    }}
    .app-name {{ font-weight: 600; font-size: 16px; }}
    .app-pub {{ font-size: 12px; color: #605e5c; margin-top: 2px; }}
    .publisher-domain {{ font-size: 11px; color: #a80000; margin-top: 4px; }}
    .section-title {{
      font-size: 13px; font-weight: 600; color: #323130;
      margin: 20px 0 8px; letter-spacing: 0.2px;
    }}
    .scopes ul {{ padding-left: 20px; margin: 0; }}
    .scopes li {{ margin: 8px 0; font-size: 14px; color: #323130; }}
    .actions {{ display: flex; gap: 10px; margin-top: 28px; }}
    .btn {{
      flex: 1; padding: 12px 16px; border: none; border-radius: 4px;
      font-size: 14px; cursor: pointer; font-weight: 600;
      transition: background .15s ease;
    }}
    .btn-deny {{ background: #f3f2f1; color: #323130; border: 1px solid #c8c6c4; }}
    .btn-deny:hover {{ background: #edebe9; }}
    .btn-allow {{ background: #0078d4; color: #fff; }}
    .btn-allow:hover {{ background: #106ebe; }}
    .footer {{ font-size: 11px; color: #8a8886; margin-top: 20px; text-align: center; }}
    .footer strong {{ color: #a80000; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Permissions requested</h1>
    <div class="app">
      <div class="app-icon">{app_obj.icon}</div>
      <div>
        <div class="app-name">{html_escape(app_obj.name)}</div>
        <div class="app-pub">{html_escape(app_obj.publisher)}</div>
        <div class="publisher-domain">Publisher domain: {html_escape(app_obj.publisher_domain)}</div>
      </div>
    </div>

    {warning_block}
    {consent_banner}

    <div class="section-title">This app wants to:</div>
    <div class="scopes">
      <ul>
        {scopes_html}
      </ul>
    </div>

    <div class="section-title">You are signed in as:</div>
    <div style="font-size:14px;color:#323130;padding:8px 0">victim@entreprise.local</div>

    <p style="font-size:13px;color:#605e5c;margin-top:20px;line-height:1.5">
      By selecting <strong>Allow</strong>, you authorize this app to access
      the resources listed above on your behalf. You can revoke these
      permissions at any time in your account settings.
    </p>

    <form method="post" action="/oauth/authorize/decision">
      <input type="hidden" name="session_id" value="{session_id}">
      <input type="hidden" name="user" value="victim@entreprise.local">
      <div class="actions">
        <button type="submit" name="decision" value="deny" class="btn btn-deny">Deny</button>
        <button type="submit" name="decision" value="allow" class="btn btn-allow">Allow</button>
      </div>
    </form>

    <div class="footer">
      Mock OAuth Provider — <strong>Vantablack LAB ONLY</strong><br>
      <em>Do not use outside an isolated test environment.</em>
    </div>
  </div>
</body>
</html>""")


# ---------------------------------------------------------------------- #
# POST /oauth/authorize/decision — la victime clique sur Allow/Deny
# ---------------------------------------------------------------------- #

@app.post("/oauth/authorize/decision")
async def authorize_decision(
    session_id: str = Form(...),
    user: str = Form(...),
    decision: str = Form(...),
):
    """Traite Allow/Deny et redirige vers le redirect_uri de l'attaquant."""
    if session_id not in _PENDING_CODES:
        raise HTTPException(400, "Invalid session_id")

    info = _PENDING_CODES.pop(session_id)

    if decision == "deny":
        logger.info("[MOCK] Victim %s DENIED consent for %s", user, info["app_name"])
        params = (
            f"error=access_denied&"
            f"error_description=The+user+denied+consent&"
            f"state={info['state']}"
        )
        return RedirectResponse(url=f"{info['redirect_uri']}?{params}", status_code=302)

    code = secrets.token_urlsafe(32)
    _PENDING_CODES[code] = {**info, "user": user}

    if info.get("code_challenge"):
        _PENDING_PKCE[code] = {
            "code_challenge": info["code_challenge"],
            "code_challenge_method": info["code_challenge_method"],
        }

    logger.info("[MOCK] Victim %s ALLOWED consent for %s", user, info["app_name"])
    return RedirectResponse(
        url=f"{info['redirect_uri']}?code={code}&state={info['state']}",
        status_code=302,
    )


# ---------------------------------------------------------------------- #
# POST /oauth/token — échange code contre tokens (standard OAuth)
# ---------------------------------------------------------------------- #

@app.post("/oauth/token")
async def token_exchange(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(""),
    code: str = Form(""),
    redirect_uri: str = Form(""),
    code_verifier: str = Form(""),
    refresh_token: str = Form(""),
    scope: str = Form(""),
):
    """Endpoint standard OAuth2 /token. Support authorization_code et refresh_token."""

    if grant_type == "authorization_code":
        if code not in _PENDING_CODES:
            raise HTTPException(400, "Invalid or expired authorization code")

        info = _PENDING_CODES.pop(code)
        if client_id != info["client_id"]:
            raise HTTPException(400, "client_id mismatch")

        if not _pkce_check(code, code_verifier or None):
            raise HTTPException(400, "Invalid PKCE code_verifier")
        _PENDING_PKCE.pop(code, None)

        user = info.get("user", "victim@entreprise.local")
        resolved_scope = info.get("scope") or scope or "User.Read Mail.Read offline_access"
        resolved_redirect = info.get("redirect_uri", redirect_uri)
        if redirect_uri and redirect_uri != resolved_redirect:
            raise HTTPException(400, "redirect_uri mismatch")

    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(400, "refresh_token required")
        try:
            decoded = pyjwt.decode(
                refresh_token,
                _MOCK_JWT_SECRET,
                algorithms=[_MOCK_JWT_ALGO],
                options={"verify_exp": False},
            )
        except Exception:
            raise HTTPException(400, "Invalid refresh_token")
        user = decoded.get("sub", "victim@entreprise.local")
        resolved_scope = scope or decoded.get("scp", "User.Read Mail.Read offline_access")

    else:
        raise HTTPException(400, f"Unsupported grant_type: {grant_type!r}")

    access_token = _mint_mock_jwt(
        sub=user,
        scopes=resolved_scope,
        ttl_seconds=3600,
        extra={"appid": client_id, "name": user, "oid": secrets.token_hex(16)},
    )

    refresh_payload = {
        "sub": user,
        "appid": client_id,
        "scp": resolved_scope,
        "iat": int(time.time()),
        "exp": int(time.time()) + 90 * 24 * 3600,
        "token_type": "refresh",
    }
    new_refresh_token = pyjwt.encode(refresh_payload, _MOCK_JWT_SECRET, algorithm=_MOCK_JWT_ALGO)

    logger.info(
        "[MOCK] /oauth/token → grant=%s client=%s user=%s scopes=%s",
        grant_type, client_id, user, resolved_scope,
    )

    return JSONResponse({
        "access_token":  access_token,
        "refresh_token": new_refresh_token,
        "token_type":    "Bearer",
        "expires_in":    3600,
        "ext_expires_in": 3600,
        "scope":         resolved_scope,
    })


# ---------------------------------------------------------------------- #
# Admin endpoints (Blue Team — labo)
# ---------------------------------------------------------------------- #

@app.get("/admin/pending")
async def admin_pending():
    return JSONResponse({
        "pending_codes": len(_PENDING_CODES),
        "pending_pkce":  len(_PENDING_PKCE),
    })


@app.post("/admin/reset")
async def admin_reset():
    _PENDING_CODES.clear()
    _PENDING_PKCE.clear()
    return JSONResponse({"ok": True, "cleared_pending": True})


# ---------------------------------------------------------------------- #
# Entry points
# ---------------------------------------------------------------------- #

def run_mock_provider(host: str = "127.0.0.1", port: int = 9000) -> None:
    """Lance le mock provider (port 9000 par défaut)."""
    print("=" * 70)
    print(" VANTABLACK — Mock OAuth Provider (LABO UNIQUEMENT)")
    print(f" Authorize endpoint : http://{host}:{port}/oauth/authorize")
    print(f" Token endpoint     : http://{host}:{port}/oauth/token")
    print(f" Admin pending      : http://{host}:{port}/admin/pending")
    print("=" * 70)
    uvicorn.run(app, host=host, port=port, log_level="info")


def run(host: str = "127.0.0.1", port: int = 9000) -> None:
    """Alias pour rétrocompatibilité."""
    run_mock_provider(host=host, port=port)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    run_mock_provider(port=port)
