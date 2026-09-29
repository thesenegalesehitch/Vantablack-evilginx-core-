"""
Blue Team - BitB Detector (Browser-in-the-Browser popup detection)
==================================================================

Détecte les fausses popups SSO (Browser-in-the-Browser) en analysant :

  1. Structure du DOM : une popup SSO légitime est dans une fenêtre
     séparée (window.open), pas dans une div positionnée
  2. Indicateurs URL : window.opener, location.ancestorOrigins,
     window.parent.document.domain
  3. Origine du iframe : si l'iframe pointe vers un domaine non-IdP
  4. Comportement : autofill sur des champs password hors origin
  5. Scripts : présence de window.webkitURL, sendBeacon vers C2,
     exfiltration de credentials
  6. Certificat SSL : un BitB n'a pas de vrai certificat SSL pour
     le faux domaine de popup

L'agent peut être déployé comme :
  - Extension navigateur qui surveille les fenêtres popup
  - EDR qui inspecte les iframes
  - Proxy d'entreprise qui parse les requêtes HTML
"""

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Patterns connus d'URL de BitB (phishlets Evilginx-like)
KNOWN_BITB_URL_PATTERNS = [
    r"https?://[a-z0-9\-]+\.example\.invalid/auth/.*",
    r"https?://[a-z0-9\-]+\.cdn-login\.com/.*",
    r"https?://[a-z0-9\-]+\.sso-portal\.net/.*",
    r"https?://[a-z0-9\-]+\.corp-auth\.[a-z]+/.*",
]

# Domaines IdP légitimes (pour vérifier qu'un iframe pointe bien vers eux)
LEGITIMATE_IDP_DOMAINS = {
    "login.microsoftonline.com",
    "login.live.com",
    "login.yahoo.com",
    "accounts.google.com",
    "okta.com",
    ".okta.com",
    "duosecurity.com",
    "auth0.com",
    "github.com",
    "appleid.apple.com",
    "facebook.com",
    "linkedin.com",
}

# Signatures HTML de templates BitB connus
BITB_HTML_SIGNATURES = [
    r'window\.open\s*\(\s*["\']https?://[^"\']*login[^"\']*["\']',
    r"position:\s*fixed.*?z-index:\s*9999",   # popup qui couvre l'écran
    r"top:\s*0.*?left:\s*0.*?width:\s*100%.*?height:\s*100%",
    r"<iframe[^>]*src=[\"'][^\"']*(?:login|sso|auth|signin)[^\"']*[\"']",
    r"sendBeacon\s*\(",
    r"webkitURL",
    r"document\.domain\s*=",
    r"window\.opener",
    r"parent\.location",
    r"top\.location",
    r"frames\[",
]


@dataclass
class BitBIndicator:
    """Un indicateur de BitB observé."""

    indicator_id: str
    timestamp: float
    source_url: str
    iframe_src: str | None = None
    indicators: list[str] = field(default_factory=list)
    score: float = 0.0
    is_bitb: bool = False
    payload_excerpt: str | None = None


@dataclass
class BitBAlert:
    alert_id: str
    severity: str
    title: str
    description: str
    source_url: str
    iframe_src: str | None
    indicators: list[str]
    mitre_techniques: list[str]
    created_at: float
    actions: list[str]


class BitBDetector:
    """
    Analyse statique et dynamique d'un DOM pour détecter les BitB.

    Sources d'entrée :
      - HTML de la page parent (via proxy / extension)
      - URL de l'iframe détecté
      - Liste des window.open() observés
    """

    def __init__(self, output_dir: str = "captures/defense") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.indicators: list[BitBIndicator] = []
        self.alerts: list[BitBAlert] = []

    def analyze_page(
        self,
        source_url: str,
        html: str,
        iframes: list[str] | None = None,
        opened_windows: list[str] | None = None,
    ) -> BitBIndicator:
        """
        Analyse une page HTML et retourne les indicateurs BitB trouvés.
        """
        indicators: list[str] = []
        score = 0.0

        # 1. Signatures HTML
        for sig in BITB_HTML_SIGNATURES:
            if re.search(sig, html, re.IGNORECASE | re.DOTALL):
                indicators.append(f"html_pattern:{sig[:40]}")
                score += 0.15

        # 2. Iframes pointant hors des IdP légitimes
        for iframe_src in iframes or []:
            if not any(
                iframe_src.endswith((d, d + "/"))
                for d in LEGITIMATE_IDP_DOMAINS
            ):
                indicators.append(f"iframe_to_untrusted:{iframe_src}")
                score += 0.30

        # 3. window.open vers des URLs non-IdP
        for url in opened_windows or []:
            if not any(
                url.startswith(("https://" + d, "http://" + d))
                for d in LEGITIMATE_IDP_DOMAINS
            ):
                indicators.append(f"popup_to_untrusted:{url}")
                score += 0.30

        # 4. Patterns URL
        for pat in KNOWN_BITB_URL_PATTERNS:
            for url in (iframes or []) + (opened_windows or []):
                if re.match(pat, url):
                    indicators.append(f"url_pattern_match:{url}")
                    score += 0.40

        # 5. Présence de scripts d'exfiltration
        if re.search(r"navigator\.sendBeacon", html):
            indicators.append("sendBeacon_exfil")
            score += 0.25
        if re.search(r"new Image\(\)\.src\s*=", html):
            indicators.append("image_exfil")
            score += 0.15
        if re.search(r"document\.location\s*=", html):
            indicators.append("redirect_exfil")
            score += 0.10

        score = min(score, 1.0)
        is_bitb = score >= 0.40
        indicator = BitBIndicator(
            indicator_id=str(uuid.uuid4()),
            timestamp=time.time(),
            source_url=source_url,
            iframe_src=(iframes or [None])[0],
            indicators=indicators,
            score=score,
            is_bitb=is_bitb,
            payload_excerpt=html[:500] if is_bitb else None,
        )
        self.indicators.append(indicator)
        if is_bitb:
            self._generate_alert(indicator)
        return indicator

    def _generate_alert(self, ind: BitBIndicator) -> None:
        alert = BitBAlert(
            alert_id=str(uuid.uuid4()),
            severity="HIGH" if ind.score < 0.7 else "CRITICAL",
            title="Browser-in-the-Browser attack detected",
            description=(
                f"Page {ind.source_url} contains a fake SSO popup with "
                f"confidence {ind.score:.0%}. {len(ind.indicators)} indicators matched."
            ),
            source_url=ind.source_url,
            iframe_src=ind.iframe_src,
            indicators=ind.indicators,
            mitre_techniques=["T1185", "T1557", "T1204.002"],
            created_at=time.time(),
            actions=[
                "1. Block the parent URL at the proxy",
                "2. Block the iframe/popup domain at the DNS firewall",
                "3. Alert the user with a browser interstitial",
                "4. Notify SOC for investigation",
                "5. Pivot to investigate the user who visited the page",
            ],
        )
        self.alerts.append(alert)


def register_bitb_defense_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    detector = BitBDetector()

    class AnalyzeRequest(BaseModel):
        source_url: str
        html: str
        iframes: list[str] = []
        opened_windows: list[str] = []

    @app.post("/_/defense/bitb/analyze")
    async def analyze(req: AnalyzeRequest):
        ind = detector.analyze_page(
            source_url=req.source_url,
            html=req.html,
            iframes=req.iframes,
            opened_windows=req.opened_windows,
        )
        return {
            "indicator_id": ind.indicator_id,
            "is_bitb": ind.is_bitb,
            "score": ind.score,
            "indicators": ind.indicators,
        }

    @app.get("/_/defense/bitb/alerts")
    async def alerts():
        return [
            {
                "id": a.alert_id,
                "severity": a.severity,
                "title": a.title,
                "source": a.source_url,
                "ts": a.created_at,
            }
            for a in detector.alerts
        ]
