from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from attack.oauth_consent.app_registration import get_default_app, MaliciousApp
from attack.oauth_consent.consent_url import AUTHORIZE_ENDPOINTS, build_consent_url


def cmd_generate(args: argparse.Namespace) -> int:
    provider = args.provider
    if provider not in AUTHORIZE_ENDPOINTS:
        print(
            f"❌ Provider '{provider}' invalide. "
            f"Disponibles: {list(AUTHORIZE_ENDPOINTS.keys())}",
            file=sys.stderr,
        )
        return 2

    app = get_default_app()
    if args.scope:
        app = MaliciousApp(
            name=app.name,
            client_id=app.client_id,
            tenant_id=app.tenant_id,
            redirect_uri=app.redirect_uri,
            scope_string=args.scope,
        )

    url = build_consent_url(app, provider=provider)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".json":
        payload = {
            "provider": provider,
            "url": url,
            "client_id": app.client_id,
            "redirect_uri": app.redirect_uri,
            "scope": app.scope_string,
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        out_path.write_text(url + "\n", encoding="utf-8")
    print(f"✅ URL de consentement générée (provider={provider})")
    print(f"   Fichier: {out_path}")
    if args.verbose:
        print(f"   URL: {url}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OAuth Illicit Consent - Générateur d'URL d'attaque",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Afficher l'URL en clair"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen_p = subparsers.add_parser(
        "generate", help="Génère une URL de consentement OAuth"
    )
    gen_p.add_argument(
        "--provider",
        "-p",
        type=str,
        required=True,
        choices=list(AUTHORIZE_ENDPOINTS.keys()),
        help="Provider cible: mock | microsoft | google",
    )
    gen_p.add_argument(
        "--scope",
        "-s",
        type=str,
        default=None,
        help="Scopes OAuth (defaut: selon app par defaut)",
    )
    gen_p.add_argument(
        "--output",
        "-o",
        type=str,
        required=True,
        help="Fichier de sortie (.txt ou .json)",
    )

    args = parser.parse_args()
    if args.command == "generate":
        return cmd_generate(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
