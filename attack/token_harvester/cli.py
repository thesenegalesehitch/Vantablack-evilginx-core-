from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from attack.token_harvester.harvester import TokenHarvester, TokenSource


def cmd_scan(args: argparse.Namespace) -> int:
    harvester = TokenHarvester()
    if args.mode == "mock":
        if args.source:
            try:
                src = TokenSource(args.source)
            except ValueError as exc:
                print(f"❌ Source invalide: {exc}", file=sys.stderr)
                return 2
            tokens = harvester.harvest_from_source(src, hostname=args.hostname)
            for t in tokens:
                harvester.exfiltrate(t)
            total_collected = len(tokens)
        else:
            total_collected = harvester.harvest_all(hostname=args.hostname)
    else:
        print(
            f"❌ Mode '{args.mode}' non supporté. Disponibles: mock",
            file=sys.stderr,
        )
        return 2

    payload = {
        "mode": args.mode,
        "hostname": args.hostname,
        "source_filter": args.source,
        "total_tokens": total_collected,
        "tokens": [
            {
                "token_id": t.token_id,
                "source": t.source.value,
                "username": t.username,
                "domain": t.domain,
                "scopes": t.scopes,
                "expired": t.is_expired(),
            }
            for t in harvester.tokens
        ],
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"✅ Token harvest terminé (mode={args.mode})")
    print(f"   Hostname: {args.hostname}")
    print(f"   Tokens  : {total_collected}")
    sources = {}
    for t in harvester.tokens:
        sources[t.source.value] = sources.get(t.source.value, 0) + 1
    for src, cnt in sources.items():
        print(f"     - {src:<12} : {cnt}")
    print(f"   Output  : {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Token Harvester - Collecte de tokens d'authentification locaux",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Lance la collecte de tokens")
    scan_p.add_argument(
        "--mode",
        "-m",
        type=str,
        required=True,
        choices=["mock"],
        help="Mode d'exécution",
    )
    scan_p.add_argument(
        "--source",
        "-s",
        type=str,
        default=None,
        help="Source unique (defaut: toutes les sources)",
        choices=[t.value for t in TokenSource],
    )
    scan_p.add_argument(
        "--hostname",
        type=str,
        default="victim-pc",
        help="Nom d'hôte simulé (defaut: victim-pc)",
    )
    scan_p.add_argument(
        "--output",
        "-o",
        type=str,
        required=True,
        help="Fichier JSON de sortie",
    )

    args = parser.parse_args()
    if args.command == "scan":
        return cmd_scan(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
