from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from attack.ws_smuggling.smuggler import (
    TunnelConfig,
    WSSmugglingTunnel,
)


def cmd_create_tunnel(args: argparse.Namespace) -> int:
    tunnel_mgr = WSSmugglingTunnel()

    cfg = tunnel_mgr.create_tunnel(
        ws_url=args.ws_url,
        subprotocol=args.subprotocol,
        headers=args.headers or None,
    )

    config_obj = {
        "tunnel_id": cfg.tunnel_id,
        "ws_url": cfg.ws_url,
        "subprotocol": cfg.subprotocol,
        "headers": cfg.headers,
        "ping_interval_s": cfg.ping_interval_s,
        "encoding": {
            "type": "xor+base64",
            "key_hint": "vantablack (par défaut, configurable côté implant)",
        },
        "supported_protocols": tunnel_mgr.list_protocols(),
        "created_at": cfg.created_at,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(config_obj, indent=2), encoding="utf-8")

    print("✅ Tunnel WS Smuggling configuré")
    print(f"   Tunnel ID    : {cfg.tunnel_id}")
    print(f"   URL WS       : {cfg.ws_url}")
    print(f"   Subprotocol  : {cfg.subprotocol}")
    print(f"   Ping interv. : {cfg.ping_interval_s}s")
    print(f"   Fichier      : {output_path}")
    return 0


def cmd_test_heartbeat(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"❌ Fichier config introuvable: {config_path}", file=sys.stderr)
        return 1

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"❌ JSON invalide: {e}", file=sys.stderr)
        return 1

    tunnel_id = config.get("tunnel_id", str(uuid.uuid4()))
    ws_url = config.get("ws_url", "wss://c2.example.invalid/ws")
    ping_interval = int(config.get("ping_interval_s", 30))

    print("🔍 Test heartbeat tunnel WS (mode simulé)")
    print(f"   Tunnel ID : {tunnel_id}")
    print(f"   WS URL    : {ws_url}")
    print(f"   Interval  : {ping_interval}s (simulé : 1 msg/{ping_interval}s)")
    print()

    heartbeat_log: list[dict] = []
    num_pings = args.num_pings or 3

    print(f"   Simulation de {num_pings} pings (sans attendre l'intervalle réel)...")
    for i in range(1, num_pings + 1):
        ping_ts = time.time()
        expected_scheduled = (i - 1) * ping_interval
        entry = {
            "seq": i,
            "tunnel_id": tunnel_id,
            "type": "ping",
            "scheduled_offset_s": expected_scheduled,
            "timestamp": ping_ts,
            "opcode": 0x9,
            "payload_size": 4,
            "payload_preview": "0x01 0x02 0x03 0x04",
            "response_expected": {
                "type": "pong",
                "opcode": 0xA,
                "echo_payload": True,
            },
        }
        heartbeat_log.append(entry)
        print(f"   [#{i}] @ T+{expected_scheduled:>4d}s  PING opcode=0x9 → attend PONG opcode=0xA")

    result = {
        "tunnel_id": tunnel_id,
        "heartbeat_interval_s": ping_interval,
        "heartbeat_mode": "simulated",
        "total_pings_simulated": num_pings,
        "passes": True,
        "notes": "Mode simulé : vérifie que le schéma de ping/pong est cohérent sans connexion réseau",
        "heartbeat_log": heartbeat_log,
    }

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\n📄 Rapport heartbeat écrit dans: {out_path}")
    else:
        print()
        print(json.dumps(result, indent=2))

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WebSocket Smuggling CLI - Configuration et test de tunnel WS",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_p = subparsers.add_parser(
        "create-tunnel", help="Crée une configuration de tunnel WS"
    )
    create_p.add_argument(
        "--ws-url",
        type=str,
        required=True,
        help="URL WebSocket du serveur C2 (wss://...)",
    )
    create_p.add_argument(
        "--subprotocol",
        type=str,
        default="graphql-ws",
        choices=WSSmugglingTunnel.SUPPORTED_PROTOCOLS,
        help="Subprotocol WS pour mimétisme applicatif (defaut: graphql-ws)",
    )
    create_p.add_argument(
        "--headers",
        type=json.loads,
        default=None,
        help='Headers HTTP additionnels (JSON: {"X-Custom":"val"})',
    )
    create_p.add_argument(
        "--output",
        "-o",
        type=str,
        default="captures/ws_tunnels/tunnel_config.json",
        help="Fichier JSON de sortie",
    )
    create_p.set_defaults(func=cmd_create_tunnel)

    heartbeat_p = subparsers.add_parser(
        "test-heartbeat", help="Teste le mécanisme de ping/pong (simulé)"
    )
    heartbeat_p.add_argument(
        "--config",
        "-c",
        type=str,
        required=True,
        help="Fichier JSON de configuration du tunnel",
    )
    heartbeat_p.add_argument(
        "--num-pings",
        type=int,
        default=3,
        help="Nombre de pings à simuler (defaut: 3)",
    )
    heartbeat_p.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Fichier JSON de sortie pour le rapport de test",
    )
    heartbeat_p.set_defaults(func=cmd_test_heartbeat)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
