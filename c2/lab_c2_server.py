"""
c2/lab_c2_server.py — Serveur C2 de laboratoire (RÉEL, stdlib pur)
===================================================================

Petit C2 autonome pour valider en réel les modules offensifs de Vantablack
sans dépendance externe. Un seul processus, aucune lib tierce.

Endpoints :
  POST /ingest        Credential stuffing — répond 200 (succès) / 401 / 423
                      / 429 selon les listes d'environnement :
                        LABC2_ACCEPT_USERS=user1,user2   → 200 pour ces users
                        LABC2_LOCK_USERS=user3           → 423 (locked)
                        LABC2_RATE_LIMIT=7               → 429 toutes les N req
                      Chaque requête est loggée dans captures/lab_c2/stuffing.jsonl
  POST /exfil         Réception d'exfiltration chiffrée :
                      {"session","file","sha256","nonce_b64","ct_b64"} → jsonl
  POST /push          Réception MFA push → répond {"decision":"allow"} à
                      partir du N-ième push (LABC2_ACCEPT_AFTER_N, défaut 3),
                      {"decision":"deny"} avant.
  GET  /health        État + compteurs.

Usage :  .venv/bin/python c2/lab_c2_server.py [port]     (défaut 8099)
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("LABC2_PORT", "8099"))
OUT = Path("captures/lab_c2")
OUT.mkdir(parents=True, exist_ok=True)

ACCEPT_USERS = {u.strip() for u in os.environ.get("LABC2_ACCEPT_USERS", "").split(",") if u.strip()}
LOCK_USERS = {u.strip() for u in os.environ.get("LABC2_LOCK_USERS", "").split(",") if u.strip()}
RATE_LIMIT_EVERY = int(os.environ.get("LABC2_RATE_LIMIT", "0"))
ACCEPT_AFTER_N = int(os.environ.get("LABC2_ACCEPT_AFTER_N", "3"))

_lock = threading.Lock()
_counters = {"stuffing": 0, "exfil": 0, "push": 0}


def _append_jsonl(name: str, obj: dict) -> None:
    with _lock:
        path = OUT / name
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, default=str) + "\n")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # silence le stderr
        pass

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"ok": True, "port": PORT, "counters": dict(_counters),
                             "accept_users": sorted(ACCEPT_USERS),
                             "lock_users": sorted(LOCK_USERS),
                             "accept_after_n": ACCEPT_AFTER_N})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        raw = self._read_body()
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {"_raw": raw.decode("utf-8", errors="replace")[:2000]}

        if self.path == "/ingest":
            with _lock:
                _counters["stuffing"] += 1
                n = _counters["stuffing"]
            user = str(body.get("user") or body.get("username") or "")
            code, verdict = 401, "denied"
            if RATE_LIMIT_EVERY and n % RATE_LIMIT_EVERY == 0:
                code, verdict = 429, "rate_limited"
            elif user in LOCK_USERS:
                code, verdict = 423, "locked"
            elif user in ACCEPT_USERS:
                code, verdict = 200, "success"
            _append_jsonl("stuffing.jsonl", {
                "ts": time.time(), "remote": self.client_address[0],
                "user": user, "password": body.get("password"),
                "ua": self.headers.get("User-Agent", ""),
                "verdict": verdict, "code": code, "req_n": n,
            })
            self._json(code, {"result": verdict})

        elif self.path == "/exfil":
            with _lock:
                _counters["exfil"] += 1
            session = str(body.get("session") or "unknown")
            _append_jsonl(f"exfil_{session}.jsonl", {
                "ts": time.time(), "remote": self.client_address[0],
                **{k: body.get(k) for k in
                   ("file", "sha256", "size", "session", "nonce_b64", "ct_b64")},
            })
            self._json(200, {"ok": True, "stored": True})

        elif self.path == "/push":
            with _lock:
                _counters["push"] += 1
                n = _counters["push"]
            decision = "allow" if n >= ACCEPT_AFTER_N else "deny"
            _append_jsonl("mfa_pushes.jsonl", {
                "ts": time.time(), "remote": self.client_address[0],
                "push_n": n, "body": body, "decision": decision,
            })
            self._json(200, {"decision": decision, "push_n": n})

        else:
            self._json(404, {"error": "not found"})


def main() -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[LABC2] écoute sur http://127.0.0.1:{PORT}")
    print(f"[LABC2] artefacts → {OUT.resolve()}")
    print(f"[LABC2] accept={sorted(ACCEPT_USERS)} lock={sorted(LOCK_USERS)} "
          f"rate_limit_every={RATE_LIMIT_EVERY} accept_after_n={ACCEPT_AFTER_N}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
