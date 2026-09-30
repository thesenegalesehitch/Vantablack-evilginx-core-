"""
c2/lab_c2_server.py — Serveur C2 de laboratoire V2 (RÉEL, stdlib pur)
======================================================================

Un seul fichier, aucune dépendance. Deux rôles :

1. INGESTION RÉELLE des modules offensifs Vantablack (POST) :
     /ingest   credential stuffing → 200 / 401 / 423 / 429 selon config
     /exfil    réception de blobs AES-256-GCM (jsonl par session)
     /push     pushes MFA → {"decision":"allow"} à partir du N-ième
     /health   état, compteurs, sessions d'exfil

2. PROJECTION LIVE (GET, pour le jour J) :
     /dashboard     tableau de bord temps réel (SSE) à projeter — le public
                    n'a besoin d'AUCUN accès au projet, juste d'un navigateur
     /events        flux Server-Sent Events : attaques, détections, volontaires
     /enroll        inscription d'un volontaire (QR/téléphone) + consentement
     /volunteers    liste des volontaires (id, pseudo, horodatage)
     /announce      (token) pousse une bannière sur le dashboard, ex:
                    l'opérateur annonce le déchiffrement d'une exfil

Sécurité d'accès : si LABC2_TOKEN est défini, seuls /ingest, /exfil, /push
et /announce exigent l'en-tête  Authorization: Bearer <token>  (401 sinon).
Le dashboard, /events, /enroll et /volunteers restent publics (jour J).

Résilience : /events garde les 2000 derniers événements → un client qui
se reconnecte (wifi instable) rejoue l'historique instantanément.

CONFIDENTIALITÉ VOLONTAIRES : seul le pseudo choisi par le volontaire est
affiché. L'adresse e-mail de labo et l'IP sont journalisées côté serveur
(captures/lab_c2/) mais jamais envoyées sur le flux public.

Usage :
  .venv/bin/python c2/lab_c2_server.py [port]          # local
  LABC2_BIND=0.0.0.0 LABC2_TOKEN=mon-secret \\          # LAN / VPS jour J
      .venv/bin/python c2/lab_c2_server.py 8099
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("LABC2_PORT", "8099"))
BIND = os.environ.get("LABC2_BIND", "127.0.0.1")     # 0.0.0.0 → LAN/VPS
TOKEN = os.environ.get("LABC2_TOKEN", "")             # vide = pas d'auth
OUT = Path("captures/lab_c2")
OUT.mkdir(parents=True, exist_ok=True)

ACCEPT_USERS = {u.strip() for u in os.environ.get("LABC2_ACCEPT_USERS", "").split(",") if u.strip()}
LOCK_USERS = {u.strip() for u in os.environ.get("LABC2_LOCK_USERS", "").split(",") if u.strip()}
RATE_LIMIT_EVERY = int(os.environ.get("LABC2_RATE_LIMIT", "0"))
ACCEPT_AFTER_N = int(os.environ.get("LABC2_ACCEPT_AFTER_N", "3"))

_lock = threading.Lock()
_counters = {"stuffing": 0, "exfil": 0, "push": 0}
_exfil_sessions: dict[str, int] = {}     # session_id → nb blobs reçus
_events: deque[dict] = deque(maxlen=2000)
_volunteers: dict[str, dict] = {}        # pseudo → {"email","ts","ip","consent"}
# Détections (moteur défensif de démonstration : ce que verrait un Blue Team)
_detect_stats = {"attacks": 0, "compromised": 0, "exfil": 0, "push_storm": 0}
_last_push_by_user: dict[str, list[float]] = {}
_src_reqs: dict[str, list[float]] = {}   # source → timestamps (brute force)
_push_by_user: dict[str, int] = {}       # user → nb de pushes (décision par user)


def _now() -> float:
    return time.time()


def _append_jsonl(name: str, obj: dict) -> None:
    with _lock:
        with (OUT / name).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, default=str) + "\n")


def _emit(kind: str, data: dict) -> None:
    """Publie un événement pour tous les dashboards connectés (SSE)."""
    ev = {"ts": _now(), "kind": kind, "data": data}
    with _lock:
        _events.append(ev)


def _detect(kind: str, score: float, description: str, user: str | None = None) -> None:
    """Moteur de détections : heuristiques simples de Blue Team live."""
    ev = {"detection": kind, "score": round(score, 2),
          "description": description, "user": user, "ts": _now()}
    _append_jsonl("detections.jsonl", ev)
    _emit("detection", ev)


# ---------------------------------------------------------------------------
# Dashboard HTML (embarqué, sans dépendance externe)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VANTABLACK — Démo Red Team live</title>
<style>
  :root { --bg:#0b0e14; --panel:#121722; --line:#1f2937; --red:#ff4d5e;
          --blue:#3b82f6; --green:#22c55e; --amber:#f59e0b; --fg:#e5e7eb;
          --dim:#8b98a9; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--fg);
         font:15px/1.45 "SF Mono",ui-monospace,Menlo,Consolas,monospace; }
  header { padding:14px 22px; border-bottom:1px solid var(--line);
           display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }
  header h1 { font-size:17px; letter-spacing:2px; }
  .live { color:var(--red); font-weight:bold; }
  .live::before { content:"●"; margin-right:6px; animation:pulse 1.2s infinite; }
  @keyframes pulse { 50% { opacity:.25; } }
  #clock { color:var(--dim); margin-left:auto; font-size:13px; }
  #status { color:var(--dim); font-size:13px; }
  main { display:grid; grid-template-columns:1.15fr .85fr; gap:12px;
         padding:12px 22px 22px; }
  section { background:var(--panel); border:1px solid var(--line);
            border-radius:10px; padding:12px 14px; min-height:170px; }
  section h2 { font-size:12px; letter-spacing:1.5px; color:var(--dim);
               text-transform:uppercase; margin-bottom:8px; }
  .red    { border-top:3px solid var(--red); }
  .blue   { border-top:3px solid var(--blue); }
  .violet { border-top:3px solid #a78bfa; }
  ul { list-style:none; }
  li { padding:5px 0; border-bottom:1px dashed var(--line);
       display:flex; gap:8px; align-items:baseline; }
  li .t { color:var(--dim); font-size:12px; white-space:nowrap; }
  .hit      { color:var(--red); font-weight:bold; }
  .denied   { color:var(--dim); }
  .locked   { color:var(--amber); font-weight:bold; }
  .exfil    { color:#c084fc; }
  .push     { color:var(--amber); }
  .allow    { color:var(--green); font-weight:bold; }
  .det      { color:var(--blue); }
  .vol      { color:var(--green); }
  #banner { display:none; margin:0 22px; padding:14px 18px;
            border:1px solid #a78bfa; border-radius:10px; color:#0b0e14;
            background:#a78bfa; font-weight:bold; font-size:16px; }
  footer { color:var(--dim); font-size:12px; padding:0 22px 18px; }
  .kpis { display:flex; gap:18px; flex-wrap:wrap; margin-top:4px; }
  .kpi { font-size:13px; color:var(--dim); }
  .kpi b { color:var(--fg); font-size:17px; }
  @media (max-width:900px){ main { grid-template-columns:1fr; } }
</style></head>
<body>
<header>
  <h1>VANTABLACK</h1><span class="live">LIVE</span>
  <span id="status">connexion…</span><span id="clock"></span>
</header>
<div id="banner"></div>
<main>
  <section class="red">
    <h2>Opérations Red Team (réel)</h2>
    <div class="kpis">
      <span class="kpi">Requêtes <b id="k-req">0</b></span>
      <span class="kpi">Compromissions <b id="k-comp">0</b></span>
      <span class="kpi">Exfils <b id="k-exfil">0</b></span>
      <span class="kpi">Push storms <b id="k-push">0</b></span>
    </div>
    <ul id="feed"></ul>
  </section>
  <section class="blue">
    <h2>Détections Blue Team (temps réel)</h2>
    <ul id="dets"></ul>
  </section>
  <section class="violet">
    <h2>Volontaires (consentement enregistré)</h2>
    <ul id="vols"></ul>
  </section>
  <section>
    <h2>Journal brut</h2>
    <ul id="raw"></ul>
  </section>
</main>
<footer>Cadre : laboratoire autorisé · identités de labo uniquement ·
artefacts : captures/lab_c2/ · le Blue Team (Phase 2) est calibré sur ces
mêmes traces.</footer>
<script>
const MAX = 12;
const $ = id => document.getElementById(id);
function add(ul, html, cls) {
  const li = document.createElement("li");
  li.innerHTML = `<span class="t">${new Date().toLocaleTimeString("fr-FR")}</span>` +
                 `<span class="${cls||""}">${html}</span>`;
  ul.prepend(li);
  while (ul.children.length > MAX) ul.removeChild(ul.lastChild);
}
function kpi(id, v) { $(id).textContent = v; }
function banner(txt) {
  const b = $("banner");
  if (!txt) { b.style.display = "none"; return; }
  b.textContent = txt; b.style.display = "block";
}
setInterval(() => { $("clock").textContent = new Date().toLocaleTimeString("fr-FR"); }, 1000);

function handle(ev) {
  const d = ev.data || {};
  switch (ev.kind) {
    case "attack": {
      kpi("k-req", d.total_requests);
      if (d.kind === "stuffing") {
        const c = d.code;
        const cls = c === 200 ? "hit" : (c === 423 ? "locked" : "denied");
        add($("feed"), `STUFFING ${d.user} → HTTP ${c} ${c===200?"HIT":(c===423?"LOCKED":"refusé")}`, cls);
        if (c === 200) kpi("k-comp", d.total_compromised);
      } else if (d.kind === "exfil") {
        kpi("k-exfil", d.total_exfil);
        add($("feed"), `EXFIL chiffrée reçue — session ${d.session} (${d.size} o, blob ${d.blob})`, "exfil");
      } else if (d.kind === "push") {
        add($("feed"), `PUSH MFA #${d.push_n} ${d.user} → ${d.decision === "allow" ? "ALLOW" : "deny"}`,
            d.decision === "allow" ? "allow" : "push");
      }
      break;
    }
    case "detection":
      add($("dets"), `<b>[${d.detection}]</b> score ${d.score} — ${d.description}`, "det");
      break;
    case "volunteer":
      add($("vols"), `<b>${d.pseudo}</b> — consentement enregistré (identité labo émise)`, "vol");
      break;
    case "raw":
      add($("raw"), d.text);
      break;
    case "announce":
      banner(d.text);
      setTimeout(() => banner(""), 12000);
      break;
    case "hello":
      $("status").textContent = "flux temps réel connecté";
      break;
  }
}
function replay() {
  fetch("/events?replay=1").then(r => r.text()).then(body => {
    $("status").textContent = "historique chargé — flux connecté";
    body.split("\n\n").forEach(chunk => {
      const line = chunk.split("\n").find(l => l.startsWith("data: "));
      if (line) { try { handle(JSON.parse(line.slice(6))); } catch (e) {} }
    });
    listen();
  }).catch(() => { $("status").textContent = "reconnexion…"; setTimeout(replay, 1500); });
}
function listen() {
  const es = new EventSource("/events");
  es.onmessage = e => { try { handle(JSON.parse(e.data)); } catch (err) {} };
  es.onerror = () => {
    $("status").textContent = "flux coupé — reconnexion automatique…";
    es.close(); setTimeout(replay, 1500);
  };
}
replay();
</script>
</body></html>
"""


JOIN_HTML = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Volontaire — démo Vantablack</title>
<style>
  body { background:#0b0e14; color:#e5e7eb; font:16px/1.5 system-ui,sans-serif;
         max-width:480px; margin:0 auto; padding:28px 20px; }
  h1 { font-size:20px; letter-spacing:1px; }
  p, li { color:#8b98a9; font-size:14px; }
  li { margin:6px 0; }
  input[type=text], input[type=email] {
    width:100%; padding:12px; margin:8px 0 16px; font-size:16px;
    background:#121722; color:#e5e7eb; border:1px solid #1f2937;
    border-radius:8px; }
  label { font-size:14px; color:#e5e7eb; display:block; margin:14px 0 4px; }
  .consent { background:#121722; border:1px solid #1f2937; border-radius:8px;
             padding:14px; margin:12px 0; }
  button { width:100%; padding:14px; font-size:17px; font-weight:bold;
           background:#ff4d5e; color:#fff; border:0; border-radius:8px; }
  button:disabled { background:#333; }
  #done { display:none; text-align:center; padding:10px; }
  .ok { color:#22c55e; font-weight:bold; font-size:18px; }
  code { color:#c084fc; word-break:break-all; }
</style></head>
<body>
<h1>🟥 Démo VANTABLACK — participer</h1>
<p>Vous allez recevoir une <b>identité de laboratoire</b> créée uniquement
pour cette démonstration, dans l'infrastructure du présentateur. Elle
n'existe nulle part ailleurs.</p>
<ul>
  <li>✅ VOTRE téléphone/votre vraie identité ne sont jamais attaqués.</li>
  <li>✅ L'attaque ne touche que ce compte de labo éphémère.</li>
  <li>✅ Votre pseudo apparaîtra sur l'écran de projection en direct.</li>
  <li>✅ Le pseudo est effacé à la fin de la présentation.</li>
</ul>
<div class="consent">
  <label><input type="checkbox" id="consent"> Je donne mon consentement :
  j'accepte que le compte de laboratoire émis pour moi soit utilisé comme
  cible de démonstration (credential stuffing, exfiltration sur ce compte
  de labo, push MFA), et je comprends qu'aucun système réel ne soit ciblé.</label>
</div>
<label>Votre pseudo à l'écran</label>
<input type="text" id="pseudo" maxlength="24" placeholder="ex: alice_paris">
<label>Votre e-mail de contact (jamais affiché, journalisé pour traçabilité)</label>
<input type="email" id="email" placeholder="vous@exemple.com">
<button id="go" disabled>Rejoindre la démo</button>
<div id="done"><p class="ok">✓ C'est noté !</p>
<p>Surveillez l'écran : votre pseudo va apparaître dans la section
« Volontaires » puis dans les opérations en direct.</p>
<p>Votre identité de labo : <code id="lab"></code></p></div>
<script>
const c = document.getElementById("consent"), b = document.getElementById("go");
c.onchange = () => b.disabled = !c.checked;
b.onclick = async () => {
  b.disabled = true; b.textContent = "Envoi…";
  const r = await fetch("/enroll", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({pseudo: pseudo.value.trim(), email: email.value.trim(),
                          consent: consent.checked})});
  const d = await r.json();
  if (r.ok) { document.querySelector(".consent").style.display="none";
    document.querySelectorAll("input,button").forEach(e=>e.style.display="none");
    document.getElementById("done").style.display="block";
    document.getElementById("lab").textContent = d.lab_user;
  } else { alert(d.error || "erreur"); b.disabled = false; b.textContent = "Rejoindre la démo"; }
};
</script></body></html>
"""


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # silence stderr
        pass

    # -- helpers ----------------------------------------------------------

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length else b""

    def _authorized(self) -> bool:
        if not TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {TOKEN}"

    def _sse(self) -> None:
        """Flux Server-Sent Events. ?replay=1 → renvoie l'historique puis
        reste connecté (le navigateur rejoue tout en un instant)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        with _lock:
            snapshot = list(_events)
        try:
            for ev in snapshot:
                self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
            self.wfile.flush()
            seq = len(snapshot)
            while True:
                time.sleep(0.5)
                with _lock:
                    current = list(_events)
                while seq < len(current):
                    self.wfile.write(
                        f"data: {json.dumps(current[seq])}\n\n".encode())
                    seq += 1
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client déconnecté (normal)

    # -- GET ---------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/dashboard":
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/join":
            body = JOIN_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/events":
            self._sse()
        elif path == "/volunteers":
            with _lock:
                vols = [{"pseudo": p, "ts": v.get("enrolled_ts"),
                         "lab_user": (f"locked.{p.lower()}@demo.lab"
                                       if p.lower().startswith("locked")
                                       else f"{p.lower()}@demo.lab")}
                        for p, v in _volunteers.items()]
            self._json(200, {"volunteers": vols})
        elif path == "/health":
            with _lock:
                hp = {
                    "ok": True, "port": PORT, "bind": BIND,
                    "auth": bool(TOKEN),
                    "counters": dict(_counters),
                    "exfil_sessions": dict(_exfil_sessions),
                    "accept_users": sorted(ACCEPT_USERS),
                    "lock_users": sorted(LOCK_USERS),
                    "accept_after_n": ACCEPT_AFTER_N,
                    "volunteers": len(_volunteers),
                    "detections": dict(_detect_stats),
                }
            self._json(200, hp)
        else:
            self._json(404, {"error": "not found"})

    # -- POST ---------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        raw = self._read_body()
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {"_raw": raw.decode("utf-8", errors="replace")[:2000]}

        if self.path == "/ingest":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            with _lock:
                _counters["stuffing"] += 1
                n = _counters["stuffing"]
            user = str(body.get("user") or body.get("username") or "")
            # Les identités de labo des volontaires (@demo.lab) sont
            # acceptées par conception (n'importe quel C2, sans config) ;
            # un pseudo commençant par "locked." est volontairement 423.
            code, verdict = 401, "denied"
            if RATE_LIMIT_EVERY and n % RATE_LIMIT_EVERY == 0:
                code, verdict = 429, "rate_limited"
            elif user.startswith("locked.") or user in LOCK_USERS:
                code, verdict = 423, "locked"
            elif user in ACCEPT_USERS or (
                    user.endswith("@demo.lab") and user):
                code, verdict = 200, "success"
            _append_jsonl("stuffing.jsonl", {
                "ts": _now(), "remote": self.client_address[0],
                "user": user, "password": body.get("password"),
                "ua": self.headers.get("User-Agent", ""),
                "verdict": verdict, "code": code, "req_n": n,
            })
            with _lock:
                _detect_stats["attacks"] += 1
                if code == 200:
                    _detect_stats["compromised"] += 1
            total_req = n
            with _lock:
                total_comp = _detect_stats["compromised"]
            _emit("attack", {"kind": "stuffing", "user": user, "code": code,
                             "total_requests": total_req,
                             "total_compromised": total_comp})
            # Détections live
            src = self.client_address[0]
            now = _now()
            hist = _src_reqs.setdefault(src, [])
            hist.append(now)
            hist[:] = [t for t in hist if now - t < 60.0]
            if len(hist) >= 5:
                _detect("brute_force_pattern",
                        min(1.0, 0.3 + 0.1 * len(hist)),
                        f"{len(hist)} tentatives d'authentification en 60s "
                        f"depuis {src} — password spraying en cours")
            if code == 200:
                _detect("credential_compromise", 0.95,
                        "identifiant compromis utilisé avec succès : "
                        "corrélation source unique", user=user)
            self._json(code, {"result": verdict})

        elif self.path == "/exfil":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            session = str(body.get("session") or "unknown")
            with _lock:
                _counters["exfil"] += 1
                _exfil_sessions[session] = _exfil_sessions.get(session, 0) + 1
                total_exfil = _counters["exfil"]
            _append_jsonl(f"exfil_{session}.jsonl", {
                "ts": _now(), "remote": self.client_address[0],
                **{k: body.get(k) for k in
                   ("file", "sha256", "size", "session", "nonce_b64", "ct_b64")},
            })
            _emit("attack", {"kind": "exfil", "session": session,
                             "size": body.get("size"),
                             "blob": _exfil_sessions[session],
                             "total_exfil": total_exfil})
            _detect("exfiltration_channel", 0.9,
                    f"canal d'exfiltration détecté : blob chiffré AES-GCM "
                    f"({body.get('size')} o) vers session {session}")
            self._json(200, {"ok": True, "stored": True})

        elif self.path == "/push":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            with _lock:
                _counters["push"] += 1
                n = _counters["push"]
            user = str(body.get("user") or "")
            # Décision PAR UTILISATEUR : chaque cible subit son propre
            # deny/deny/…/allow (fatigue réaliste), pas un compteur global.
            with _lock:
                _push_by_user[user] = _push_by_user.get(user, 0) + 1
                per_user = _push_by_user[user]
            decision = "allow" if per_user >= ACCEPT_AFTER_N else "deny"
            _append_jsonl("mfa_pushes.jsonl", {
                "ts": _now(), "remote": self.client_address[0],
                "push_n": n, "body": body, "decision": decision,
            })
            _emit("attack", {"kind": "push", "push_n": per_user, "user": user,
                             "decision": decision})
            # Détection push-storm : ≥3 pushes même utilisateur en 60s
            now = _now()
            hist = _last_push_by_user.setdefault(user, [])
            hist.append(now)
            hist[:] = [t for t in hist if now - t < 60.0]
            if len(hist) >= 3:
                with _lock:
                    _detect_stats["push_storm"] += 1
                _detect("mfa_push_storm", min(1.0, 0.4 + 0.2 * len(hist)),
                        f"{len(hist)} pushes MFA en 60s sur « {user} » — "
                        f"fatigue attack en cours", user=user)
            self._json(200, {"decision": decision, "push_n": per_user})

        elif self.path == "/enroll":
            pseudo = str(body.get("pseudo") or "").strip()[:24]
            email = str(body.get("email") or "").strip().lower()[:80]
            consent = bool(body.get("consent"))
            if not pseudo or not email or not consent:
                self._json(400, {"error":
                                 "pseudo + email labo + consentement requis"})
                return
            with _lock:
                if pseudo in _volunteers:
                    self._json(409, {"error": "pseudo déjà pris, "
                                             "choisis-en un autre"})
                    return
                lab_identity = {
                    "pseudo": pseudo,
                    "email": f"{secrets.token_hex(4)}@demo.lab.local",
                    "enrolled_ts": _now(),
                    "ip": self.client_address[0],
                    "consent": True,
                }
                _volunteers[pseudo] = lab_identity
            _append_jsonl("volunteers.jsonl", lab_identity)
            # Le pseudo se battra dans la démo : compte accepté, ou verrouillé
            # si son pseudo commence par "locked"
            lab_user = (f"locked.{pseudo}@demo.lab"
                        if pseudo.lower().startswith("locked")
                        else f"{pseudo.lower()}@demo.lab")
            _emit("volunteer", {"pseudo": pseudo, "lab_user": lab_user})
            _emit("raw", {"text": f"identité de labo émise pour {pseudo}"})
            self._json(200, {"ok": True, "pseudo": pseudo,
                             "lab_user": lab_user,
                             "note": "cette identité n'existe que dans le "
                                     "labo de la démo"})

        elif self.path == "/announce":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            text = str(body.get("text") or "")[:200]
            _emit("announce", {"text": text})
            self._json(200, {"ok": True})

        else:
            self._json(404, {"error": "not found"})


def main() -> None:
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"[LABC2] écoute sur http://{BIND}:{PORT}")
    if BIND == "0.0.0.0":
        print(f"[LABC2] dashboard de projection : "
              f"http://<cette-machine>:{PORT}/dashboard")
        print("[LABC2] volontaires (QR téléphone) : "
              f"http://<cette-machine>:{PORT}/enroll  (POST JSON)")
    if TOKEN:
        print("[LABC2] auth par token ACTIVE sur /ingest /exfil /push /announce")
    print(f"[LABC2] artefacts → {OUT.resolve()}")
    print(f"[LABC2] accept={sorted(ACCEPT_USERS)} lock={sorted(LOCK_USERS)} "
          f"rate_limit_every={RATE_LIMIT_EVERY} accept_after_n={ACCEPT_AFTER_N}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
