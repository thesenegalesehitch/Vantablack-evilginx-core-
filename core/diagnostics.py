#!/usr/bin/env python3
"""
core/diagnostics.py
-------------------
Rapport de diagnostic initial du projet VANTABLACK GODMODE.

Utilisation standalone :
    $ .venv/bin/python core/diagnostics.py

Intégré au Makefile :
    $ make diagnose

Section 0 : environnement (Python / Go / Redis / Node)
Section 1 : imports critiques (core, attack, engine, blue_team)
Section 2 : ruff (statique)
Section 3 : pytest (unitaires)

Cette brique sert à la TASK 1 (Red Team — diagnostic initial) et
est réutilisée tout au long du projet par les playbooks de
post-mortem Blue Team (vérifier si un hôte "labo" est propre).
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Chemins & constantes
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
CAPTURES_DIR: Path = PROJECT_ROOT / "captures"
CAPTURES_DIR.mkdir(exist_ok=True)
DIAGNOSE_OUTPUT: Path = CAPTURES_DIR / "diagnose_report.json"

# Test d'imports (section 2) : (nom_affiché, expression_exec OR callable)
# On sépare : imports "simples" (from X import Y) et checks ad-hoc
IMPORT_TESTS: list[tuple[str, str]] = [
    ("yaml", "import yaml"),
    ("httpx", "import httpx"),
    ("fastapi", "import fastapi"),
    ("rich", "import rich"),
    ("numpy", "import numpy"),
    ("pandas", "import pandas"),
    ("sklearn", "import sklearn"),
    ("core.config.Settings", "from core.config import Settings"),
    ("core.session.SessionHijacker", "from core.session import SessionHijacker"),
    ("core.mfa.MFABypassEngine", "from core.mfa import MFABypassEngine"),
    ("engine.advanced_proxy.DoSolver",
     "from engine.advanced_proxy import DoHResolver, JA4Spoofer"),
]

ATTACK_IMPORT_TESTS: list[tuple[str, str]] = [
    ("attack.bitb.generator",
     "from attack.bitb.generator import BitBTarget, BitBInjector"),
    ("attack.oauth_consent.consent_url",
     "from attack.oauth_consent.consent_url import build_consent_url"),
    ("attack.device_code.initiator",
     "from attack.device_code.initiator import DeviceCodeInitiator"),
    ("attack.mfa_bombing.bomber",
     "from attack.mfa_bombing.bomber import MFABombingEngine"),
    ("attack.token_harvester.harvester",
     "from attack.token_harvester.harvester import TokenHarvester"),
    ("attack.domain_fronting.fronting",
     "from attack.domain_fronting.fronting import CDNProvider, DomainFrontingConfig, FrontingRouter"),
    ("attack.ws_smuggling.smuggler",
     "from attack.ws_smuggling.smuggler import WSSmugglingTunnel"),
    ("attack.anti_forensics.wiper",
     "from attack.anti_forensics.wiper import AntiForensicsWiper"),
    ("attack.anti_analysis.detector",
     "from attack.anti_analysis.detector import AntiAnalysisDetector"),
]

BLUE_IMPORT_TESTS: list[tuple[str, str]] = [
    ("blue_team.mitre_attack",
     "from blue_team.mitre_attack import MitreAttackMapper, TECHNIQUES"),
    ("blue_team.aitm_detector",
     "from blue_team.aitm_detector import TLSFingerprint, KNOWN_AITM_FINGERPRINTS"),
    ("blue_team.incident_response",
     "from blue_team.incident_response import Playbook, PlaybookAction, PLAYBOOK_TEMPLATES"),
]

CUSTOM_CHECKS: list[tuple[str, Callable[[], tuple[bool, str]]]] = []


# ---------------------------------------------------------------------------
# Rapport
# ---------------------------------------------------------------------------
@dataclass
class DiagnosticSection:
    name: str
    entries: list[tuple[str, bool, str]] = field(default_factory=list)
    ok_count: int = 0
    total_count: int = 0


@dataclass
class DiagnosticReport:
    sections: dict[str, DiagnosticSection] = field(default_factory=dict)

    def add(self, section: str, entry_name: str, ok: bool, message: str = "") -> None:
        sec = self.sections.setdefault(section, DiagnosticSection(name=section))
        sec.entries.append((entry_name, ok, message))
        sec.total_count += 1
        if ok:
            sec.ok_count += 1

    def to_dict(self) -> dict:
        return {
            "sections": {
                sec: {
                    "ok": self.sections[sec].ok_count,
                    "total": self.sections[sec].total_count,
                    "entries": [
                        {"name": n, "ok": o, "message": m}
                        for (n, o, m) in self.sections[sec].entries
                    ],
                }
                for sec in self.sections
            },
            "project_root": str(PROJECT_ROOT),
        }

    def summary(self) -> str:
        lines = []
        for sec_name, sec in self.sections.items():
            ratio = f"{sec.ok_count}/{sec.total_count}"
            lines.append(f"  {sec_name:<25} {ratio}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def _ok(msg: str) -> str:
    return f"  {GREEN}✅{NC} {msg}"


def _warn(msg: str) -> str:
    return f"  {YELLOW}⚠️{NC} {msg}"


def _fail(msg: str) -> str:
    return f"  {RED}❌{NC} {msg}"


def _section(title: str) -> None:
    print(f"\n{BOLD}{YELLOW}{title}{NC}")


# ---------------------------------------------------------------------------
# Sections du diagnostic
# ---------------------------------------------------------------------------
def s01_environnement(report: DiagnosticReport) -> None:
    _section("[1] Environnement (outils)")

    # Python3 système
    py_system = shutil.which("python3")
    if py_system:
        res = subprocess.run([py_system, "--version"], capture_output=True, text=True)
        ver = res.stdout.strip() or res.stderr.strip() or "version inconnue"
        print(f"  Python3 système : {ver} ({py_system})")
        report.add("environnement", "python3_system", True, f"{ver} @ {py_system}")
    else:
        print(_fail("Python3 introuvable dans le PATH"))
        report.add("environnement", "python3_system", False)

    # venv
    venv_python = PROJECT_ROOT / ".venv" / "bin" / "python"
    if venv_python.is_file() and os.access(venv_python, os.X_OK):
        res = subprocess.run([str(venv_python), "--version"], capture_output=True, text=True)
        ver = res.stdout.strip() or res.stderr.strip() or "version inconnue"
        print(f"  .venv Python    : {ver}")
        print(f"  Chemin .venv    : {PROJECT_ROOT / '.venv'}")
        report.add("environnement", "venv_python", True, f"{ver}")
    else:
        print(_warn(".venv absent — lancez `make install`"))
        report.add("environnement", "venv_python", False, "absent")

    for binary, label, critical in (
        ("go", "Go", False),
        ("redis-cli", "Redis-cli", False),
        ("npm", "npm / Node", False),
        ("terraform", "Terraform", False),
    ):
        path = shutil.which(binary)
        if path:
            ver_out = ""
            try:
                if binary == "terraform":
                    v = subprocess.run([binary, "-version"],
                                       capture_output=True, text=True, timeout=5).stdout
                    ver_out = v.splitlines()[0].strip()
                elif binary == "npm":
                    v = subprocess.run([binary, "--version"],
                                       capture_output=True, text=True, timeout=5).stdout
                    ver_out = "npm " + v.strip()
                    nv = subprocess.run(["node", "--version"],
                                        capture_output=True, text=True, timeout=5).stdout
                    ver_out += f" / node {nv.strip()}"
                else:
                    v = subprocess.run([binary, "version"],
                                       capture_output=True, text=True, timeout=5).stdout
                    ver_out = v.strip().splitlines()[0]
            except Exception:
                ver_out = ""
            print(f"  {label:<16}: {ver_out or path}")
            report.add("environnement", binary, True, f"{path} {ver_out}")
        else:
            note = {
                "go": "build-go ignoré ; C2 implant non compilable (mode labo Python OK)",
                "redis-cli": "Celery workers ignorés — utiliser MODE_MEMORY_ONLY=1",
                "npm": "Build frontend React ignoré (Task 13)",
                "terraform": "Deploy AWS redirector ignoré",
            }.get(binary, "")
            print(_warn(f"{label:<16}: absent — {note}"))
            report.add("environnement", binary, not critical, note)


def _exec_imports(report: DiagnosticReport, section_key: str,
                  tests: list[tuple[str, str]]) -> None:
    """Exécute une liste de tests d'imports via exec, capture les exceptions."""
    # s'assurer que project root est dans le sys.path
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    for name, stmt in tests:
        try:
            exec(stmt, {"__name__": "__diagnose__"})
            # Messages additionnels après import réussi (verbose)
            extra: list[str] = []
            if name == "blue_team.mitre_attack":
                from blue_team.mitre_attack import TECHNIQUES  # noqa: WPS433
                extra.append(f"MITRE: {len(TECHNIQUES)} techniques")
            elif name == "blue_team.aitm_detector":
                from blue_team.aitm_detector import KNOWN_AITM_FINGERPRINTS  # noqa: WPS433
                extra.append(f"JA3/JA4 DB: {len(KNOWN_AITM_FINGERPRINTS)} entrées")
            elif name == "blue_team.incident_response":
                from blue_team.incident_response import PLAYBOOK_TEMPLATES  # noqa: WPS433
                extra.append(f"Playbooks: {len(PLAYBOOK_TEMPLATES)} templates")
            msg = " ; ".join(extra) if extra else ""
            print(_ok(name) + (f" ← {msg}" if msg else ""))
            report.add(section_key, name, True, msg)
        except Exception as exc:  # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"
            print(_fail(f"{name}: {msg}"))
            report.add(section_key, name, False, msg)


def s02_core_imports(report: DiagnosticReport) -> None:
    _section("[2] Imports — Core + ML")
    _exec_imports(report, "core_imports", IMPORT_TESTS)


def s03_attack_imports(report: DiagnosticReport) -> None:
    _section("[3] Imports — Red Team (vecteurs offensifs)")
    _exec_imports(report, "attack_imports", ATTACK_IMPORT_TESTS)


def s04_blue_imports(report: DiagnosticReport) -> None:
    _section("[4] Imports — Blue Team (défense)")
    _exec_imports(report, "blue_imports", BLUE_IMPORT_TESTS)


def s05_ruff(report: DiagnosticReport) -> None:
    _section("[5] Qualité statique — ruff check .")
    ruff = PROJECT_ROOT / ".venv" / "bin" / "ruff"
    if not ruff.is_file():
        print(_warn("ruff non installé dans le venv → make install"))
        report.add("qualite", "ruff_installed", False)
        return
    cmd = [str(ruff), "check", "."]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)
    combined = (proc.stdout + "\n" + proc.stderr).strip()
    lines = combined.splitlines()
    if proc.returncode == 0:
        print(_ok("0 erreurs ruff (line-length=100, ignore E501)"))
        report.add("qualite", "ruff", True, "exit 0")
    else:
        # on affiche les 15 premières lignes pour diagnostiquer
        preview = "\n".join(lines[-15:])
        print(_warn(f"ruff a remonté des warnings/erreurs ({len(lines)} lignes)"))
        for l in lines[-15:]:
            print(f"      {l}")
        report.add("qualite", "ruff", False, preview[:500])


def s06_pytest(report: DiagnosticReport) -> None:
    _section("[6] Tests unitaires — pytest tests/")
    py = PROJECT_ROOT / ".venv" / "bin" / "python"
    if not py.is_file():
        print(_warn(".venv python absent → make install"))
        report.add("tests", "pytest_available", False)
        return
    tests_dir = PROJECT_ROOT / "tests"
    if not tests_dir.is_dir():
        print(_warn(f"dossier tests/ introuvable ({tests_dir})"))
        report.add("tests", "tests_dir_exists", False)
        return
    cmd = [str(py), "-m", "pytest", "tests/", "-q", "--tb=short",
           "--no-header", "-p", "no:warnings"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)
    out = proc.stdout.strip().splitlines()
    # On affiche tout ce que pytest a sort en quiet
    for l in out[-20:]:
        print(f"    {l}")
    if proc.returncode == 0:
        print(_ok("pytest exit 0"))
        report.add("tests", "pytest", True, out[-1] if out else "")
    else:
        print(_warn(f"pytest exit={proc.returncode} (warnings OK si pre-existing)"))
        report.add("tests", "pytest", False, (proc.stdout + proc.stderr)[-500:])


# ---------------------------------------------------------------------------
# Orchestrateur du diagnostic
# ---------------------------------------------------------------------------
def run_diagnose(write_json: bool = True,
                 verbose: bool = True) -> DiagnosticReport:
    report = DiagnosticReport()

    print(f"\n{BOLD}{CYAN}"
          f"{'━' * 57}\n"
          f"  RAPPORT DE DIAGNOSTIC VANTABLACK GODMODE\n"
          f"{'━' * 57}{NC}")

    s01_environnement(report)
    s02_core_imports(report)
    s03_attack_imports(report)
    s04_blue_imports(report)
    s05_ruff(report)
    s06_pytest(report)

    print(f"\n{BOLD}{CYAN}"
          f"{'━' * 57}\n"
          f"  RÉSUMÉ PAR SECTION\n"
          f"{'━' * 57}{NC}\n")
    print(report.summary())

    if write_json:
        import json
        DIAGNOSE_OUTPUT.write_text(json.dumps(report.to_dict(),
                                              indent=2, ensure_ascii=False))
        print(f"\n  {GREEN}→{NC} JSON stocké : {DIAGNOSE_OUTPUT}")

    print(f"\n{BOLD}{CYAN}{'━' * 57}{NC}")
    return report


if __name__ == "__main__":
    rep = run_diagnose(verbose=True)
    # Valeurs de sortie : 0 = tout OK, 1 = warnings non critiques, 2 = échecs majeurs
    total = sum(s.total_count for s in rep.sections.values())
    oks = sum(s.ok_count for s in rep.sections.values())
    fails = total - oks
    if fails == 0:
        sys.exit(0)
    # 1 ou plusieurs échecs mais section environnement venv présent = non critique
    env_sec = rep.sections.get("environnement")
    venv_ok = any(e[0] == "venv_python" and e[1] for e in env_sec.entries) \
        if env_sec else False
    # Si fails sont seulement des binaires optionnels (Go, redis, npm...) → 1
    critical_fail = False
    for sec in ("core_imports", "attack_imports", "blue_imports"):
        s = rep.sections.get(sec)
        if s and (s.total_count - s.ok_count) > 0:
            critical_fail = True
    sys.exit(2 if critical_fail else 1)
