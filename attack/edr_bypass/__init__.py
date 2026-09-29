"""
attack.edr_bypass — Contre-mesures EDR / AV / AMSI
====================================================

Implémente les techniques modernes de bypass pour :
  - AMSI (AntiMalware Scan Interface) : patch AmsiScanBuffer
  - ETW (Event Tracing for Windows) : désactivation EtwEventWrite
  - Direct syscalls (SysWhispers-like) : évite les hooks EDR en userland
  - Process Hollowing (concept) : PE injection en mémoire
  - Reflective DLL loading (concept) : charge une DLL sans LoadLibrary
  - Unmanaged PowerShell : exécution sans powershell.exe (CLR via C++)

Conformité : toutes les techniques sont décrites conceptuellement et
simulées pour les tests. L'usage réel nécessite un labo Windows 10/11
avec les autorisations administratives appropriées.
"""

from .amsi import (
    AMSIPatchStrategy,
    BypassReport,
    EDRBypassEngine,
    ETWDisableStrategy,
    SyscallStub,
    disable_etw_tracing,
    generate_syscall_stub,
    patch_amsi_in_memory,
)

__all__ = [
    "AMSIPatchStrategy",
    "BypassReport",
    "EDRBypassEngine",
    "ETWDisableStrategy",
    "SyscallStub",
    "disable_etw_tracing",
    "generate_syscall_stub",
    "patch_amsi_in_memory",
]
