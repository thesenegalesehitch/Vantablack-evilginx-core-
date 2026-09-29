"""
attack.anti_analysis — Contre-mesures Anti-VM / Anti-Sandbox / Anti-Analyse
===========================================================================

Détecte si l'implant ou l'attaque s'exécute dans :
  - Une machine virtuelle (VMware, VirtualBox, Hyper-V, KVM, QEMU)
  - Un sandbox d'analyse (Cuckoo, Joe Sandbox, Any.Run, Falcon Sandbox)
  - Un debugger attaché (WinDbg, x64dbg, OllyDbg, GDB)
  - Une analyse statique/dynamique (timing checks, CPUID traps)

Stratégies de contre-mesures :
  - Sleep obfuscation : pas de time.sleep() détectable, boucles de calcul
  - Timing checks : mesure de la dérive temporelle (sandbox = temps accéléré)
  - Hardware fingerprint : RAM < 4GB, CPU < 2 cores, pas de GPU = suspect
  - Registry / WMI checks : clés et classes spécifiques aux VM
  - Process list : présence de processus d'analyse (vboxservice, vmtoolsd...)
  - MAC address : OUI connus des hyperviseurs

Conformité : réservé aux tests en labo autorisé.
"""

from .detector import (
    VENDOR_HYPERV,
    VENDOR_KVM,
    VENDOR_QEMU,
    VENDOR_VIRTUALBOX,
    VENDOR_VMWARE,
    VENDOR_XEN,
    AntiAnalysisDetector,
    EnvironmentCheckResult,
    SandboxHeuristic,
    check_environment_trust,
    obfuscated_sleep,
    stealth_timing_check,
)

__all__ = [
    "VENDOR_HYPERV",
    "VENDOR_KVM",
    "VENDOR_QEMU",
    "VENDOR_VIRTUALBOX",
    "VENDOR_VMWARE",
    "VENDOR_XEN",
    "AntiAnalysisDetector",
    "EnvironmentCheckResult",
    "SandboxHeuristic",
    "check_environment_trust",
    "obfuscated_sleep",
    "stealth_timing_check",
]
