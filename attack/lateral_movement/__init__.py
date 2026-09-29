"""
attack.lateral_movement — Mouvement latéral post-compromission
================================================================

Techniques MITRE ATT&CK de mouvement latéral :
  - T1550.002 Pass-the-Hash (PtH)
  - T1550.003 Pass-the-Ticket (PtT) / Kerberoasting (T1558.003)
  - T1550.004 AS-REP Roasting
  - T1047 Windows Management Instrumentation (WMI)
  - T1021.002 SMB/Windows Admin Shares (PsExec-like)
  - T1021.001 Remote Desktop Protocol (RDP)
  - T1021.006 Windows Remote Management (WinRM)
  - T1570 Lateral Tool Transfer (SMB/WinRM copy)
  - T1090 Proxy / SOCKS pivot

Chaque technique est décrite :
  - Ports / protocoles requis
  - Artefacts laissés (logs, fichiers)
  - Score de furtivité et de succès
  - Étapes d'exécution simulables pour le labo

Conformité : strictement réservé aux labos avec accréditation.
"""

from .pivot import (
    KerberoastTarget,
    LateralMovementEngine,
    LateralMovementReport,
    PassTheHashContext,
    PivotTechnique,
    PsExecContext,
    RDPPivotContext,
    WinRMContext,
    WMICommandContext,
    asrep_roast,
    generate_psexec_command,
    generate_pth_command,
    generate_wmi_exec,
    kerberoast_request,
)

__all__ = [
    "KerberoastTarget",
    "LateralMovementEngine",
    "LateralMovementReport",
    "PassTheHashContext",
    "PivotTechnique",
    "PsExecContext",
    "RDPPivotContext",
    "WMICommandContext",
    "WinRMContext",
    "asrep_roast",
    "generate_psexec_command",
    "generate_pth_command",
    "generate_wmi_exec",
    "kerberoast_request",
]
