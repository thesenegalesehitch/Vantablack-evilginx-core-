"""
attack.persistence — Persistance post-compromission
=====================================================

Techniques de persistance MITRE ATT&CK (TA0003) :
  - T1547.001 Registry Run / RunOnce (HKLM / HKCU)
  - T1053.005 Scheduled Task (schtasks.exe / XML)
  - T1546.003 WMI Event Subscription (permanent WMI filter + consumer)
  - T1546.015 COM Hijacking (CLSID InprocServer32)
  - T1547.009 Shortcut Modification (LNK Startup folder)
  - T1574.002 DLL Side-Loading
  - T1543.003 Windows Service (SC.exe)
  - T1547.008 Image File Execution Options (IFEO) Debugger
  - T1556.003 Winlogon Helper DLL (HKLM\\...\\Winlogon\\Notify)
  - T1197 BITS Jobs (Background Intelligent Transfer Service)
  - T1037.001 Logon Script (Group Policy Startup)

Conformité : labo autorisé UNIQUEMENT. La persistance sur un système
d'information sans autorisation écrite est un délit.
"""

from .implant import (
    ComHijackPersistence,
    PersistenceEngine,
    PersistenceReport,
    PersistenceTechnique,
    RunKeyPersistence,
    ScheduledTaskPersistence,
    ServicePersistence,
    WMIEventSubscriptionPersistence,
    create_com_hijack_payload,
    create_run_key_payload,
    create_scheduled_task_xml,
    create_wmi_filter_consumer,
)

__all__ = [
    "ComHijackPersistence",
    "PersistenceEngine",
    "PersistenceReport",
    "PersistenceTechnique",
    "RunKeyPersistence",
    "ScheduledTaskPersistence",
    "ServicePersistence",
    "WMIEventSubscriptionPersistence",
    "create_com_hijack_payload",
    "create_run_key_payload",
    "create_scheduled_task_xml",
    "create_wmi_filter_consumer",
]

# Contrat godmode : helpers kwargs + alias canoniques
from .implant import (  # noqa: E402,F401
    build_com_hijack,
    build_ifeo_debugger,
    create_scheduled_task_xml,
    create_scheduled_task_xml_ex,
    create_wmi_filter_consumer,
    create_wmi_filter_consumer_ex,
)
