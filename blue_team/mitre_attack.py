"""
Blue Team - MITRE ATT&CK Mapping
=================================

Mapping complet des techniques offensives du Red Team vers MITRE ATT&CK
v15 (Enterprise + ICS). Permet de :
  1. Générer des détections basées sur le framework
  2. Produire des rapports d'incident alignés
  3. Calculer un score de couverture défense (heatmap)
  4. Recommander des mitigations (M-Series)

Chaque technique a :
  - ID MITRE (T-numéro)
  - Tactique
  - Description
  - Data sources de détection
  - Mitigations recommandées
  - Modules Vantablack associés
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Modèle de données
# ---------------------------------------------------------------------------

@dataclass
class MitreTechnique:
    technique_id: str               # ex: "T1557"
    name: str
    tactic: str
    description: str
    url: str = "https://attack.mitre.org/techniques/"  # suffix ajouté
    data_sources: list[str] = field(default_factory=list)
    detections: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    vantablack_modules: list[str] = field(default_factory=list)
    severity: str = "HIGH"


# ---------------------------------------------------------------------------
# Catalogue des techniques couvertes par Vantablack
# ---------------------------------------------------------------------------

TECHNIQUES: list[MitreTechnique] = [
    # --- Initial Access ---
    MitreTechnique(
        technique_id="T1566.002",
        name="Spearphishing Link",
        tactic="initial-access",
        description=(
            "Adversary sends a link to a victim that leads to a phishing kit, "
            "an AiTM proxy, or a BitB popup."
        ),
        url="T1566/002",
        data_sources=["Network Traffic", "Email", "File: File Creation"],
        detections=[
            "Proxy logs : connection to newly-registered domain < 30 days",
            "Email gateway : links to URL shorteners + non-corporate IdP",
            "EDR : browser navigation to known phishing TLDs",
        ],
        mitigations=[
            "M1054 - Software Configuration: enable SmartScreen / SafeBrowsing",
            "M1017 - User Training: phishing awareness program",
            "M1031 - Network Intrusion Prevention: block known phishing infra",
        ],
        vantablack_modules=["automated_flow", "bitb", "mfa_bombing"],
    ),
    MitreTechnique(
        technique_id="T1185",
        name="Browser Session Hijacking",
        tactic="collection",
        description=(
            "Adversary hijacks an existing browser session by stealing cookies "
            "via AiTM proxy or BitB."
        ),
        url="T1185",
        data_sources=["Network Traffic", "Web Logs"],
        detections=[
            "JA3 fingerprint of known AiTM proxy (Evilginx, EvilProxy)",
            "Cookie replay from unexpected IP / ASN",
            "TLS fingerprint mismatch between sessions of the same user",
        ],
        mitigations=[
            "M1054 - Bind session cookies to device (DPoP / Token Binding)",
            "M1026 - Privileged Account Management: use FIDO2 / WebAuthn",
            "M1031 - Network Intrusion Prevention: TLS fingerprinting",
        ],
        vantablack_modules=["aitm_detector", "bitb_detector"],
        severity="CRITICAL",
    ),
    MitreTechnique(
        technique_id="T1557",
        name="Adversary-in-the-Middle",
        tactic="credential-access",
        description=(
            "Adversary positions themselves between the victim and a legitimate "
            "service to intercept and modify traffic."
        ),
        url="T1557",
        data_sources=["Network Traffic", "Web Logs"],
        detections=[
            "JA3/JA4 fingerprinting",
            "TLS interception by third-party CDN not in allowlist",
            "Mutual TLS / mTLS breaking",
        ],
        mitigations=[
            "M1041 - Encrypt Sensitive Information: enforce HTTPS / HSTS",
            "M1037 - Filter Network Traffic: certificate pinning",
            "M1031 - Network Intrusion Prevention: TLS inspection",
        ],
        vantablack_modules=["aitm_detector", "bitb_detector", "automated_flow"],
    ),
    # --- Defense Evasion / Persistence ---
    MitreTechnique(
        technique_id="T1550.001",
        name="Use Alternate Authentication Material: Application Access Token",
        tactic="defense-evasion",
        description=(
            "Adversary uses stolen OAuth tokens to authenticate to cloud "
            "services without re-auth."
        ),
        url="T1550/001",
        data_sources=["Logon Session", "User Account"],
        detections=[
            "OAuth consent grants to unknown apps (publisher unverified)",
            "Token replay from unexpected IP / ASN",
            "Refresh token age > 24h for first-party apps",
        ],
        mitigations=[
            "M1047 - Audit: review OAuth grants weekly",
            "M1026 - Privileged Account Management: limit consent to admins",
            "M1018 - Account Management: rotate SP secrets quarterly",
        ],
        vantablack_modules=["oauth_monitor", "incident_response"],
        severity="CRITICAL",
    ),
    MitreTechnique(
        technique_id="T1528",
        name="Steal Application Access Token",
        tactic="credential-access",
        description=(
            "Adversary steals tokens (browser local, Outlook, CLI) to bypass "
            "MFA and authenticate as the user."
        ),
        url="T1528",
        data_sources=["File: File Access", "Command Execution"],
        detections=[
            "Abnormal access to Chrome/Edge Cookies database",
            "Read of ~/.aws/credentials or ~/.azure/ by unusual process",
            "EDR : process access to browser Local Storage by non-browser",
        ],
        mitigations=[
            "M1027 - Password Policies: short-lived tokens + DPoP binding",
            "M1054 - Software Configuration: disable browser password storage",
            "M1018 - Account Management: enforce FIDO2 for sensitive apps",
        ],
        vantablack_modules=["token_harvester", "device_code_detector"],
    ),
    MitreTechnique(
        technique_id="T1098.001",
        name="Account Manipulation: Additional Cloud Credentials",
        tactic="persistence",
        description=(
            "Adversary adds OAuth apps / service principals to maintain "
            "access after credential reset."
        ),
        url="T1098/001",
        data_sources=["Logon Session", "User Account"],
        detections=[
            "New OAuth app in tenant with high-risk scopes",
            "Service principal added with Owner / Contributor role",
            "App permission grant to mailbox.Read outside known apps",
        ],
        mitigations=[
            "M1018 - Account Management: restrict who can consent to apps",
            "M1047 - Audit: review apps weekly",
            "M1032 - Multi-factor Authentication: enforce for app consent",
        ],
        vantablack_modules=["oauth_monitor"],
    ),
    MitreTechnique(
        technique_id="T1114.003",
        name="Email Collection: Email Forwarding Rule",
        tactic="collection",
        description=(
            "Adversary injects inbox rules to forward / hide / delete emails "
            "(BEC, financial fraud)."
        ),
        url="T1114/003",
        data_sources=["Logon Session", "Email"],
        detections=[
            "Inbox rule forwarding to external domain",
            "Rule hiding 'security' or 'phishing' keywords",
            "Rule created within 24h of credential compromise",
        ],
        mitigations=[
            "M1047 - Audit: alert on inbox rule changes",
            "M1031 - Network Intrusion Prevention: block external forwarding",
            "M1018 - Account Management: review mailbox permissions",
        ],
        vantablack_modules=["mailbox_pivot", "incident_response"],
    ),
    MitreTechnique(
        technique_id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="command-and-control",
        description=(
            "Adversary tunnels C2 over HTTPS / WebSocket to blend in with "
            "legitimate traffic."
        ),
        url="T1071/001",
        data_sources=["Network Traffic"],
        detections=[
            "Outbound WS connections to non-corporate domains",
            "TLS connections with mismatched SNI / Host header (domain fronting)",
            "Long-lived WS connections (>1h) with high data exfil volume",
        ],
        mitigations=[
            "M1031 - Network Intrusion Prevention: TLS inspection",
            "M1037 - Filter Network Traffic: egress allowlist by domain reputation",
            "M1041 - Encrypt Sensitive Information: enforce mTLS internally",
        ],
        vantablack_modules=["ws_smuggling", "domain_fronting"],
    ),
    MitreTechnique(
        technique_id="T1090.004",
        name="Proxy: Domain Fronting",
        tactic="command-and-control",
        description=(
            "Adversary uses domain fronting via CDN to hide C2 traffic."
        ),
        url="T1090/004",
        data_sources=["Network Traffic"],
        detections=[
            "Mismatch between SNI and Host header",
            "Connection to CDN followed by direct connection to non-CDN IP",
            "egress filtering anomalies",
        ],
        mitigations=[
            "M1037 - Filter Network Traffic: enforce SNI == Host header",
            "M1031 - Network Intrusion Prevention: CDN egress allowlist",
        ],
        vantablack_modules=["domain_fronting"],
    ),
    MitreTechnique(
        technique_id="T1620",
        name="Reflective Code Loading",
        tactic="defense-evasion",
        description=(
            "Adversary reflects downloaded code into memory (e.g., Service "
            "Worker in browser)."
        ),
        url="T1620",
        data_sources=["File: File Creation", "Process"],
        detections=[
            "Service Worker registration from non-corporate domain",
            "Egress to script hosting with no business justification",
        ],
        mitigations=[
            "M1054 - Software Configuration: SW allowlist by domain",
            "M1018 - Account Management: restrict browser extensions",
        ],
        vantablack_modules=["sw_persistence"],
    ),
    MitreTechnique(
        technique_id="T1070.002",
        name="Indicator Removal: Clear Linux/Mac Logs",
        tactic="defense-evasion",
        description=(
            "Adversary clears logs to hide compromise (EventLog clear, "
            "PowerShell history clear, file wipe)."
        ),
        url="T1070/002",
        data_sources=["File: File Deletion", "Windows Event Logs"],
        detections=[
            "wevtutil clear invocation by non-admin process",
            "PowerShell history size drop",
            "Prefetch deletion anomaly",
        ],
        mitigations=[
            "M1029 - Remote Data Storage: forward logs to SIEM in real time",
            "M1022 - Restrict File and Directory Permissions: protect logs",
        ],
        vantablack_modules=["anti_forensics"],
    ),
    MitreTechnique(
        technique_id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        tactic="defense-evasion",
        description=(
            "Adversary uses stolen cloud credentials (OAuth tokens, device "
            "code grants) to access resources."
        ),
        url="T1078/004",
        data_sources=["Logon Session", "User Account"],
        detections=[
            "OAuth consent to high-risk scopes",
            "Device code flow from suspicious UA",
            "Login from impossible-travel IP",
        ],
        mitigations=[
            "M1018 - Account Management: enforce FIDO2 + Conditional Access",
            "M1032 - Multi-factor Authentication: phishing-resistant MFA",
            "M1026 - Privileged Account Management: just-in-time access",
        ],
        vantablack_modules=["oauth_monitor", "device_code_detector", "incident_response"],
        severity="CRITICAL",
    ),
    # --- MFA bombing ---
    MitreTechnique(
        technique_id="T1621",
        name="Request Browser Notifications (MFA fatigue)",
        tactic="credential-access",
        description=(
            "Adversary triggers multiple MFA push notifications until user "
            "accepts by error or exhaustion."
        ),
        url="T1621",
        data_sources=["Logon Session", "User Account"],
        detections=[
            ">3 MFA push requests in <1h for the same user",
            "MFA push followed by user complaint about 'IT support' call",
            "MFA accept on IP different from historical pattern",
        ],
        mitigations=[
            "M1032 - Multi-factor Authentication: number matching (Authenticator v2)",
            "M1018 - Account Management: limit MFA push per session",
            "M1054 - Software Configuration: require biometric for MFA",
        ],
        vantablack_modules=["mfa_bombing", "incident_response"],
    ),
]


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

class MitreAttackMapper:
    """Gestionnaire du mapping MITRE ATT&CK."""

    def __init__(self) -> None:
        self.techniques = {t.technique_id: t for t in TECHNIQUES}

    def by_tactic(self) -> dict[str, list[MitreTechnique]]:
        """Regroupe par tactique."""
        out: dict[str, list[MitreTechnique]] = {}
        for t in TECHNIQUES:
            out.setdefault(t.tactic, []).append(t)
        return out

    def coverage_report(self) -> dict[str, Any]:
        """Calcule la couverture défense (nb techniques, par sévérité)."""
        by_severity: dict[str, int] = {}
        for t in TECHNIQUES:
            by_severity[t.severity] = by_severity.get(t.severity, 0) + 1
        return {
            "total_techniques": len(TECHNIQUES),
            "by_severity": by_severity,
            "tactics": sorted({t.tactic for t in TECHNIQUES}),
        }

    def technique_to_dict(self, t: MitreTechnique) -> dict[str, Any]:
        return {
            "id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
            "description": t.description,
            "url": "https://attack.mitre.org/techniques/" + t.url,
            "data_sources": t.data_sources,
            "detections": t.detections,
            "mitigations": t.mitigations,
            "vantablack_modules": t.vantablack_modules,
            "severity": t.severity,
        }


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_mitre_routes(app) -> None:
    from fastapi import HTTPException

    mapper = MitreAttackMapper()

    @app.get("/_/defense/mitre/techniques")
    async def list_techniques():
        return [mapper.technique_to_dict(t) for t in TECHNIQUES]

    @app.get("/_/defense/mitre/technique/{tid}")
    async def get_technique(tid: str):
        t = mapper.techniques.get(tid)
        if not t:
            raise HTTPException(404, "technique not found")
        return mapper.technique_to_dict(t)

    @app.get("/_/defense/mitre/coverage")
    async def coverage():
        return mapper.coverage_report()
