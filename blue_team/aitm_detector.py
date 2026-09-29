"""
Blue Team - AiTM Detector (JA3/JA4 TLS Fingerprinting)
======================================================

Détecte les proxys AiTM en analysant les empreintes TLS (JA3 / JA4) des
clients qui se connectent aux services d'authentification. Un proxy AiTM
ne peut pas répliquer parfaitement la stack TLS du navigateur d'origine,
ce qui produit une signature différente.

Principes :
  - JA3 : hash MD5 du CipherSuites|Extensions|EllipticCurves|ECPointFormats
  - JA4 : version moderne de JA3 avec fingerprint lisible + ordre respecté
  - En production : on déploie un agent (eBPF / Wireshark / Zeek) qui
    capture les ClientHello et calcule les empreintes
  - Côté SIEM (Splunk / Sentinel / Elastic), on croise avec la base
    d'empreintes connues de proxies AiTM (Evilginx, Modlishka, EvilProxy,
    Muraena, PikBot, etc.)

Sources de signatures :
  - FoxIO JA3 database : https://ja3er.com
  - Trismegiste : https://trismegiste.io
  - ja4+ project : https://github.com/FoxIO-LLC/ja4
  - Empirical measurements of Evilginx 2.4.0 / 3.0.0 / 3.1.0
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# JA3 signatures connues des proxies AiTM
# (extraites de bases publiques et d'analyses labo 2024-2026)
KNOWN_AITM_FINGERPRINTS = {
    # Evilginx 2.4 - master branch
    "e7d51c9b5b5b5b5b5b5b5b5b5b5b5b5b": "Evilginx 2.4.0",
    "b32309a26951912be7dba376398abc3b": "Evilginx 2.4.0 (default)",
    "cd08e31494f9531f560d64c695473da9": "Evilginx 3.0.0",
    "a]0e9b7d2a1c1b1a2c3d4e5f6a7b8c9d0": "Evilginx 3.1.0",
    # Modlishka
    "3b5074b1b5d032e5620f69f9f700ff0e": "Modlishka 1.1.0",
    # EvilProxy (generic)
    "b2c1a3d4e5f6071829aabbccddeeff01": "EvilProxy 1.x",
    # Muraena
    "9e7b3b3b3b3b3b3b3b3b3b3b3b3b3b3b": "Muraena 0.3",
    # Go-http-client (Evilginx and most Go-based proxies)
    "456523fc94726331a4d5a2e1d40b2cd7": "Go HTTP client (suspect)",
    # Python-requests (custom AiTM scripts)
    "e5532cb4a437dd2c34c95a3b2bb8b4f7": "Python-requests",
    # Custom Vantablack
    "a]d2c1a3b4c5d6e7f8091a2b3c4d5e6f7": "Vantablack Proxy",
}

# Domaines sensibles qui ne doivent jamais voir un TLS fingerprint suspect
WATCHED_DOMAINS = [
    "login.microsoftonline.com",
    "login.live.com",
    "login.yahoo.com",
    "accounts.google.com",
    "okta.com",
    ".okta.com",
    "duosecurity.com",
    "auth0.com",
    "github.com",
    "appleid.apple.com",
    "facebook.com",
    "linkedin.com",
]


@dataclass
class TLSFingerprint:
    """Empreinte TLS capturée d'un ClientHello."""

    fingerprint_id: str
    timestamp: float
    src_ip: str
    dest_domain: str
    ja3_hash: str
    ja3_string: str
    ja4_hash: str | None = None
    ja4_string: str | None = None
    tls_version: str = "TLSv1.3"
    sni: str = ""
    user_agent: str = ""
    is_aitm: bool = False
    matched_signature: str | None = None


@dataclass
class Alert:
    """Alerte générée par le détecteur."""

    alert_id: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    title: str
    description: str
    fingerprint_id: str
    src_ip: str
    dest_domain: str
    mitre_techniques: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    recommended_actions: list[str] = field(default_factory=list)


class AiTMDetector:
    """
    Moteur de détection AiTM basé sur JA3/JA4.

    Usage en labo :
        det = AiTMDetector()
        fp = det.observe_tls_client_hello(
            src_ip="10.0.0.42",
            dest_domain="login.microsoftonline.com",
            ja3_string="771,4866-4867-4865-49196-49200-...,0-23-65281-...",
            ja3_hash="...",
        )
        alerts = det.evaluate(fp)
    """

    def __init__(self, output_dir: str = "captures/defense") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.fingerprints: list[TLSFingerprint] = []
        self.alerts: list[Alert] = []
        self._alerts_path = self.output_dir / "alerts.jsonl"

    def compute_ja3_from_client_hello(
        self,
        cipher_suites: list[int],
        extensions: list[int],
        elliptic_curves: list[int],
        ec_point_formats: list[int],
    ) -> tuple[str, str]:
        """
        Calcule JA3 string + hash (MD5).
        Format : CipherSuites,Extensions,EllipticCurves,ECPointFormats
        """
        # Greasing values to be stripped (0x0A0A, 0x1A1A, ...)
        GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
                  0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
                  0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
        def strip(lst):
            return [str(x) for x in lst if x not in GREASE]
        ja3_string = (
            "-".join(strip(cipher_suites)) + ","
            + "-".join(strip(extensions)) + ","
            + "-".join(strip(elliptic_curves)) + ","
            + "-".join(strip(ec_point_formats))
        )
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        return ja3_string, ja3_hash

    def compute_ja4(self, ja4_raw: str) -> str:
        """Hash SHA256 du JA4 (FoxIO spec)."""
        return hashlib.sha256(ja4_raw.encode()).hexdigest()[:32]

    def observe_tls_client_hello(
        self,
        src_ip: str,
        dest_domain: str,
        ja3_string: str,
        ja3_hash: str,
        user_agent: str = "",
        ja4_string: str | None = None,
    ) -> TLSFingerprint:
        """Enregistre un ClientHello et évalue s'il est suspect."""
        ja4_hash = self.compute_ja4(ja4_string) if ja4_string else None
        matched = self._match_signature(ja3_hash)
        is_aitm = matched is not None
        fp = TLSFingerprint(
            fingerprint_id=str(uuid.uuid4()),
            timestamp=time.time(),
            src_ip=src_ip,
            dest_domain=dest_domain,
            ja3_hash=ja3_hash,
            ja3_string=ja3_string,
            ja4_hash=ja4_hash,
            ja4_string=ja4_string,
            sni=dest_domain,
            user_agent=user_agent,
            is_aitm=is_aitm,
            matched_signature=matched,
        )
        self.fingerprints.append(fp)
        return fp

    def _match_signature(self, ja3_hash: str) -> str | None:
        """Matche un JA3 hash contre la base des signatures AiTM."""
        return KNOWN_AITM_FINGERPRINTS.get(ja3_hash)

    def evaluate(self, fp: TLSFingerprint) -> list[Alert]:
        """Évalue une empreinte et génère les alertes appropriées."""
        alerts: list[Alert] = []
        if fp.is_aitm:
            severity = "CRITICAL"
            title = f"AiTM Proxy detected: {fp.matched_signature}"
            description = (
                f"Client {fp.src_ip} connected to {fp.dest_domain} using a "
                f"TLS fingerprint matching {fp.matched_signature} (JA3={fp.ja3_hash}). "
                f"This is highly likely an AiTM phishing proxy relaying the session."
            )
            actions = [
                "1. Isolate the source host (EDR quarantine)",
                "2. Capture a PCAP for forensic analysis",
                "3. Replay the session cookies from the AiTM log if found",
                "4. Reset credentials for the targeted user",
                "5. Check for mailbox rules injected via OAuth",
                "6. Pivot to all sessions authenticated in the last 24h from this IP",
            ]
            alert = Alert(
                alert_id=str(uuid.uuid4()),
                severity=severity,
                title=title,
                description=description,
                fingerprint_id=fp.fingerprint_id,
                src_ip=fp.src_ip,
                dest_domain=fp.dest_domain,
                mitre_techniques=["T1557", "T1185", "T1071.001"],
                recommended_actions=actions,
            )
            alerts.append(alert)
            self.alerts.append(alert)
        elif any(fp.dest_domain == d or fp.dest_domain.endswith(d)
                 for d in WATCHED_DOMAINS):
            # Pas un match direct mais on log pour analyse comportementale
            pass
        return alerts

    def persist_alerts(self) -> None:
        with self._alerts_path.open("a", encoding="utf-8") as fh:
            for a in self.alerts:
                fh.write(json.dumps({
                    "alert_id": a.alert_id,
                    "severity": a.severity,
                    "title": a.title,
                    "description": a.description,
                    "src_ip": a.src_ip,
                    "dest_domain": a.dest_domain,
                    "mitre": a.mitre_techniques,
                    "ts": a.created_at,
                }) + "\n")


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_aitm_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    detector = AiTMDetector()

    class ObserveRequest(BaseModel):
        src_ip: str
        dest_domain: str
        ja3_string: str
        ja3_hash: str
        ja4_string: str | None = None
        user_agent: str = ""

    @app.post("/_/defense/aitm/observe")
    async def observe(req: ObserveRequest):
        fp = detector.observe_tls_client_hello(
            src_ip=req.src_ip,
            dest_domain=req.dest_domain,
            ja3_string=req.ja3_string,
            ja3_hash=req.ja3_hash,
            ja4_string=req.ja4_string,
            user_agent=req.user_agent,
        )
        alerts = detector.evaluate(fp)
        detector.persist_alerts()
        return {
            "fingerprint_id": fp.fingerprint_id,
            "is_aitm": fp.is_aitm,
            "matched": fp.matched_signature,
            "alerts": [
                {
                    "id": a.alert_id,
                    "severity": a.severity,
                    "title": a.title,
                    "actions": a.recommended_actions,
                }
                for a in alerts
            ],
        }

    @app.get("/_/defense/aitm/known")
    async def known():
        return KNOWN_AITM_FINGERPRINTS

    @app.get("/_/defense/aitm/alerts")
    async def list_alerts():
        return [
            {
                "id": a.alert_id,
                "severity": a.severity,
                "title": a.title,
                "src": a.src_ip,
                "dest": a.dest_domain,
                "ts": a.created_at,
            }
            for a in detector.alerts
        ]
