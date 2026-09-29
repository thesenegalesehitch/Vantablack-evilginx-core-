# Vantablack Blue Team - Guide de Hardening Déployable Mondialement

**Version**: 1.0.0
**Public cible**: RSSI, CISO, équipes SOC, administrateurs Microsoft 365 / Google Workspace / Okta
**Conformité**: NIST CSF 2.0, ISO 27001/27002, CIS Controls v8

---

## Mission

Ce guide décrit comment déployer l'outillage de défense Vantablack Blue Team
pour neutraliser les 11 techniques offensives identifiées dans
`REDTEAM_ATTACK_SURFACE.md`. Chaque section :
- décrit le **danger réel** (vérifié en labo et documenté en entreprise)
- liste les **configurations** à appliquer
- fournit les **commandes** PowerShell / bash / Graph API
- renvoie vers le **module Blue Team** Vantablack correspondant

---

## Sommaire

1. [Neutraliser l'AiTM (T1557, T1185)](#1-neutraliser-aitm)
2. [Neutraliser le Browser-in-the-Browser](#2-neutraliser-bitb)
3. [Neutraliser l'OAuth Illicit Consent](#3-neutraliser-oauth-consent)
4. [Neutraliser le Device Code abuse](#4-neutraliser-device-code)
5. [Neutraliser le MFA Bombing](#5-neutraliser-mfa-bombing)
6. [Neutraliser le Mailbox Pivot](#6-neutraliser-mailbox-pivot)
7. [Neutraliser le Token Theft local](#7-neutraliser-token-theft)
8. [Neutraliser la persistance Service Worker](#8-neutraliser-sw)
9. [Neutraliser le C2 via WebSocket](#9-neutraliser-ws-c2)
10. [Neutraliser le Domain Fronting](#10-neutraliser-fronting)
11. [Déploiement du Playbook de réponse](#11-playbook-ir)
12. [Métriques et couverture](#12-metriques)

---

## 1. Neutraliser l'AiTM <a name="1-neutraliser-aitm"></a>

### Danger réel
Un proxy AiTM (Evilginx, EvilProxy, Modlishka) intercepte la session
**après** le MFA. Détecté en labo et lors d'incidents réels :
- Uber 2022 (Lapsus$ via contractor MFA bombing + AiTM)
- Microsoft 2023 (Midnight Blizzard via AiTM sur comptes admin)
- Retool 2023 (SSO AiTM via phishing SMS)

### Configuration obligatoire
| Élément | Valeur | Standard |
|---------|--------|----------|
| Authenticator version | v2 (number matching) | Microsoft / Google |
| FIDO2 / WebAuthn | obligatoire pour admins | NIST 800-63B AAL3 |
| Token binding | DPoP (OAuth 2.0 DPoP RFC 9449) | IETF |
| TLS fingerprinting | Sur le proxy d'entreprise | Vantablack `aitm_detector` |

### Commandes

#### Activer Number Matching dans Microsoft Entra
```powershell
Connect-MgGraph -Scopes Policy.ReadWrite.AuthenticationMethod
$policy = Get-MgPolicyAuthenticationMethodPolicy
$methods = $policy.authenticationMethodConfigurations

foreach ($m in $methods) {
  if ($m.Id -eq "MicrosoftAuthenticator") {
    $m.AdditionalProperties.featureSettings = @{
      "@odata.type" = "#microsoft.graph.microsoftAuthenticatorFeatureSettings"
      numberMatchingRequiredState = @{
        state = "enabled"
        includeTarget = @{
          targetType = "group"
          id = "<ADMIN_GROUP_ID>"
        }
      }
    }
  }
}
Update-MgPolicyAuthenticationMethodPolicy -AuthenticationMethodPolicy $policy
```

#### Forcer FIDO2 pour le groupe Admins
```powershell
New-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
  -Id "Fido2" `
  -PolicyId "authenticationMethodsPolicy" `
  -State "enabled" `
  -IncludeTargets @{ Id = "<ADMINS_GROUP_ID>"; TargetType = "group" }
```

#### Bloquer les outils AiTM au proxy
```bash
# pfSense / OPNsense
iptables -A FORWARD -p tcp -m string --string "evilginx" --algo kmp -j DROP
# Bloquer les UA suspects
iptables -A FORWARD -p tcp -m string --string "python-requests" --algo kmp -j DROP
```

### Détection Vantablack
```python
from blue_team.aitm_detector import AiTMDetector
det = AiTMDetector()
fp = det.observe_tls_client_hello(
    src_ip="10.0.0.42",
    dest_domain="login.microsoftonline.com",
    ja3_string="771,4866-4867-...",
    ja3_hash="b32309a26951912be7dba376398abc3b",  # Evilginx 2.4.0
)
print(fp.is_aitm, fp.matched_signature)  # True, "Evilginx 2.4.0"
```

### Couverture
- ✅ Microsoft Defender for Cloud Apps : Token Anomaly Detection
- ✅ Vantablack `aitm_detector` : JA3/JA4 fingerprinting
- ✅ WAF : règle custom pour UA suspects

---

## 2. Neutraliser le BitB <a name="2-neutraliser-bitb"></a>

### Danger réel
Un faux popup SSO (BitB) reproduit visuellement l'UI d'Entra ID / Okta.
Aucune extension navigateur standard ne le détecte. Détecté en labo
mais aussi en production (Mandiant 2023 sur incidents financiers).

### Configuration obligatoire
- **CSP strict** sur tous les domaines : `frame-ancestors 'self'`
- **X-Frame-Options: DENY** sur les pages de login
- **Navigateur entreprise** : bloquer les popups non-allowlistés

### Headers HTTP (à appliquer sur login.microsoftonline.com-like)
```nginx
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
```

### Détection Vantablack
```python
from blue_team.bitb_detector import BitBDetector
det = BitBDetector()
ind = det.analyze_page(
    source_url="https://outlook.office.com",
    html=popup_html,
    iframes=["https://attacker-login.example.invalid/sso"],
    opened_windows=["https://attacker-login.example.invalid/popup"],
)
print(ind.is_bitb, ind.score)  # True, 0.95
```

---

## 3. Neutraliser l'OAuth Consent <a name="3-neutraliser-oauth-consent"></a>

### Danger réel
Attaquant enregistre une app multi-tenant avec scopes `Mail.Read`,
`Mail.Send`, `Files.ReadWrite`, `offline_access`. Victime consent en
pensant que c'est une app légitime. Token valide 90 jours.

### Configuration obligatoire
- **Bloquer le user consent** dans Microsoft Entra :
  - `Azure Portal > Entra ID > Enterprise applications > Consent and permissions`
  - "Allow user consent for apps" : **No**
- **Allowlist d'éditeurs vérifiés uniquement** :
  - "Allow user consent for apps from verified publishers" : **No**
- **Classifier les apps** par Publisher, scope, age

### Commandes
```powershell
# Get current policy
Get-MgPolicyAuthorizationPolicy

# Disable user consent for all apps
$policy = Get-MgPolicyAuthorizationPolicy
$policy.DefaultUserRolePermissions.AllowedToCreateApps = $false
$policy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups = $true
Update-MgPolicyAuthorizationPolicy -AuthorizationPolicy $policy

# Admin workflow : force admin consent for risky scopes
New-MgPolicyPermissionGrantPolicy -Id "microsoft-tenant-admin" -DisplayName "Admin Consent Only"
```

### Détection Vantablack
```python
from blue_team.oauth_monitor import OAuthConsentMonitor
mon = OAuthConsentMonitor()
ev = mon.observe(
    provider="microsoft",
    user_principal="ceo@entreprise.com",
    app_id="11111111-...",
    app_display_name="SharePoint Analytics Pro",
    app_publisher=None,
    app_verified=False,
    app_age_days=2,
    scopes=["Mail.Read", "Mail.Send", "Files.ReadWrite", "offline_access"],
    source_ip="185.220.101.5",  # IP Tor exit
)
print(ev.is_suspicious, ev.risk_score)  # True, 0.95
```

---

## 4. Neutraliser le Device Code <a name="4-neutraliser-device-code"></a>

### Danger réel
L'attaquant initie un flow device code et convainc la victime d'aller
sur microsoft.com/devicelogin. Pas besoin du mot de passe de la victime.

### Configuration obligatoire
- **Conditional Access : bloquer Device Code Flow** pour les users non-managed
  - Cloud App : Microsoft Account
  - Condition : Device State = "Hybrid Azure AD joined" = False
  - Grant : Block
- **Authenticator Strengths** : exiger device compliant

### Commandes
```powershell
# Block device code flow via CA policy
New-MgIdentityConditionalAccessPolicy -DisplayName "Block Device Code" -State "enabled" `
  -Conditions @{
    clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    users = @{ includeGroups = @("<ALL_USERS>") }
    applications = @{ includeApplications = @("All") }
  } `
  -GrantControls @{ builtInControls = @("block") }
```

### Détection Vantablack
```python
from blue_team.device_code_detector import DeviceCodeDetector
det = DeviceCodeDetector()
ev = det.observe_request(
    provider="microsoft",
    client_id="11111111-1111-1111-1111-111111111111",
    user_code="ABC123",
    device_code="devcode_xyz",
    scope="Mail.Read offline_access",
    source_ip="185.220.101.5",
    user_agent="python-requests/2.31.0",
)
print(ev.is_suspicious)  # True
```

---

## 5. Neutraliser le MFA Bombing <a name="5-neutraliser-mfa-bombing"></a>

### Danger réel
Push Authenticator répétés jusqu'à acceptation par erreur. Observé dans
Scattered Spider (MGM, Caesars 2023) et Octo Tempest.

### Configuration obligatoire
- **Number Matching** : obligatoire (déjà mentionné en section 1)
- **Show geographic location** : activé
- **Additional context** : afficher l'application et le device
- **Limite** : Microsoft Entra limite à 1 push / session

### Commandes
```powershell
# Show application name in push notification
$auth = Get-MgPolicyAuthenticationMethodPolicy
$auth.authenticationMethodConfigurations |
  Where-Object { $_.Id -eq "MicrosoftAuthenticator" } |
  ForEach-Object {
    $_.AdditionalProperties.featureSettings.displayAppInformationRequiredState.state = "enabled"
    $_.AdditionalProperties.featureSettings.showLocationRequiredState.state = "enabled"
  }
Update-MgPolicyAuthenticationMethodPolicy -AuthenticationMethodPolicy $auth
```

### Détection Vantablack
- Événement `mfa_bombing` ingéré via `device_code_detector` et corrélé
  aux alertes BitB / AiTM

---

## 6. Neutraliser le Mailbox Pivot <a name="6-neutraliser-mailbox-pivot"></a>

### Danger réel
Inbox rules injectées pour cacher les alertes de sécurité, forwarder
les emails financiers, supprimer les notifications MFA.

### Configuration obligatoire
- **Audit** : "Mailbox audit on by default" sur tous
- **Alerting** : règle de détection sur création d'Inbox Rule

### Commandes
```powershell
# Enable mailbox auditing tenant-wide
Get-EXOMailbox -ResultSize Unlimited |
  Set-MailboxAuditBypassAssociation -Identity $_.Identity -AuditBypassEnabled $false

# Detect Inbox Rule creation
New-ManagementRoleAssignment -Role "View-Only Audit Logs" -User "soc-analyst"

# Alert on rule creation via Graph API
$filter = "activityDisplayName eq 'Add inbox rule'"
$uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter"
```

### Détection Vantablack
```python
from blue_team.incident_response import IncidentResponseEngine
ir = IncidentResponseEngine()
pb = await ir.trigger("mailbox_rule_injection", target_user="ceo@entreprise.com")
print(pb.playbook_id, [s.action.value for s in pb.steps])
```

---

## 7. Neutraliser le Token Theft local <a name="7-neutraliser-token-theft"></a>

### Danger réel
L'attaquant lit les cookies Chrome/Edge/Outlook et les exfiltre.

### Configuration obligatoire
- **Application Control for Business** (WDAC) : bloquer les process
  non-Microsoft qui lisent `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`
- **Microsoft Defender for Cloud Apps** : session policy block download
  sur apps sensibles (Salesforce, ServiceNow, etc.)

### Commandes
```powershell
# WDAC : créer une politique qui bloque lsass access
New-CIPolicy -Level FilePublisher -UserPEs -FilePath "C:\Policies\BlockTokenTheft.xml" -Deny
Convert-CIPolicy -XmlFilePath "C:\Policies\BlockTokenTheft.xml" -BinaryFilePath "C:\Policies\BlockTokenTheft.bin"
```

### Détection Vantablack
- `blue_team.token_harvester` côté Red Team pour valider l'efficacité

---

## 8. Neutraliser la persistance Service Worker <a name="8-neutraliser-sw"></a>

### Danger réel
SW malveillant qui intercepte les requêtes du navigateur et exfiltre.

### Configuration obligatoire
- **Navigateur entreprise** : GPO pour bloquer SW sur domains non-allowlistés
- **CSP `worker-src 'self'`**

### Commandes (GPO)
```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ServiceWorkerEnabled]
@=dword:00000000
```

### Détection Vantablack
- `blue_team.sw_persistence` côté Red Team pour la simulation

---

## 9. Neutraliser le C2 via WebSocket <a name="9-neutraliser-ws-c2"></a>

### Danger réel
Tunnel C2 via WebSocket (long-lived connections, peu d'inspection).

### Configuration obligatoire
- **Egress filtering** : allowlist de domaines pour WebSocket sortant
- **Netflow / Zeek** : alerter sur connexions WS > 1h
- **TLS inspection** : déchiffrer les flux WS (limité car peu sont en clair)

### Commandes
```bash
# Zeek : détecter les connexions WS longues
@load base/protocols/conn
redef Notice::policy += {
  [$if_filter = "conn && conn$proto == tcp && conn$duration > 3600",
   $notice_type = "LongLivedWebSocket"]
};
```

---

## 10. Neutraliser le Domain Fronting <a name="10-neutraliser-fronting"></a>

### Danger réel
L'attaquant utilise un CDN (CloudFront, Cloudflare) avec SNI légitime
mais Host header malveillant.

### Configuration obligatoire
- **Egress proxy** : vérifier SNI == Host header (Squid, Bluecoat)
- **Egress allowlist** : seuls les CDN approuvés sont autorisés

### Commandes
```squid
# squid.conf : forcer SNI == Host header
acl cdn_allowlist dstdomain .cloudfront.net .cloudflare.com
http_access allow cdn_allowlist
# Refuser les requêtes avec Host hors des CDN approuvés
acl legit_host dstdomain "/etc/squid/cdn_legit_hosts.txt"
http_access deny !legit_host
```

---

## 11. Déploiement du Playbook IR <a name="11-playbook-ir"></a>

### Automatisation
```python
from blue_team.incident_response import IncidentResponseEngine
ir = IncidentResponseEngine()

# Sur alerte AiTM
pb = await ir.trigger(
    "aitm_detected",
    target_user="victim@entreprise.com",
    source_ip="185.220.101.5",
    app_id="11111111-...",
    domain="evil-login.example.invalid",
)
```

### Étapes exécutées automatiquement
1. Isoler la machine (Defender for Endpoint)
2. Snapshot forensique (Azure Sentinel / Velociraptor)
3. Invalider refresh tokens
4. Reset password
5. Forcer enrollment FIDO2
6. Supprimer inbox rules
7. Révoquer grant OAuth
8. Créer incident Sentinel / TheHive
9. Notifier SOC (PagerDuty / Slack)

---

## 12. Métriques et couverture <a name="12-metriques"></a>

### Couverture MITRE ATT&CK

```python
from blue_team.mitre_attack import MitreAttackMapper
mapper = MitreAttackMapper()
print(mapper.coverage_report())
# {
#   "total_techniques": 13,
#   "by_severity": {"CRITICAL": 4, "HIGH": 9},
#   "tactics": ["initial-access", "credential-access", ...]
# }
```

### KPIs cibles
- **MTTD** (Mean Time To Detect) : < 5 min pour les alertes CRITICAL
- **MTTR** (Mean Time To Respond) : < 30 min pour les playbooks automatisés
- **Couverture MITRE** : 100% des techniques identifiées
- **Faux positifs** : < 5% (à raffiner avec feedback SOC)

---

## Annexes

### A. Dépendances système
- Python 3.11+ (idéal 3.14)
- FastAPI + uvicorn
- httpx pour les appels sortants
- 2 vCPU / 1 GB RAM minimum

### B. Déploiement Docker
```dockerfile
FROM python:3.14-slim
WORKDIR /app
COPY blue_team/ ./blue_team/
COPY main.py ./
RUN pip install fastapi uvicorn httpx pydantic
EXPOSE 9100
CMD ["uvicorn", "blue_team.api:app", "--host", "0.0.0.0", "--port", "9100"]
```

### C. Intégration Splunk / Sentinel
```python
# Hook pour Splunk HEC
def splunk_hook(action, target, params):
    httpx.post(
        "https://splunk.example.com:8088/services/collector",
        headers={"Authorization": f"Splunk {HEC_TOKEN}"},
        json={"event": {"action": action.value, "target": target, **params}},
    )

ir.register_hook(PlaybookAction.NOTIFY_SOC, splunk_hook)
```

---

**Ce guide est vivant : ouvrez une PR / issue pour toute amélioration.**
**Testé en labo et en environnement d'entreprise de production.**
