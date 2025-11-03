# MANUEL UTILISATEUR - PROJET VANTABLACK (SÉCURITÉ INDUSTRIELLE)

Bienvenue dans le manuel officiel du projet **VANTABLACK** (Advanced Logical Extraction & X-Orchestration). Ce document est conçu pour vous guider dans l'installation, la configuration et l'opération de cette infrastructure d'audit de sécurité ultra-résiliente.

---

## 1. Description du Système

VANTABLACK est une plateforme d'orchestration **polymorphe**. Elle ne remplace pas les outils existants, elle les **dirige** et les **protège**. VANTABLACK gère principalement deux moteurs :
- **Evilginx** : Le cœur de l'interception (Reverse Proxy).
- **Gophish** : Le gestionnaire de campagnes d'audit.

VANTABLACK ajoute une couche de **Cloaking (furtivité)**, de **Persistance (SQLite Vault)** et de **Monitoring (Nervous System API)** pour garantir un déploiement de classe industrielle.

---

## 2. Installation Rapide

### Pré-requis
- **Système** : macOS ou Linux (recommandé pour les privilèges réseau).
- **Dépendances** : Python 3.10+, Docker & Docker Compose (optionnel mais recommandé).

### Méthode 1 : Docker (Recommandée)
C'est la méthode la plus simple et la plus sûre. Elle isole l'infrastructure.
```bash
# Se déplacer dans le dossier
cd /Users/macbookpro/Downloads/alex

# Lancer l'infrastructure complète
docker-compose up -d --build
```

### Méthode 2 : Installation Native
```bash
# Créer et activer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'orchestrateur
sudo python3 vanta.py --stealth-level 3
```

---

## 3. Configuration de l'Arsenal

Le fichier central de configuration est `hitch_config.yaml`.

### Exfiltration Telegram
Pour recevoir les captures en temps réel sur votre téléphone :
1. Créez un bot via **@BotFather**.
2. Récupérez votre **TOKEN**.
3. Récupérez votre **CHAT_ID** (via @userinfobot).
4. Remplissez le fichier :
```yaml
telegram:
  token: "VOTRE_TOKEN"
  chat_id: "VOTRE_ID"
```

---

## 4. Guide des Opérations

### Lancement des Moteurs
Utilisez l'orchestrateur `vanta.py` pour piloter le système :
```bash
sudo python3 vanta.py [OPTIONS]
```
**Options disponibles :**
- `--stealth-level [1-5]` : Niveau d'agressivité de l'évasion (5 est le plus furtif).
- `--auto-kill` : Active l'autodestruction des données sensibles si une sandbox est détectée.
- `--proxy-list [FILE]` : Utilise une liste de proxies résidentiels.

### Surveillance en temps réel
Ouvrez un nouveau terminal pour surveiller les captures sans polluer l'orchestrateur :
```bash
python3 monitor_captures.py
```

### Vérification de l'Infrastructure
Pour vérifier que tous les ports (80, 443, 8000, 3333) sont ouverts et sécurisés :
```bash
python3 check_status.py
```

---

## 5. Le "Nervous System" (API & Vault)

VANTABLACK n'écrit pas de simples fichiers logs. Toutes les données interceptées passent par une API interne (**FastAPI**) et sont scellées dans une base de données **SQLite** (`hitch_vault.db`).
- **Persistance** : Même si le serveur crash, vos captures sont sauvegardées.
- **Exportation** : Utilisez `vanta/utils/export_vault.py` pour extraire les données en JSON proprement.

---

## 6. Gouvernance Étique & OPSEC

> [!CAUTION]
> **RAPPEL JURIDIQUE**
> L'utilisation de cet outil est strictement réservée au Red Teaming professionnel. Toute utilisation sans contrat écrit préalable est illégale.

**Conseils OPSEC (Sécurité Opérationnelle) :**
- Toujours utiliser un **VPN** ou un proxy résidentiel pour masquer l'IP source de VANTABLACK.
- Activer le `--stealth-level 3` minimum pour bloquer les robots de Microsoft et Google.
- Vérifier régulièrement l'intégrité des binaires via le menu audit.

---

**VANTABLACK : Through the Looking Glass of Security.**
