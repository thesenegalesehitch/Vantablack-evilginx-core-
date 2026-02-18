# Guide Utilisateur & FAQ - VANTABLACK v4.0
*Pour les futures légendes de la Red Team*

---

## 👋 Bienvenue

Félicitations pour votre accès à VANTABLACK v4.0. Ce guide a été conçu spécialement pour vous accompagner dans vos premiers pas, même si vous débutez dans le domaine. Notre objectif est de rendre l'orchestration de campagnes Red Team aussi simple et intuitive que possible.

---

## 🚀 Installation et Démarrage Rapide

### Prérequis
*   Un ordinateur (Mac, Linux ou Windows avec WSL)
*   Docker (si vous utilisez la version conteneurisée)
*   Python 3.9+

### Lancer l'Application

Nous avons simplifié le processus avec un script unique.

1.  **Ouvrir le Terminal** : Accédez au dossier du projet.
    ```bash
    cd /Users/pro/SaaS/Vantablack
    ```

2.  **Installation Automatique** (Première fois seulement) :
    Ce script va installer toutes les dépendances (Python et Interface Web).
    ```bash
    python3 vanta.py --setup
    ```
    *Note : Cela peut prendre quelques minutes.*

3.  **Démarrer VANTABLACK** :
    Une fois l'installation terminée, lancez simplement :
    ```bash
    python3 vanta.py
    ```
    
    Cela ouvrira automatiquement :
    *   Le serveur Backend (API)
    *   L'interface Web (Dashboard)

4.  **Accéder à l'Interface** :
    Si elle ne s'ouvre pas automatiquement, allez sur `http://localhost:3000`.

---

## 🖥️ Tour de l'Interface

L'interface de VANTABLACK est divisée en plusieurs sections clés accessibles via le menu latéral.

### 1. Dashboard (Tableau de Bord)
C'est votre centre de commande.
*   **Métriques Clés** : Vue d'ensemble (Nombre de phishlets, Campagnes actives, Taux de succès).
*   **Graphique de Performance** : Suivez l'efficacité de vos campagnes jour par jour.
*   **Activité Récente** : Un fil d'actualité de tout ce qui se passe sur votre instance (sessions capturées, erreurs, etc.).

### 2. Phishlet Analyzer (Analyseur)
C'est ici que vous préparez vos armes.
*   **Upload** : Chargez un fichier `.yaml` (ex: `o365.yaml`).
*   **Score de Risque** : Vantablack analyse le fichier et vous donne un score de 1 à 10 sur sa furtivité.
*   **Signatures** : Voir quelles signatures (YARA, Snort) sont générées pour protéger vos outils.

### 3. Behavioral Analysis (Analyse Comportementale)
Comprenez vos cibles.
*   **Entonnoir (Funnel)** : Combien de personnes ont cliqué ? Combien ont entré leur mot de passe ?
*   **Appareils & Lieux** : D'où viennent vos victimes ? (Mobile vs Desktop).
*   **Recommandations IA** : Le système vous suggère des améliorations (ex: "Optimisez pour mobile", "Envoyez les emails à 18h").

---

## 🎓 Tutoriel : Ma Première Campagne

Suivez ces étapes pour lancer votre première simulation.

### Étape 1 : Choisir une Cible
Disons que nous ciblons **Microsoft Office 365**.
Allez dans l'onglet *Phishlets* et assurez-vous que `o365.yaml` est présent.

### Étape 2 : Configuration du Domaine
Dans le terminal de Vantablack (ou via l'interface si disponible) :
1.  Configurez votre nom de domaine (ex: `login-secure-update.com`).
2.  Assurez-vous que les DNS pointent vers votre serveur.

### Étape 3 : Créer un "Lure" (Appât)
Le "Lure" est l'URL unique que vous allez envoyer.
1.  Sélectionnez le phishlet `o365`.
2.  Générez une URL.
3.  Copiez cette URL.

### Étape 4 : Envoi et Suivi
1.  Envoyez l'URL à votre compte de test (pour vérifier).
2.  Ouvrez le lien sur votre téléphone (en 4G pour simuler une vraie victime).
3.  Regardez le **Dashboard** : vous devriez voir une nouvelle activité "Session Capturée".

### Étape 5 : Récupération
Une fois la session capturée, vous obtenez un cookie. Importez ce cookie dans votre navigateur pour accéder au compte.

---

## 🚀 Mode God Mode (Multi-Social)

Le "God Mode" est une fonctionnalité avancée permettant de lancer un portail de connexion universel qui supporte plusieurs réseaux sociaux simultanément. C'est idéal pour les campagnes de masse où la cible peut choisir son mode de connexion préféré.

### Lancement
```bash
# Assurez-vous d'être dans l'environnement virtuel ou d'avoir les dépendances installées
python3 godmode.py
```
Le portail sera accessible sur `http://localhost:6666`.

### Fonctionnalités
- **Portail Unifié** : Une seule page pour Facebook, Instagram, X (Twitter), TikTok et Google.
- **Redirection Intelligente** : Redirige automatiquement la victime vers le phishlet approprié selon son choix.
- **Logs en Temps Réel** : Affiche les tentatives de connexion directement dans la console.

---

## ❓ FAQ (Foire Aux Questions)

### Q: J'ai une erreur "Port already in use".
**R:** Un autre programme utilise probablement le port 80 ou 443 (souvent Apache ou Nginx). Arrêtez-les avec `sudo service apache2 stop` ou changez les ports dans la configuration de Vantablack.

### Q: Les victimes voient une alerte rouge "Site Dangereux".
**R:** Votre domaine a été flaggé par Google Safe Browsing.
*   **Solution** : Changez de domaine immédiatement.
*   **Prévention** : Utilisez la fonctionnalité "Rotation de Domaines" de Vantablack.

### Q: Le MFA (Double Authentification) ne passe pas.
**R:**
1.  Vérifiez que vous utilisez bien un phishlet compatible "Session" (comme nos templates O365 ou Google).
2.  Si la victime utilise une clé de sécurité physique (YubiKey), l'attaque échouera. C'est une limitation technique connue.

### Q: Comment mettre à jour Vantablack ?
**R:** `git pull origin main` suivi de `pip install -r requirements-v4.txt` pour mettre à jour les dépendances.

---

## 📖 Glossaire pour Débutants

*   **Phishlet** : Un fichier de configuration (YAML) qui dit à Vantablack comment imiter un site spécifique (ex: Facebook).
*   **Lure (Leurre)** : L'URL spécifique générée pour une campagne. C'est le lien sur lequel la victime doit cliquer.
*   **Session Cookie** : Le "ticket d'or". C'est le fichier que Vantablack vole pour vous permettre de vous connecter sans mot de passe ni code SMS.
*   **Red Team** : L'équipe (vous !) qui simule des attaques pour tester la sécurité.
*   **MFA / 2FA** : Authentification Multi-Facteurs (Mot de passe + Code SMS/App).

---

*Bonne chance pour votre soutenance ! L'équipe Vantablack croit en vous.*
