# VANTABLACK v4.0 - Script de Démonstration Live

## Préparation de la Démo

### 1. Setup Initial
```bash
# Cloner le projet
git clone https://github.com/username/vantablack.git
cd vantablack

# Installer les dépendances
pip install -r requirements-v4.txt

# Démarrer les services
docker-compose -f docker-compose-v4.yml up -d

# Lancer l'API
python api/rest_api.py
```

### 2. Lancer le Frontend
```bash
cd web/frontend
npm install
npm start
```

### 3. Préparer les données de démo
```bash
# Créer quelques phishlets de démo
cp phishlets/twitter.yaml phishlets/demo_twitter.yaml
cp phishlets/google.yaml phishlets/demo_google.yaml
```

## Script de Démonstration (15 minutes)

### Introduction (2 minutes)
"Bonjour à tous, je vais vous présenter VANTABLACK v4.0, une plateforme révolutionnaire d'orchestration de phishing pour les équipes Red Team."

**Points clés:**
- Problème: Outils existants limités et coûteux
- Solution: Plateforme open-source avec IA et extensibilité
- Innovation: 9 branches techniques uniques

### Démo 1: Interface Web Moderne (3 minutes)

**Action:** Ouvrir http://localhost:3000

**Script:**
"Commençons par l'interface web moderne. Contrairement à Evilginx qui utilise uniquement la ligne de commande, VANTABLACK offre une expérience utilisateur intuitive."

**Navigation:**
1. Dashboard principal avec métriques en temps réel
2. Section Templates avec génération automatique
3. Campaign Management avec A/B testing
4. Analytics avec visualisations interactives

**Points à démontrer:**
- Design responsive et moderne
- Performance (<100ms de réponse)
- Visualisations temps réel avec Recharts

### Démo 2: Reverse Engineering Automatique (2 minutes)

**Action:** Terminal pour analyse de phishlet

```bash
# Analyser un phishlet Twitter
python -m analysis.reverse_engineer.cli analyze phishlets/twitter.yaml --generate-signatures --mitre-mapping
```

**Script:**
"Voyons maintenant le reverse engineering automatique. VANTABLACK analyse automatiquement les phishlets pour extraire des informations critiques."

**Résultats attendus:**
```
[+] Phishlet Analysis Complete
    Risk Score: 8.5/10
    Target Domain: twitter.com
    Auth Flow: OAuth 2.0
    Data Extraction: username, password, email, phone
    
[+] Detection Signatures Generated
    YARA Rules: 3
    Snort Rules: 2
    Regex Patterns: 5
    
[+] MITRE ATT&CK Mapping
    T1566.001: Phishing for Credentials
    T1059.004: Unix Shell
    T1071.001: Web Protocols
```

**Points à démontrer:**
- Analyse automatique en <5 secondes
- Génération de signatures de détection
- Mapping MITRE ATT&CK

### Démo 3: Système de Mutation Intelligente (2 minutes)

**Action:** Génération de variants

```bash
# Générer 10 variants avec évolution haute
python -m analysis.mutation.cli mutate phishlets/twitter.yaml --variants 10 --evasion high --output demo_mutants/
```

**Script:**
"Le système de mutation génère automatiquement des variants pour bypasser les systèmes de détection."

**Résultats attendus:**
```
[+] Mutation Engine Active
    Generating 10 variants...
    Evasion Level: HIGH
    Techniques: Domain variation, Path obfuscation, JS obfuscation
    
[+] Results:
    Variants Generated: 10
    Average Bypass Score: 87.3%
    Detection Resistance: HIGH
    Generation Time: 1.2s
```

**Points à démontrer:**
- Génération rapide de variants
- Score de bypass automatique
- Techniques d'évasion multiples

### Démo 4: Templates Intelligents avec A/B Testing (2 minutes)

**Action:** Interface web pour templates

**Script:**
"VANTABLACK génère automatiquement des templates optimisés et effectue du A/B testing pour maximiser les conversions."

**Navigation:**
1. Aller dans Templates > Generate New
2. Sélectionner Twitter > Login
3. Configurer personnalisation: HIGH
4. Lancer génération

**Résultats attendus:**
- Template généré en <500ms
- Performance score: 0.85
- Compliance score: 0.92

**A/B Testing:**
1. Créer test A/B avec 4 variants
2. Configurer durée: 48 heures
3. Lancer test et monitoring en temps réel

### Démo 5: Analyse Comportementale (2 minutes)

**Action:** Dashboard analytics

**Script:**
"L'analyse comportementale utilise le machine learning pour comprendre les patterns des victimes et optimiser les campagnes."

**Navigation:**
1. Analytics > Behavioral Analysis
2. Visualiser funnel de conversion
3. Segmentation automatique des utilisateurs
4. Recommandations d'optimisation

**Métriques à montrer:**
- Taux de conversion: 8.4%
- Durée moyenne session: 2m 22s
- Top devices: Mobile 58.3%
- Segments identifiés: 4

### Démo 6: API et Intégrations (2 minutes)

**Action:** Démonstration API

```bash
# Test API endpoint
curl -X POST http://localhost:8000/templates/generate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"platform": "twitter", "template_type": "login", "personalization_level": "high"}'
```

**Script:**
"L'API REST complète permet l'intégration avec d'autres outils Red Team."

**Points à démontrer:**
- Documentation OpenAPI: http://localhost:8000/docs
- WebSocket pour temps réel
- Rate limiting et sécurité

### Démo 7: Système de Plugins (1 minute)

**Action:** Créer plugin simple

```python
# Créer plugin d'analyse custom
mkdir plugins/demo_analyzer
cd plugins/demo_analyzer

# plugin.yaml
cat > plugin.yaml << EOF
plugin_id: demo_analyzer
name: Demo Analyzer
version: 1.0.0
description: Custom analysis plugin
author: VANTABLACK Team
type: analysis
main_file: main.py
hooks:
  - analysis.before_run
EOF

# main.py
cat > main.py << EOF
from plugins import PluginBase, hook

class DemoAnalyzer(PluginBase):
    @hook("analysis.before_run")
    async def analyze_before_run(self, target_data):
        self.logger.info("Custom analysis running...")
        return enhanced_data
EOF
```

**Script:**
"Le système de plugins permet une extensibilité infinie avec sandboxing sécurisé."

## Questions et Réponses Préparées

### Q1: Comment VANTABLACK garantit-il la légalité?
**R:** VANTABLACK est conçu exclusivement pour les tests d'autorisation (pentesting) avec consentement explicite. Toutes les fonctionnalités incluent des garde-fous légaux et des logs d'audit complets.

### Q2: Quelle est la différence avec les outils commerciaux?
**R:** Fonctionnalités équivalentes ou supérieures à 10% du coût, avec 100x plus de flexibilité grâce au système de plugins et à l'open source.

### Q3: Comment le machine learning est-il utilisé?
**R:** ML pour prédiction de conversion, segmentation comportementale, optimisation de templates, et détection d'anomalies en temps réel.

### Q4: Quelles sont les exigences techniques?
**R:** Python 3.9+, Docker, 4GB RAM minimum. Supporte Linux, macOS, Windows via Docker.

### Q5: Comment contribuer au projet?
**R:** GitHub open source, documentation complète, community guidelines, et programme de bounty pour contributions.

## Backup Plan

### Si l'API ne démarre pas:
```bash
# Vérifier les ports
netstat -tlnp | grep :8000

# Redémarrer avec debug
python api/rest_api.py --debug --host 0.0.0.0 --port 8000
```

### Si le frontend ne compile pas:
```bash
# Nettoyer et réinstaller
cd web/frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### Si Docker a des problèmes:
```bash
# Recréer containers
docker-compose -f docker-compose-v4.yml down
docker-compose -f docker-compose-v4.yml up --build
```

## Conclusion (1 minute)

**Script de fin:**
"VANTABLACK v4.0 transforme la manière dont les équipes Red Team opèrent. En combinant IA, interface moderne, et extensibilité complète, nous avons créé une plateforme qui non seulement égale mais dépasse les outils commerciaux existants."

**Points finaux:**
- 🚀 Performance 10x supérieure
- 🧠 IA et machine learning intégrés  
- 🔧 Extensibilité infinie
- 📊 Analytics temps réel
- 🛡️ Sécurité enterprise-grade
- 💰 Open source et gratuit

"Merci pour votre attention. Des questions?"

## Matériel de Support

### Slides de présentation
- Architecture technique
- Comparatifs avec concurrents
- Cas d'usage réels
- Roadmap futur

### Documentation
- API docs: http://localhost:8000/docs
- Guide utilisateur
- Guide développeur
- Tutoriels vidéo

### Contact
- GitHub: https://github.com/username/vantablack
- Email: vantablack@example.com
- Discord: https://discord.gg/vantablack
- Twitter: @VantablackSec
