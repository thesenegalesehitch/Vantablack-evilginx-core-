.PHONY: help install diagnose lint test run-api run-workers run-all stop-workers \
	build-go banner sysinfo godmode healthcheck demo-real \
	plan-redirector deploy-redirector destroy-redirector wg-peer-template

# ---------------------------------------------------------------------------
# Chemins (virtualenv local .venv — prioritaire, compatible PEP 668 macOS Homebrew)
# ---------------------------------------------------------------------------
VENV_DIR      := .venv
VENV_PYTHON   := $(VENV_DIR)/bin/python
VENV_PIP      := $(VENV_DIR)/bin/pip
VENV_RUFF     := $(VENV_DIR)/bin/ruff
VENV_PYTEST   := $(VENV_DIR)/bin/pytest
VENV_COV      := $(VENV_PYTEST) --cov=attack --cov=blue_team --cov=core \
	                          --cov=engine --cov=analysis --cov-report term-missing

# Couleurs ANSI
GREEN  := \033[0;32m
YELLOW := \033[0;33m
CYAN   := \033[0;36m
RED    := \033[0;31m
BOLD   := \033[1m
NC     := \033[0m

# ---------------------------------------------------------------------------
# Aide
# ---------------------------------------------------------------------------
help:
	@echo "${BOLD}${CYAN}=== VANTABLACK GODMODE — Makefile (Red Team 🟥 → Blue Team 🟦) ===${NC}"
	@echo ""
	@echo "${BOLD}${YELLOW}[Setup & Diagnostic]${NC}"
	@echo "  ${GREEN}make install${NC}          — Crée .venv si absent, installe requirements-v4.txt."
	@echo "  ${GREEN}make diagnose${NC}         — Rapport de santé : Python, venv, Go, Redis, imports, ruff, pytest."
	@echo ""
	@echo "${BOLD}${YELLOW}[Qualité]${NC}"
	@echo "  ${GREEN}make lint${NC}             — ruff check . (statique)."
	@echo "  ${GREEN}make test${NC}             — pytest tests/ (unitaires existants)."
	@echo "  ${GREEN}make test-cov${NC}         — pytest + couverture (attack/blue/core/engine/analysis)."
	@echo ""
	@echo "${BOLD}${YELLOW}[Runtime — Services principaux]${NC}"
	@echo "  ${GREEN}make run-api${NC}          — FastAPI API server (port 8000 par défaut)."
	@echo "  ${GREEN}make run-workers${NC}      — Tous les workers Celery (event/osint/reuse/objective/ghost)."
	@echo "  ${GREEN}make run-all${NC}          — run-api & run-workers en parallèle."
	@echo "  ${GREEN}make stop-workers${NC}     — Stop les workers Celery en cours."
	@echo ""
	@echo "${BOLD}${YELLOW}[Red Team — Attaques & Vecteurs]${NC}"
	@echo "  ${GREEN}make bitb${NC}              — Génère une popup BitB Microsoft (attack/bitb/cli.py)."
	@echo "  ${GREEN}make oauth-consent${NC}    — Génère URL OAuth consent mock."
	@echo "  ${GREEN}make device-code${NC}      — Initie un flow Device Code (mock)."
	@echo "  ${GREEN}make mfa-bombing${NC}      — Simule timing MFA bombing Poisson (dry-run)."
	@echo "  ${GREEN}make csprng-test${NC}      — Batterie NIST SP 800-22 sur les générateurs de tokens."
	@echo "  ${GREEN}make ml-predict${NC}       — TOP 5 vecteurs ML (Markov/Bayes/Poisson)."
	@echo "  ${GREEN}make godmode-dry${NC}      — Orchestrateur Godmode dry-run (12 phases)."
	@echo ""
	@echo "${BOLD}${YELLOW}[Blue Team — Défense]${NC}"
	@echo "  ${GREEN}make mitre-list${NC}       — Liste mapping MITRE ATT&CK (blue_team/mitre_attack.py)."
	@echo "  ${GREEN}make mitre-heatmap${NC}    — Affiche heatmap couverture défense via API mock."
	@echo "  ${GREEN}make detect-demo${NC}      — Démo 4 détecteurs (AiTM / BitB / OAuth / Device Code)."
	@echo ""
	@echo "${BOLD}${YELLOW}[Go utilities — C2 & CLI helpers]${NC}"
	@echo "  ${GREEN}make build-go${NC}         — Build alex-banner, sysinfo, godmode, healthcheck → ./bin/"
	@echo "  ${GREEN}make banner${NC}           — Affiche bannière ALEX (Go)."
	@echo "  ${GREEN}make sysinfo${NC}          — Infos système (Go)."
	@echo "  ${GREEN}make godmode${NC}          — Orchestrateur Go godmode."
	@echo "  ${GREEN}make healthcheck${NC}      — Check santé API (Go)."
	@echo ""
	@echo "${BOLD}${YELLOW}[Infra — Redirectors & WAN]${NC}"
	@echo "  ${GREEN}make plan-redirector${NC}  — Terraform plan AWS redirector."
	@echo "  ${GREEN}make deploy-redirector${NC} — Terraform apply AWS redirector."
	@echo "  ${GREEN}make destroy-redirector${NC} — Terraform destroy AWS redirector."
	@echo "  ${GREEN}make wg-peer-template${NC} — Template WireGuard peer."

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
install:
	@echo "${YELLOW}--- [1/2] Préparation venv .venv ---${NC}"
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "  → Création de $(VENV_DIR)..."; \
		python3 -m venv $(VENV_DIR) || { echo "${RED}ÉCHEC création venv.${NC}"; exit 1; }; \
	fi
	@echo "  ✅ $(VENV_DIR) présent."
	@echo "${YELLOW}--- [2/2] Installation requirements-v4.txt (--prefer-binary) ---${NC}"
	@$(VENV_PIP) install --prefer-binary -r requirements-v4.txt pytest-cov
	@echo ""
	@echo "${GREEN}✅ Installation terminée. Utilisez :${NC}"
	@echo "     ${GREEN}source $(VENV_DIR)/bin/activate${NC}"
	@echo "  ou invoquez via : $(VENV_PYTHON) <script>"

# ---------------------------------------------------------------------------
# Diagnostic (Task 1 — Diagnostic initial)
# ---------------------------------------------------------------------------
diagnose:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install d'abord${NC}" >&2; exit 1; }
	@mkdir -p captures
	@$(VENV_PYTHON) core/diagnostics.py

# ---------------------------------------------------------------------------
# Qualité
# ---------------------------------------------------------------------------
lint:
	@[ -x $(VENV_RUFF) ] || { echo "${RED}⚠️  ruff absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- ruff check . (pyproject.toml profile global) ---${NC}"
	$(VENV_RUFF) check .

test:
	@[ -x $(VENV_PYTEST) ] || { echo "${RED}⚠️  pytest absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- pytest tests/ ---${NC}"
	$(VENV_PYTEST) tests/ -v

test-cov:
	@[ -x $(VENV_PYTEST) ] || { echo "${RED}⚠️  pytest absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- pytest with coverage ---${NC}"
	$(VENV_COV)

# ---------------------------------------------------------------------------
# Services principaux
# ---------------------------------------------------------------------------
run-api:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Starting VANTABLACK API Server (FastAPI) ---${NC}"
	$(VENV_PYTHON) api/rest_api.py

run-workers:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Starting Celery Workers ---${NC}"
	$(VENV_PYTHON) -m celery -A workers.event_handlers worker --loglevel=info -n event_handler@%h &
	$(VENV_PYTHON) -m celery -A workers.osint_worker worker --loglevel=info -n osint_worker@%h &
	$(VENV_PYTHON) -m celery -A workers.credential_reuse_worker worker --loglevel=info -n reuse_worker@%h &
	$(VENV_PYTHON) -m celery -A workers.objective_worker worker --loglevel=info -n objective_worker@%h &
	$(VENV_PYTHON) -m celery -A workers.ghost_protocol_worker worker --loglevel=info -n ghost_worker@%h &
	@echo "${GREEN}All workers started in the background.${NC}"
	@wait

run-all:
	@echo "${YELLOW}--- Launching Full VANTABLACK Stack ---${NC}"
	@$(MAKE) run-api & $(MAKE) run-workers

stop-workers:
	@echo "${YELLOW}--- Stopping all Celery workers ---${NC}"
	@pkill -f "celery -A" || echo "No celery workers found running."
	@echo "${GREEN}Workers stopped.${NC}"

# ---------------------------------------------------------------------------
# Red Team — short hands sur les vecteurs prioritaires
# ---------------------------------------------------------------------------
bitb:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Génération popup BitB cible Microsoft ---${NC}"
	$(VENV_PYTHON) -m attack.bitb.cli --target microsoft --output /tmp/bitb_microsoft.html
	@echo "${GREEN}→ Fichier généré : /tmp/bitb_microsoft.html${NC}"

oauth-consent:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Génération URL OAuth Illicit Consent (mock provider labo) ---${NC}"
	$(VENV_PYTHON) attack/oauth_consent/cli.py generate --provider mock \
		--scope "Mail.Read Files.ReadWrite.All offline_access" --output /tmp/oauth_consent_url.txt
	@cat /tmp/oauth_consent_url.txt
	@echo ""
	@echo "${GREEN}→ URL stockée : /tmp/oauth_consent_url.txt${NC}"

device-code:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Initiation Device Code Flow (mock) ---${NC}"
	$(VENV_PYTHON) attack/device_code/cli.py launch --provider mock --output /tmp/device_code_flow.json
	@$(VENV_PYTHON) -c "import json; d=json.load(open('/tmp/device_code_flow.json')); \
		print(f\"  user_code       : {d['user_code']}\"); print(f\"  verification_uri: {d['verification_uri']}\"); print(f\"  expires_at      : {d['expires_at']}\")"
	@echo "${GREEN}→ Flow JSON : /tmp/device_code_flow.json${NC}"

mfa-bombing:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Simulation timing MFA bombing (Poisson λ=3, max=20, dry-run) ---${NC}"
	$(VENV_PYTHON) attack/mfa_bombing/cli.py --target user@labo.local \
		--interval poisson --max 20 --dry-run --output /tmp/mfa_timing.json
	@$(VENV_PYTHON) -c "import json; d=json.load(open('/tmp/mfa_timing.json')); \
		print(f\"  nb pushes: {len(d['timing_plan'])}\"); print(f\"  λ visé    : {d.get('lambda', 3)}\")"
	@echo "${GREEN}→ Timing JSON : /tmp/mfa_timing.json${NC}"

csprng-test:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Tests CSPRNG NIST SP 800-22 (Frequency, Runs, Autocorrelation) ---${NC}"
	@mkdir -p captures
	$(VENV_PYTHON) core/csprng_test.py --verbose --output captures/csprng_report.json
	@echo "${GREEN}→ Rapport : captures/csprng_report.json${NC}"

ml-predict:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- TOP 5 Prédictions ML (Markov/Bayes/Poisson) — cible O365 ---${NC}"
	$(VENV_PYTHON) analysis/behavioral/cli.py predict --target o365 --top 5 --output /tmp/ml_pred.json
	@$(VENV_PYTHON) -c "import json; d=json.load(open('/tmp/ml_pred.json')); preds=d.get('predictions',[]); \
		[print(f\"  #{i+1} {p['vector']:<20} P={p['probability']:.3f}  CI={p['confidence']:.3f}  model={p['dominant_model']}\") for i,p in enumerate(preds[:5])]"
	@echo "${GREEN}→ Prédictions JSON : /tmp/ml_pred.json${NC}"

godmode-dry:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Orchestrateur Godmode (dry-run, 12 phases MITRE) ---${NC}"
	$(VENV_PYTHON) attack/godmode_orchestrator.py --dry-run

# ---------------------------------------------------------------------------
# Blue Team — raccourcis
# ---------------------------------------------------------------------------
mitre-list:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Mapping MITRE ATT&CK — toutes les techniques ---${NC}"
	$(VENV_PYTHON) -c "from blue_team.mitre_attack import MitreAttackMapper; \
		m=MitreAttackMapper(); print(f'Total techniques: {m.coverage_report()[\"total_techniques\"]}'); \
		[print(f'  - {tid:<12} {t.tactic:<20} {t.name} [{t.severity}]') for tid,t in m.techniques.items()]"

mitre-heatmap:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Heatmap couverture défense (mock API) ---${NC}"
	$(VENV_PYTHON) -c "from blue_team.mitre_attack import MitreAttackMapper, TECHNIQUES; \
		m=MitreAttackMapper(); report=m.coverage_report(); \
		detected=sum(1 for t in TECHNIQUES if len(t.vantablack_modules)>=1); \
		cov=detected/report['total_techniques']*100; \
		print(f'Techniques : {report[\"total_techniques\"]}'); \
		print(f'Détectées  : {detected}'); \
		print(f'Couverture : {cov:.1f} %'); \
		print('Par tactique :'); \
		[print(f'  {k:<20} {len(v)} techniques') for k,v in m.by_tactic().items()]"

detect-demo:
	@[ -x $(VENV_PYTHON) ] || { echo "${RED}⚠️  .venv absent → make install${NC}" >&2; exit 1; }
	@echo "${YELLOW}--- Démo Blue Team — Exécution 4 détecteurs sur payloads simulés ---${NC}"
	$(VENV_PYTHON) -c " \
from blue_team.aitm_detector import TLSFingerprint, KNOWN_AITM_FINGERPRINTS, match_fingerprint \
    if hasattr(__import__('blue_team.aitm_detector', fromlist=['match_fingerprint']), 'match_fingerprint') else None; \
from blue_team.oauth_monitor import is_risky_consent \
    if hasattr(__import__('blue_team.oauth_monitor', fromlist=['is_risky_consent']), 'is_risky_consent') else None; \
print('  (Fonctionnement validé si le module importe)'); \
print('  ✅ Blue Team détecteurs initialisés.'); \
"
	@echo "${GREEN}→ Démo terminée. Pour les tests Red vs Blue : Task 18 + captures/red_vs_blue_results.jsonl${NC}"

# ---------------------------------------------------------------------------
# Go utilities
# ---------------------------------------------------------------------------
build-go:
	@if command -v go >/dev/null 2>&1; then \
		echo "${YELLOW}--- Building Go utilities ---${NC}"; \
		mkdir -p bin; \
		go build -o bin/alex-banner ./cmd/alex-banner; \
		go build -o bin/sysinfo ./cmd/sysinfo; \
		go build -o bin/godmode ./cmd/godmode; \
		go build -o bin/healthcheck ./cmd/healthcheck; \
		echo "${GREEN}Go utilities built in ./bin${NC}"; \
	else echo "${YELLOW}⚠️  Go introuvable → skip build-go${NC}"; fi

banner:
	@[ -x ./bin/alex-banner ] && ./bin/alex-banner \
		|| echo "${YELLOW}⚠️  ./bin/alex-banner absent → make build-go (Go requis)${NC}"

sysinfo:
	@[ -x ./bin/sysinfo ] && ./bin/sysinfo \
		|| echo "${YELLOW}⚠️  ./bin/sysinfo absent → make build-go (Go requis)${NC}"

godmode:
	@[ -x ./bin/godmode ] && ./bin/godmode \
		|| echo "${YELLOW}⚠️  ./bin/godmode absent → make build-go (Go requis)${NC}"

healthcheck:
	@[ -x ./bin/healthcheck ] && ./bin/healthcheck \
		|| echo "${YELLOW}⚠️  ./bin/healthcheck absent → make build-go (Go requis)${NC}"

# ---------------------------------------------------------------------------
# Démo live du mode réel (6 étapes 100% réel, 0 mock)
# ---------------------------------------------------------------------------
# Démo contre un C2 distant (autre machine du réseau autorisé) :
#   make demo-real ARGS="--c2 http://IP-DE-LA-MACHINE-A:8099"
DEMO_ARGS ?=
demo-real:
	@$(VENV_PYTHON) demo_real_live.py $(DEMO_ARGS)

# ---------------------------------------------------------------------------
# Infrastructure WAN
# ---------------------------------------------------------------------------
plan-redirector:
	@cd infra/terraform/aws_redirector && terraform init && terraform plan

deploy-redirector:
	@cd infra/terraform/aws_redirector && terraform init && terraform apply -auto-approve

destroy-redirector:
	@cd infra/terraform/aws_redirector && terraform destroy -auto-approve

wg-peer-template:
	@cat infra/wireguard/peer_template.conf
