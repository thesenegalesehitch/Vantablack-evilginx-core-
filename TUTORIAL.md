# 📚 VANTABLACK Complete Tutorial
## From Zero to Hero - Complete Guide for Beginners

---

# Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Creating Your First Campaign](#creating-your-first-campaign)
6. [Launching Campaigns](#launching-campaigns)
7. [Monitoring & Analysis](#monitoring--analysis)
8. [Advanced Techniques](#advanced-techniques)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

---

# 1. Introduction

## What is VANTABLACK?

VANTABLACK is an **advanced phishing orchestration platform** designed for Red Team professionals. It combines:

- 🔴 **Evilginx** - Advanced phishing proxy for credential harvesting
- 📧 **GoPhish** - Email campaign management
- 🤖 **Automated Exfiltration** - Real-time notifications
- 🛡️ **Advanced Evasion** - Sandbox and detection avoidance
- 📊 **Real-time Dashboard** - Live monitoring

## Who is this for?

This tutorial is designed for:
- 🔴 **Red Teamers** - Security professionals conducting authorized assessments
- 🛡️ **Penetration Testers** - Testing organizational defenses
- 📚 **Security Students** - Learning about phishing attacks
- 🎓 **Researchers** - Studying attack techniques

> ⚠️ **IMPORTANT**: This tool is for **authorized security testing only**. Unauthorized use is illegal.

---

# 2. Prerequisites

## System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| OS | Ubuntu 20.04+ / macOS 12+ | Ubuntu 22.04+ |
| RAM | 4 GB | 8 GB |
| CPU | 2 cores | 4+ cores |
| Disk | 20 GB | 50 GB |
| Python | 3.9+ | 3.11+ |

## Required Software

### Install Python
```bash
# Check if Python is installed
python3 --version

# If not installed (Ubuntu/Debian)
sudo apt update
sudo apt install python3 python3-pip

# macOS
brew install python3
```

### Install Docker
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# macOS
# Download Docker Desktop from https://docker.com
```

### Install Git
```bash
# Ubuntu/Debian
sudo apt install git

# macOS (already installed)
```

---

# 3. Installation

## Step 1: Clone the Repository

```bash
git clone https://github.com/thesenegalesehitch/VANTABLACK.git
cd VANTABLACK
```

## Step 2: Install Dependencies

```bash
# Using pip
pip3 install -r requirements.txt

# Using uv (faster)
pip3 install uv
uv pip install -r requirements.txt
```

## Step 3: Verify Installation

```bash
python3 vanta.py --check-deps
```

Expected output:
```
✓ Python 3.x detected
✓ Rich library installed
✓ PyYAML installed
✓ All dependencies satisfied
```

---

# 4. Configuration

## Quick Setup (Recommended)

The easiest way to configure VANTABLACK is using the interactive wizard:

```bash
python3 vanta.py --setup
```

This will guide you through:
1. Telegram bot setup
2. Discord webhook setup
3. Stealth level selection
4. Proxy configuration

## Manual Configuration

### Edit hitch_config.yaml

```bash
cp hitch_config.yaml.example hitch_config.yaml
nano hitch_config.yaml
```

### Configuration Options

#### Telegram Notifications
```yaml
telegram:
  enabled: true
  token: "YOUR_BOT_TOKEN"    # Get from @BotFather
  chat_id: "YOUR_CHAT_ID"    # Get from @userinfobot
```

#### Discord Notifications
```yaml
discord:
  enabled: true
  webhook_url: "YOUR_WEBHOOK_URL"
```

#### Stealth Levels
```yaml
evasion:
  stealth_level: 1  # 1=Minimal, 3=Medium, 5=Maximum
  
  # Advanced evasion options
  sandbox_detect: true
  vm_detect: true
  automation_check: true
```

---

# 5. Creating Your First Campaign

## Using Campaign Templates

VANTABLACK comes with **36 pre-built campaign templates**!

### Step 1: Browse Templates

```bash
python3 campaign_templates.py --list
```

You'll see templates organized by category:
- 📱 Social Media
- 💼 Productivity & Work
- 🏦 Banking & Finance
- 🛒 Shopping
- 📺 Streaming
- 🎮 Gaming
- ☁️ Cloud Storage
- 📧 Email Services
- 💰 Cryptocurrency

### Step 2: View Template Details

```bash
# View Facebook template
python3 campaign_templates.py --show 1

# View Microsoft 365 template  
python3 campaign_templates.py --show 6
```

Each template includes:
- Complete email template
- Landing page suggestions
- Best practices
- Success rate estimation

### Step 3: Generate Campaign Files

```bash
# Generate files for template #1 (Facebook)
python3 campaign_templates.py --generate 1
```

This creates a campaign folder with:
- `email_template.txt` - Ready-to-use email
- `campaign_config.yaml` - Configuration file
- `PLANNING_NOTES.md` - Complete planning guide
- `QUICKSTART.sh` - Quick start script

---

# 6. Launching Campaigns

## Method 1: Interactive Menu (Recommended)

```bash
python3 vanta.py
```

You'll see a beautiful menu:
```
╔══════════════════════════════════════════════════════════╗
║           VANTABLACK v3.1 - MAIN MENU                   ║
╠══════════════════════════════════════════════════════════╣
║  [1] 🚀  Start Campaign                                 ║
║  [2] 📊  View Dashboard                                  ║
║  [3] 🔍  Check Status                                   ║
║  [4] 📁  Manage Captures                                ║
║  [5] ⚙️  Configuration                                 ║
║  [6] 🐳  Docker Control                                 ║
║  [7] 📖  Help                                           ║
║  [0] ❌  Exit                                           ║
╚══════════════════════════════════════════════════════════╝
```

Press `1` to start a campaign!

## Method 2: Command Line

```bash
# Basic start
python3 vanta.py --start

# With stealth mode
python3 vanta.py --start --stealth-level 3

# With notifications
python3 vanta.py --start --notify telegram

# Full options
python3 vanta.py --start --stealth-level 4 --notify telegram --auto-kill
```

## Method 3: Docker

```bash
# Start everything
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

# 7. Monitoring & Analysis

## Real-time Dashboard

```bash
python3 monitor_captures.py
```

This shows:
- Live credential captures
- Timestamp
- Source (which phishlet)
- Captured data

## System Status

```bash
python3 check_status.py
```

Shows:
- Docker status
- Database health
- API server status
- Notification channels

## Managing Captures

From the main menu, option `4` lets you:
- View all captures
- Export to JSON
- Export to CSV
- Delete captures

---

# 8. Advanced Techniques

## Stealth Levels Explained

| Level | Name | Features |
|-------|------|----------|
| 1 | Testing | No evasion, for testing only |
| 2 | Basic | Basic User-Agent rotation |
| 3 | Medium | Recommended - sandbox detection |
| 4 | High | VM detection + advanced evasion |
| 5 | Paranoid | Maximum evasion, may break some sites |

## Proxy Rotation

1. Create a proxy list file:
```bash
nano proxies.txt
```

2. Add proxies (one per line):
```
socks5://user:pass@proxy1.com:1080
socks5://proxy2.com:1080
http://proxy3.com:8080
```

3. Run with proxy:
```bash
python3 vanta.py --proxy-list proxies.txt
```

## Custom Phishlets

Place custom phishlets in:
```
./phishlets/
```

## Multi-target Campaigns

```bash
python3 vanta.py --multi-tenant
```

This allows running multiple campaigns simultaneously.

---

# 9. Troubleshooting

## Common Issues

### "Database locked"
```bash
chmod 755 data/
chmod 644 hitch_vault.db
```

### "Port already in use"
```bash
# Find what's using the port
lsof -i :8000

# Kill it
kill -9 <PID>
```

### "Telegram not working"
1. Verify token: @BotFather
2. Get chat ID: @userinfobot
3. Test with: curl https://api.telegram.org/bot<TOKEN>/getUpdates

### "Docker not running"
```bash
sudo systemctl start docker
sudo docker ps
```

### "Binary not found"
```bash
# Make binaries executable
chmod +x bin/evilginx
chmod +x bin/gophish
```

---

# 10. Best Practices

## Pre-Engagement

- [ ] Get **written authorization** from client
- [ ] Define **scope** clearly
- [ ] Set **rules of engagement**
- [ ] Prepare **communication plan**

## During Campaign

- [ ] Monitor in real-time
- [ ] Document everything
- [ ] Stay within scope
- [ ] Don't over-persist

## Post-Engagement

- [ ] Clean up all artifacts
- [ ] Delete test data
- [ ] Provide detailed report
- [ ] Recommend improvements

## Legal & Ethical

✅ **ALWAYS**:
- Get authorization
- Document scope
- Report findings properly
- Clean up after

❌ **NEVER**:
- Attack without permission
- Exceed scope
- Keep sensitive data
- Use for illegal purposes

---

# Quick Reference

## Commands

| Command | Description |
|---------|-------------|
| `python3 vanta.py` | Launch interactive menu |
| `python3 vanta.py --setup` | Setup wizard |
| `python3 vanta.py --start` | Start directly |
| `python3 monitor_captures.py` | Live dashboard |
| `python3 check_status.py` | System status |
| `python3 campaign_templates.py` | Browse templates |

## File Locations

| File | Purpose |
|------|---------|
| `hitch_config.yaml` | Main configuration |
| `hitch_vault.db` | Captured credentials |
| `vanta.log` | Application logs |
| `campaigns/` | Generated campaigns |

## Support

- 📖 [Wiki](https://github.com/thesenegalesehitch/VANTABLACK/wiki)
- 🐛 [Issues](https://github.com/thesenegalesehitch/VANTABLACK/issues)
- 💬 [Discussions](https://github.com/thesenegalesehitch/VANTABLACK/discussions)

---

**VANTABLACK v3.1** - Built for Red Teams by Red Teams

*Remember: With great power comes great responsibility. Use ethically.*
