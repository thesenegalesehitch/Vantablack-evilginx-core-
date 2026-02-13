# 🚀 VANTABLACK Quick Start Guide

This guide will get you up and running with VANTABLACK in under 5 minutes.

---

## Prerequisites

Before you begin, ensure you have:

- [ ] Python 3.9 or higher
- [ ] Docker & Docker Compose
- [ ] Git

Check your versions:
```bash
python3 --version    # Should be 3.9+
docker --version     # Should be 20.10+
docker-compose --version  # Should be 2.0+
```

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/thesenegalesehitch/VANTABLACK.git
cd VANTABLACK
```

---

## Step 2: Install Dependencies

```bash
# Install Python packages
pip3 install -r requirements.txt

# Verify installation
python3 vanta.py --check-deps
```

Expected output:
```
✓ All dependencies satisfied
```

---

## Step 3: Quick Setup (Recommended)

Run the interactive setup wizard:

```bash
python3 vanta.py --setup
```

The wizard will guide you through:
1. Configuring Telegram notifications (optional)
2. Setting up Discord webhooks (optional)
3. Choosing your stealth level
4. Setting up proxy rotation (optional)

---

## Step 4: Start VANTABLACK

### Option A: Interactive Menu (Recommended)

```bash
python3 vanta.py
```

You'll see a beautiful menu. Press `1` to start a campaign, or explore other options.

### Option B: Direct Start

```bash
# Start with default settings
python3 vanta.py --start

# Start with custom settings
python3 vanta.py --start --stealth-level 3 --notify telegram
```

---

## Step 5: Monitor Captures

Open a new terminal:

```bash
# Real-time dashboard
python3 monitor_captures.py

# Check system status
python3 check_status.py
```

---

## 🔥 Common Commands

| Command | Description |
|---------|-------------|
| `python3 vanta.py` | Launch interactive menu |
| `python3 vanta.py --setup` | Run setup wizard |
| `python3 vanta.py --start` | Start directly |
| `python3 monitor_captures.py` | Live capture dashboard |
| `python3 check_status.py` | System diagnostics |
| `python3 campaign_templates.py --list` | View campaign templates |

---

## Docker Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

---

## ⚙️ Configuration

Edit `hitch_config.yaml` to customize:

```yaml
evasion:
  stealth_level: 3          # 1-5 (3 is recommended)

telegram:
  enabled: true
  token: "YOUR_TOKEN"
  chat_id: "YOUR_CHAT_ID"
```

---

## 🎯 Quick Campaign Launch

Want to launch a campaign fast?

```bash
# 1. List available templates
python3 campaign_templates.py --list

# 2. Generate campaign files
python3 campaign_templates.py --generate 1

# 3. Start VANTABLACK
python3 vanta.py
```

---

## 🔧 Troubleshooting

### "Database locked" error
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
- Verify bot token with @BotFather
- Get chat ID from @userinfobot

---

## 📚 Next Steps

- Read [README.md](README.md) for complete documentation
- Check out [MASTER_GUIDE.md](MASTER_GUIDE.md) for advanced usage
- Review [SECURITY.md](SECURITY.md) for ethical guidelines

---

**Need Help?**

- Check the wiki: [GitHub Wiki](https://github.com/thesenegalesehitch/VANTABLACK/wiki)
- Open an issue: [Issues](https://github.com/thesenegalesehitch/VANTABLACK/issues)

---

*VANTABLACK v3.1 - Built for Red Teams*
