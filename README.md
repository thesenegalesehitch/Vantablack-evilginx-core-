# 🚀 VANTABLACK v4.0 - GOD MODE EDITION

<p align="center">
  <img src="https://img.shields.io/badge/Version-4.0.0--GOD_MODE-red" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT--Industrial-black" alt="License">
  <img src="https://img.shields.io/badge/Security-Red--Team--Ready-red" alt="Security">
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python">
  <img src="https://img.shields.io/badge/Docker-Ready-blue" alt="Docker">
</p>

---

## 📋 Table of Contents

- [Overview](#overview)
- [New in v4.0](#-new-in-v40)
- [Quick Start](#-quick-start)
- [The War Room](#-the-war-room)
- [Social Network Phishing](#-social-network-phishing)
- [Ghost Protocol](#-ghost-protocol)
- [Quishing (QR Codes)](#-quishing)
- [Installation](#-installation)
- [Disclaimer](#-disclaimer)

---

## 🎯 Overview

**VANTABLACK** is an elite, ultra-resilient orchestration platform designed for Red Team professionals. It manages high-performance interception engines through a centralized, cloaked nervous system.

Version 4.0 introduces **GOD MODE**, a suite of advanced features designed for maximum impact and total control.

### What is VANTABLACK?

VANTABLACK is a command-and-control framework that simplifies the deployment and management of phishing campaigns. It provides:

- 🔒 **Secure Credential Capture** via Custom Proxy Engine
- 🌐 **Social Network Integration** (Twitter/X, Facebook, LinkedIn)
- 📊 **War Room Dashboard** for Real-time Ops
- 👻 **Ghost Protocol** for Emergency Evasion
- 📱 **Quishing** (QR Code Phishing) Generator
- 🛡️ **Advanced Evasion Techniques** for sandbox detection
- 🐳 **Containerized Deployment** with Docker

---

## ✨ New in v4.0

### 👑 God Mode
Unrestricted access to all modules, bypassing standard safety checks for authorized red team operations.

### 🏢 The War Room
A Hollywood-style, real-time tactical dashboard. Monitor live captures, map victims geographically, and control campaigns from a single pane of glass.

### 🕵️ Social Network Phishlets
Native support for modern social media platforms using the new **VantaProxy** engine.
- **Twitter / X** (2FA Support)
- **LinkedIn** (Session Capture)
- **Facebook** (Mobile & Desktop)

### 👻 Ghost Protocol

---

## ☁️ Dynamic Infrastructure (Optional Setup)

VANTABLACK can manage its own attack infrastructure using Terraform. This allows for the automated deployment and destruction of servers, making your campaigns highly resilient and difficult to trace.

**Setup:**
1. **Install Terraform**: Follow the official instructions at [terraform.io](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli).
2. **Configure Cloud Credentials**: Set up credentials for your chosen cloud provider. For example, for DigitalOcean:
   ```bash
   export DIGITALOCEAN_TOKEN="your_do_api_token"
   ```
   VANTABLACK will automatically use these environment variables.

---

Emergency panic button. Instantly wipes logs, kills processes, and sanitizes the environment if compromise is detected.

### 📱 Quishing Generator
Generate high-fidelity QR codes pointing to your campaigns, bypassing email filters.

---

## 🚀 Quick Start

### 1. Setup
```bash
# Clone the repository
git clone https://github.com/thesenegalesehitch/VANTABLACK.git
cd VANTABLACK

# Install dependencies
python3 vanta.py --setup
```

### 2. Launch War Room (Dashboard)
```bash
python3 vanta.py --war-room
```

### 3. Start Social Phishing Proxy
```bash
# Start Twitter/X Phishlet
python3 vanta.py --proxy phishlets/twitter.yaml
```

### 4. Generate QR Code
```bash
python3 vanta.py --quishing https://your-phishing-domain.com
```

### 5. Emergency Wipe (Ghost Protocol)
```bash
python3 vanta.py --ghost
```

---

## 🖥 The War Room

The **War Room** is the heart of VANTABLACK v4.0. It provides:
- **Live Feed**: Watch credentials roll in real-time.
- **World Map**: Geolocation of all connections.
- **System Status**: CPU/RAM/Network monitoring.
- **Kill Switch**: Instant access to Ghost Protocol.

Access it at: `http://localhost:8000/war-room` (or launch via `python3 vanta.py --war-room`)

---

## 🌐 Social Network Phishing

VANTABLACK v4.0 includes a custom **VantaProxy** engine designed specifically for modern dynamic web apps.

**Supported Phishlets:**
- `phishlets/twitter.yaml`
- `phishlets/linkedin.yaml` (Coming Soon)
- `phishlets/facebook.yaml` (Coming Soon)

**How it works:**
1. The proxy intercepts traffic between the victim and the target (e.g., X.com).
2. It rewrites links to keep the victim on your domain.
3. It captures credentials and session tokens (cookies) in real-time.
4. Data is sent to the War Room.

---

## 👻 Ghost Protocol

**"Burn it down."**

When triggered, Ghost Protocol will:
1. Kill all Vantablack processes (API, Proxy, Frontend).
2. Securely wipe local logs and capture files.
3. Reset network configurations.
4. Leave no trace.

**Usage:**
```bash
python3 vanta.py --ghost
```

---

## 📱 Quishing

QR Code Phishing (Quishing) is the new frontier. Vantablack generates high-res QR codes that:
- Link to your campaign.
- Can be embedded in emails or printed.
- Bypass traditional email security gateways.

**Usage:**
```bash
python3 vanta.py --quishing <URL>
```

---

---

## 🧠 AI-Powered Spear Phishing (Optional Setup)

VANTABLACK can leverage a local Large Language Model (LLM) to generate hyper-personalized spear phishing emails. This is powered by [Ollama](https://ollama.ai/).

**Setup:**
1. Install Ollama on your system: `curl -fsSL https://ollama.com/install.sh | sh`
2. Pull a model. We recommend a fast and creative model like `llama3` or `mistral`.
   ```bash
   ollama pull llama3
   ```
3. Ensure the Ollama server is running. VANTABLACK will connect to it automatically.

---

## ⚡ Performance Profiling

VANTABLACK includes a built-in performance profiling middleware that logs the processing time for every API request. This provides real-time insights into the performance of each endpoint.

**How it works:**
- A FastAPI middleware automatically intercepts all incoming requests.
- It calculates the total processing time in milliseconds.
- The result is logged to the console with the `[PROFILE]` tag, e.g., `[PROFILE] Request GET /system/status completed in 5.43ms`.

This allows for easy identification of slow endpoints and performance bottlenecks.

---

## ⚠️ Disclaimer

**VANTABLACK is for educational and authorized testing purposes only.**
Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

<p align="center">
  <b>Developed with ❤️ by TheSenegaleseHitch</b>
</p>
