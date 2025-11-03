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
- **Health Diagnostic**: `check_status.py` script to validate the black-site infrastructure.
- **Terminal Dashboard**: `monitor_captures.py` script for live capture viewing.
- **Forensic Fingerprinting**: Detailed technical reports on attack signatures.

## 📂 Project Structure
- `vanta/`: The internal nervous system (Core modules & Sub-systems).
- `engines/`: The primary Go-based interception engines.
- `bin/`: Hardened, optimized binary distributions.
- `vanta.py`: The universal Command-Line entry point.
- `vanta_legacy.py`: Legacy standalone Control Center.

## 🛡️ Ethical Governance
The use of this tool is strictly governed by the [LICENSE](LICENSE). Any usage outside of a legal and contractual Red Teaming framework is strictly prohibited.

## 📦 Quick Start
1. Configure your clandestine tokens in `hitch_config.yaml`.
2. Launch the black-site infrastructure:
    ```bash
    docker-compose up -d --build
    ```
3. Monitor operations in real-time:
    ```bash
    python3 monitor_captures.py
    ```

---
**VANTABLACK: Through the Looking Glass of Security.**
