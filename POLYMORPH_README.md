# VANTABLACK POLYMORPH (V3.0) - OPERATIONAL MANUAL

## 1. Modular Architecture
The tool has been restructured into a full Python package for maximum resilience.
- `vanta.py`: New universal entry point.
- `hitch_vault.db`: SQLite database (replaces volatile logs).

## 2. CLI Arguments (Command Line)
The orchestrator now accepts advanced parameters:

| Argument | Description | Values |
| :--- | :--- | :--- |
| `--stealth-level` | Sets the evasion aggressiveness. | 1 (Low) to 5 (Extreme) |
| `--proxy-list` | Path to a SOCKS5 proxy file. | e.g.: `./proxies.txt` |
| `--notify` | Channel for exfiltrations. | `telegram` or `discord` |
| `--auto-kill` | DB destruction if a threat is detected. | Active flag |
| `--multi-tenant` | Allows managing multiple isolated domains. | Active flag |

## 3. Resilience Supervisor
The `supervisor` module monitors in real-time:
- **CPU > 80%**: Automatic restart of the faulty engine.
- **RAM > 500MB**: Immediate kill to prevent server crash.

## 4. Evasion & Anti-Sandbox
The Turnstile redirector now verifies:
- **GPU**: Detects software rendering (VirtualBox/VMware).
- **Resolution**: Filters non-standard screen resolutions (bots).
- **Battery**: Verifies energy status consistency.

---
**USAGE:** `sudo python3 vanta.py --stealth-level 3 --auto-kill`
