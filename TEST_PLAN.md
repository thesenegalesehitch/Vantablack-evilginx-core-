# 🧪 Operational Test Plan: VANTABLACK

The tool is operational. Here is how to verify its core capabilities.

## Test 1: Total Orchestration
1. Launch `sudo python3 vanta.py --stealth-level 3`
2. Wait for the logs indicating both engines are deployed.
3. **Verification**: Open your browser at `https://127.0.0.1:3333`. If the Gophish page displays, orchestration is working.

## Test 2: Resilience & Self-Healing
1. While the system is running, open another terminal.
2. Kill the Gophish process: `pkill gophish`
3. Watch your first terminal: you will see the supervisor detect the crash and restart the engine.
4. A few seconds later, Gophish will be back online.

## Test 3: Infrastructure Audit
1. Run `python3 check_status.py` to perform a sanity check on the network and binary integrity.
2. Verify that all VANTABLACK sub-systems are reported as "ONLINE".

---

### 🎁 Operational Credentials
- **Gophish Admin**: `https://127.0.0.1:3333`
- **Initial Password**: `53460a35c8e93d9d`

> [!IMPORTANT]
> Change the default password immediately after the first login to maintain OPSEC.
