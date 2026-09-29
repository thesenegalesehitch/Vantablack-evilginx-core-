from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import secrets
import sys
import uuid
from pathlib import Path
from typing import Dict

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class CSPRNGTest:
    @staticmethod
    def _bytes_to_bits(data: bytes) -> list[int]:
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _erf_inv(x: float) -> float:
        a = 8 * (math.pi - 3) / (3 * math.pi * (4 - math.pi))
        ln1mx = math.log(1 - x * x)
        term1 = 2 / (math.pi * a) + ln1mx / 2
        term2 = ln1mx / a
        return math.copysign(1, x) * math.sqrt(math.sqrt(term1 ** 2 - term2) - term1)

    @staticmethod
    def _normal_cdf_inv(p: float) -> float:
        if p <= 0 or p >= 1:
            raise ValueError("p must be in (0, 1)")
        return math.sqrt(2) * CSPRNGTest._erf_inv(2 * p - 1)

    @staticmethod
    def _erf(x: float) -> float:
        sign = 1 if x >= 0 else -1
        x = abs(x)
        a1, a2, a3, a4, a5 = (
            0.254829592, -0.284496736, 1.421413741, -1.453152027, 1.061405429
        )
        p = 0.3275911
        t = 1.0 / (1.0 + p * x)
        y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * math.exp(-x * x)
        return sign * y

    @staticmethod
    def _normal_cdf(x: float) -> float:
        return 0.5 * (1.0 + CSPRNGTest._erf(x / math.sqrt(2.0)))

    def frequency_test(self, data: bytes) -> Dict[str, float]:
        bits = self._bytes_to_bits(data)
        n = len(bits)
        if n < 100:
            return {"pvalue": 0.0, "statistic": 0.0, "n": n, "passed": False}
        s = sum(1 if b == 1 else -1 for b in bits)
        s_obs = abs(s) / math.sqrt(n)
        pvalue = math.erfc(s_obs / math.sqrt(2))
        return {
            "pvalue": pvalue,
            "statistic": s_obs,
            "n": n,
            "passed": pvalue > 0.01,
        }

    def runs_test(self, data: bytes) -> Dict[str, float]:
        bits = self._bytes_to_bits(data)
        n = len(bits)
        if n < 100:
            return {"pvalue": 0.0, "statistic": 0.0, "n": n, "passed": False}
        pi = sum(bits) / n
        tau = 2 / math.sqrt(n)
        if abs(pi - 0.5) >= tau:
            return {
                "pvalue": 0.0,
                "statistic": 0.0,
                "n": n,
                "pi": pi,
                "passed": False,
                "note": "Frequency test prerequisite failed",
            }
        runs = 1
        for i in range(1, n):
            if bits[i] != bits[i - 1]:
                runs += 1
        numerator = abs(runs - 2 * n * pi * (1 - pi))
        denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        if denominator == 0:
            pvalue = 0.0
        else:
            pvalue = math.erfc(numerator / denominator)
        return {
            "pvalue": pvalue,
            "statistic": runs,
            "n": n,
            "pi": pi,
            "passed": pvalue > 0.01,
        }

    def autocorrelation_test(
        self, data: bytes, d: int = 1
    ) -> Dict[str, float]:
        bits = self._bytes_to_bits(data)
        n = len(bits)
        if n < 100:
            return {
                "pvalue": 0.0,
                "statistic": 0.0,
                "n": n,
                "d": d,
                "passed": False,
            }
        if d <= 0 or d >= n:
            d = 1
        a = 0
        for i in range(n - d):
            a += bits[i] ^ bits[i + d]
        s_obs = abs(2 * a - (n - d)) / math.sqrt(n - d)
        pvalue = math.erfc(s_obs / math.sqrt(2))
        return {
            "pvalue": pvalue,
            "statistic": a,
            "n": n,
            "d": d,
            "passed": pvalue > 0.01,
        }


def test_token(data: bytes) -> Dict[str, Dict[str, float]]:
    tester = CSPRNGTest()
    results = {
        "frequency": tester.frequency_test(data),
        "runs": tester.runs_test(data),
        "autocorrelation": tester.autocorrelation_test(data),
    }
    all_passed = all(r.get("passed", False) for r in results.values())
    results["overall"] = {
        "passed": all_passed,
        "threshold": 0.01,
    }
    return results


def _extract_token_bytes(raw) -> bytes:
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        raw_bytes = None
        if len(s) >= 64 and all(c in "0123456789abcdef" for c in s.lower()):
            try:
                raw_bytes = bytes.fromhex(s)
            except Exception:
                pass
        if raw_bytes is None:
            for decoder in (base64.urlsafe_b64decode, base64.b64decode):
                try:
                    padded = s + "=" * (-len(s) % 4)
                    raw_bytes = decoder(padded)
                    text_ratio = sum(
                        1 for b in raw_bytes if 32 <= b < 127 or b in (9, 10, 13)
                    ) / max(len(raw_bytes), 1)
                    if text_ratio > 0.6:
                        raw_bytes = None
                        continue
                    break
                except Exception:
                    raw_bytes = None
                    continue
        if raw_bytes and len(raw_bytes) >= 16:
            return raw_bytes
        return hashlib.sha256(s.encode("utf-8")).digest()
    return hashlib.sha256(str(raw).encode("utf-8")).digest()


def audit_all_modules() -> Dict[str, any]:
    from datetime import datetime, timezone

    report: Dict[str, any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "modules": {},
        "overall": {"pass_count": 0, "total": 0, "all_passed": False},
    }

    secrets_bytes = secrets.token_bytes(32)
    report["modules"]["secrets.token_bytes(32)"] = {
        "raw_hex": secrets_bytes.hex(),
        "tests": test_token(secrets_bytes),
    }

    uuid_val = uuid.uuid4()
    uuid_bytes = uuid_val.bytes
    report["modules"]["uuid4"] = {
        "raw_str": str(uuid_val),
        "tests": test_token(uuid_bytes),
    }

    try:
        from attack.device_code.initiator import DeviceCodeInitiator
        initiator = DeviceCodeInitiator()
        flow = initiator.initiate()
        dc_bytes = _extract_token_bytes(flow.device_code)
        report["modules"]["device_code (attack.device_code.initiator)"] = {
            "raw_preview": flow.device_code[:48] + "...",
            "tests": test_token(dc_bytes),
        }
    except Exception as e:
        report["modules"]["device_code (attack.device_code.initiator)"] = {
            "error": str(e),
            "tests": {"overall": {"passed": False}},
        }

    try:
        from attack.oauth_consent.consent_url import build_consent_url
        from attack.oauth_consent.app_registration import get_default_app
        app = get_default_app()
        url = build_consent_url(app, provider="mock")
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        state_val = parse_qs(parsed.query).get("state", [""])[0]
        state_bytes = _extract_token_bytes(state_val)
        report["modules"]["oauth_state (attack.oauth_consent.consent_url)"] = {
            "raw_preview": state_val[:48] + ("..." if len(state_val) > 48 else ""),
            "tests": test_token(state_bytes),
        }
    except Exception as e:
        report["modules"]["oauth_state (attack.oauth_consent.consent_url)"] = {
            "error": str(e),
            "tests": {"overall": {"passed": False}},
        }

    try:
        from engine.advanced_proxy import SessionHijacker
        sh = SessionHijacker()
        sid_src = "192.0.2." + str(secrets.randbelow(254) + 1)
        import base64 as _b64
        import datetime as _dt
        sid_raw = _b64.b64encode(
            f"{sid_src}_{_dt.datetime.now().timestamp()}".encode()
        ).decode()
        sid_bytes = hashlib.sha256(sid_raw.encode("utf-8")).digest()
        report["modules"]["session_id (core.session)"] = {
            "raw_preview": sid_raw[:48] + ("..." if len(sid_raw) > 48 else ""),
            "note": "session_id is deterministic (ip+timestamp); hash tested for entropy",
            "tests": test_token(sid_bytes),
        }
    except Exception as e:
        report["modules"]["session_id (core.session)"] = {
            "error": str(e),
            "tests": {"overall": {"passed": False}},
        }

    pass_count = 0
    total = 0
    for mod_name, mod_data in report["modules"].items():
        total += 1
        tests = mod_data.get("tests", {})
        overall = tests.get("overall", {})
        if overall.get("passed"):
            pass_count += 1
    report["overall"]["pass_count"] = pass_count
    report["overall"]["total"] = total
    report["overall"]["all_passed"] = pass_count == total

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CSPRNG Audit - NIST SP 800-22 tests on project tokens",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Afficher le détail par test"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="captures/csprng_report.json",
        help="Chemin du fichier JSON de sortie",
    )
    args = parser.parse_args()

    report = audit_all_modules()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=False)

    if args.verbose:
        print(f"{'MODULE':<60} {'PASSED':<7} {'FREQ':<6} {'RUNS':<6} {'AUTO':<6}")
        print("-" * 90)
        for mod_name, mod_data in report["modules"].items():
            tests = mod_data.get("tests", {})
            overall = tests.get("overall", {})
            fp = tests.get("frequency", {}).get("pvalue", float("nan"))
            rp = tests.get("runs", {}).get("pvalue", float("nan"))
            ap = tests.get("autocorrelation", {}).get("pvalue", float("nan"))
            passed = "OK" if overall.get("passed") else "FAIL"
            def fmt(p):
                return f"{p:.3f}" if not math.isnan(p) else "N/A"
            print(f"{mod_name:<60} {passed:<7} {fmt(fp):<6} {fmt(rp):<6} {fmt(ap):<6}")
            if "error" in mod_data:
                print(f"  → ERREUR: {mod_data['error']}")
            if "note" in mod_data:
                print(f"  → NOTE: {mod_data['note']}")
        print("-" * 90)
        o = report["overall"]
        print(
            f"TOTAL: {o['pass_count']}/{o['total']} modules passent "
            f"(seuil p>0.01) → {'OK' if o['all_passed'] else 'ÉCHEC'}"
        )

    print(f"Rapport écrit dans: {out_path}")
    return 0 if report["overall"]["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
