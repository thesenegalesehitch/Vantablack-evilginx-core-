from __future__ import annotations

import argparse
import json
import math
import sys
import time
import uuid
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import numpy as np


def _build_timing_plan(
    interval_mode: str,
    max_attempts: int,
    lambda_poisson: float = 3.0,
    fixed_interval_s: float = 30.0,
) -> dict:
    from attack.mfa_bombing.bomber import test_poisson_ks

    if interval_mode == "poisson":
        intervals = np.random.poisson(lam=lambda_poisson, size=max_attempts).astype(float)
        intervals = np.clip(intervals, 0.5, None).tolist()
    else:
        intervals = [float(fixed_interval_s)] * max_attempts

    plan = []
    cumulative = 0.0
    for i, dt in enumerate(intervals):
        cumulative += dt
        plan.append({
            "attempt": i + 1,
            "interval_s": dt,
            "elapsed_s": cumulative,
            "attempt_id": str(uuid.uuid4()),
            "scheduled_ts": time.time() + cumulative,
        })

    ks_result = None
    if interval_mode == "poisson":
        ks_result = test_poisson_ks(lambda_val=lambda_poisson, n_samples=1000)

    return {
        "campaign_id": str(uuid.uuid4()),
        "target": "",
        "interval_mode": interval_mode,
        "lambda": lambda_poisson if interval_mode == "poisson" else None,
        "max_attempts": max_attempts,
        "dry_run": True,
        "timing_plan": plan,
        "poisson_ks_test": ks_result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MFA Bombing - Simulateur de timing pour push bombing",
    )
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Compte cible (username@domain)",
    )
    parser.add_argument(
        "--interval",
        type=str,
        choices=["fixed", "poisson"],
        default="poisson",
        help="Distribution des intervalles (defaut: poisson)",
    )
    parser.add_argument(
        "--lambda",
        dest="lambda_poisson",
        type=float,
        default=3.0,
        help="Paramètre λ pour distribution Poisson (defaut: 3.0)",
    )
    parser.add_argument(
        "--fixed-interval",
        type=float,
        default=30.0,
        help="Intervalle fixe en secondes (mode fixed, defaut: 30)",
    )
    parser.add_argument(
        "--max",
        dest="max_attempts",
        type=int,
        default=60,
        help="Nombre max de tentatives (defaut: 60)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Ne pas envoyer de push, seulement générer le timing plan (defaut: True)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        required=True,
        help="Fichier JSON de sortie",
    )
    args = parser.parse_args()

    plan = _build_timing_plan(
        interval_mode=args.interval,
        max_attempts=args.max_attempts,
        lambda_poisson=args.lambda_poisson,
        fixed_interval_s=args.fixed_interval,
    )
    plan["target"] = args.target

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    print(f"✅ Timing plan MFA bombing généré (mode={args.interval})")
    print(f"   Cible        : {args.target}")
    print(f"   Nb pushes    : {len(plan['timing_plan'])}")
    if args.interval == "poisson":
        print(f"   λ visé       : {args.lambda_poisson}")
        ks = plan.get("poisson_ks_test")
        if ks:
            status = "OK" if ks["passes"] else "ÉCHEC"
            print(f"   KS-test (N={ks['n_samples']}) : D={ks['ks_stat']:.4f}  p={ks['p_value']:.4f}  → {status}")
            print(f"     Moyenne échantillon : {ks['sample_mean']:.3f} (théorique: {ks['theoretical_mean']})")
            print(f"     Variance échantillon: {ks['sample_var']:.3f} (théorique: {ks['theoretical_var']})")
    else:
        print(f"   Intervalle   : {args.fixed_interval}s")
    total = plan["timing_plan"][-1]["elapsed_s"] if plan["timing_plan"] else 0
    h = int(total // 3600)
    m = int((total % 3600) // 60)
    s = int(total % 60)
    print(f"   Durée totale : {h}h{m:02d}m{s:02d}s")
    print(f"   Output       : {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
