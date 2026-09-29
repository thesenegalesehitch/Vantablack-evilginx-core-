#!/usr/bin/env python3
"""
VANTABLACK Behavioral Analysis CLI
===================================

Command-line interface for behavioral analysis and ML attack vector prediction.

Interface utilisée par Makefile :
  analysis/behavioral/cli.py predict --target o365 --top 5 --output /tmp/ml_pred.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from analysis.behavioral.predictor import EnsembleMetaLearner


def cmd_predict_vectors(args: argparse.Namespace) -> int:
    engine = EnsembleMetaLearner()
    result = engine.predict(
        target=args.target,
        top_k=args.top,
    )

    for p in result["predictions"]:
        p["confidence"] = p.get(
            "confidence_interval",
            p.get("confidence", 0.0),
        )

    output = {
        "target": result["target"],
        "predictions": result["predictions"],
        "features_used": result.get("features_used", {}),
        "seed_sequence": result.get("seed_sequence", []),
        "weights": result.get("weights", {}),
        "probability_sum": result.get("probability_sum", 1.0),
        "ks_validation_pass_rate": result.get("ks_validation", 0.0),
        "generated_at": time.time(),
    }

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    preds = output["predictions"]
    for i, p in enumerate(preds[: args.top]):
        vec = p["vector"]
        prob = p["probability"]
        ci = p.get("confidence", p.get("confidence_interval", 0.0))
        model = p["dominant_model"]
        print(f"  #{i + 1} {vec:<20} P={prob:.3f}  CI={ci:.3f}  model={model}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VANTABLACK Behavioral Analysis - ML Prédiction vecteurs",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    predict_p = subparsers.add_parser(
        "predict",
        help="TOP-K prédictions de vecteurs d'attaque (Markov/Bayes/Poisson)",
    )
    predict_p.add_argument(
        "--target",
        "-t",
        type=str,
        required=True,
        help="Cible (ex: o365, google, aws, finance...)",
    )
    predict_p.add_argument(
        "--top",
        type=int,
        default=5,
        help="Nombre de vecteurs à retourner (defaut: 5)",
    )
    predict_p.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Fichier JSON de sortie",
    )
    predict_p.set_defaults(func=cmd_predict_vectors)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
