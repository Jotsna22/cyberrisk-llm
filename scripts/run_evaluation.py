"""Run the full evaluation and write results/ (CSV + JSON). Usage: python scripts/run_evaluation.py [--seeds N]."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberrisk.experiments import DEFAULT_SEEDS, run  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=DEFAULT_SEEDS, help="environments per topology template")
    parser.add_argument("--out", type=Path, default=ROOT / "results")
    args = parser.parse_args()
    result = run(args.out, seeds=args.seeds)
    print(json.dumps(result["summary"], indent=2))
    print(json.dumps(result["robustness"], indent=2))
