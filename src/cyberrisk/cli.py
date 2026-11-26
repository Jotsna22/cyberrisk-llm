"""Command-line interface: `cyberrisk demo` and `cyberrisk evaluate`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .defense import apply_plan, greedy_recommend
from .extraction import ExtractionError, RuleBasedExtractor
from .graph import at_risk_assets, enumerate_attack_paths, model_warnings, total_risk
from .synthetic import TEMPLATES, generate_environment, render_report


def _demo(args: argparse.Namespace) -> int:
    truth = generate_environment(args.template, args.seed)
    report = render_report(truth, args.seed)
    rejected = None
    if args.extractor == "rules":
        model = RuleBasedExtractor().extract(report)
    elif args.extractor == "gemini":
        from .extraction import GeminiExtractor

        try:
            extractor = GeminiExtractor(cache_dir=Path(args.cache_dir))
            model = extractor.extract(report)
        except (RuntimeError, ExtractionError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        rejected = extractor.last_rejected
    else:
        model = truth
    print(f"Environment: {truth.name} ({len(truth.assets)} assets, {len(truth.links)} links)")
    print(f"Extractor:   {args.extractor}" + (f" ({rejected} facts rejected)" if rejected is not None else ""))
    for warning in model_warnings(model):
        print(f"WARNING (planner input): {warning}")
    print(f"Modeled risk before plan: {total_risk(truth):.4f}; at-risk critical assets: {sorted(at_risk_assets(truth))}")
    print("\nTop attack paths (ground truth):")
    for path in enumerate_attack_paths(truth)[:args.top]:
        print(f"  {' -> '.join(path.nodes)}  p={path.probability:.3f}  risk={path.risk:.4f}")
    plan = greedy_recommend(model, args.budget)
    print(f"\nRecommended plan (budget {args.budget}):")
    if not plan:
        print("  (none: the planner's model contains no attack path to a critical asset)")
    for control in plan:
        print(f"  - {control.describe()} (cost {control.cost:g})")
    after = apply_plan(truth, plan)
    before = total_risk(truth)
    print(f"\nTrue modeled risk: {before:.4f} -> {total_risk(after):.4f}")
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    from .experiments import run

    llm = None
    if args.llm == "gemini":
        from .extraction import GeminiExtractor

        llm = GeminiExtractor(cache_dir=Path(args.out) / "llm_cache")
    try:
        result = run(Path(args.out), seeds=args.seeds, llm_extractor=llm,
                     llm_robustness_seeds=args.llm_robustness_seeds)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for row in result["summary"]:
        print(f"{row['config']:<28} risk reduction {row['risk_reduction_mean']:.3f} ± {row['risk_reduction_sd']:.3f}")
    print("\nBudget sweep (risk reduction):")
    for row in result["budget_sweep"]:
        print(f"  budget {row['budget']:g}  {row['config']:<28} {row['risk_reduction_mean']:.3f}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberrisk")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the pipeline on one synthetic environment")
    demo.add_argument("--template", choices=sorted(TEMPLATES), default="small_lab")
    demo.add_argument("--seed", type=int, default=0)
    demo.add_argument("--extractor", choices=["rules", "oracle", "gemini"], default="oracle",
                      help="oracle: plan on ground truth; rules: plan on rule-based extraction of the report; "
                           "gemini: plan on LLM extraction (needs GEMINI_API_KEY unless cached)")
    demo.add_argument("--cache-dir", default="results/llm_cache",
                      help="response cache for --extractor gemini")
    demo.add_argument("--budget", type=float, default=4.0)
    demo.add_argument("--top", type=int, default=5)
    demo.set_defaults(func=_demo)

    ev = sub.add_parser("evaluate", help="run the full evaluation and write results/")
    ev.add_argument("--seeds", type=int, default=20)
    ev.add_argument("--out", default="results")
    ev.add_argument("--llm", choices=["none", "gemini"], default="none",
                    help="add the LLM-extraction configuration (gemini needs GEMINI_API_KEY unless cached)")
    ev.add_argument("--llm-robustness-seeds", type=int, default=5,
                    help="seeds per template for the LLM text-robustness run (0 to skip)")
    ev.set_defaults(func=_evaluate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
