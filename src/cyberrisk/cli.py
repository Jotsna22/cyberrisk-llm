"""Command-line interface: `cyberrisk demo` and `cyberrisk evaluate`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .defense import apply_plan, greedy_recommend
from .extraction import ExtractionError, RuleBasedExtractor, TemplateExtractor
from .graph import at_risk_assets, enumerate_attack_paths, model_warnings, total_risk
from .simulation import simulate_attacks
from .attack_mapping import map_path
from .hard_reports import render_hard_report, trap_outcome
from .inventory import Inventory, reconcile
from .nvd import real_catalog
from .synthetic import TEMPLATES, generate_environment, render_report


def _demo(args: argparse.Namespace) -> int:
    if args.catalog == "real" and args.extractor != "oracle":
        print("error: --catalog real works with --extractor oracle only (the extractors and the cached "
              "Gemini responses were built for synthetic SYN-CVE ids)", file=sys.stderr)
        return 2
    catalog = real_catalog() if args.catalog == "real" else None
    truth = generate_environment(args.template, args.seed, catalog=catalog)
    traps = []
    if args.report == "easy":
        report = render_report(truth, args.seed)
    else:
        hard = render_hard_report(truth, args.seed, injected=args.report == "hard_injected")
        report, traps = hard.text, hard.traps
    if args.show_report:
        print(report)
    rejected = None
    if args.extractor == "rules":
        model = RuleBasedExtractor().extract(report)
    elif args.extractor == "template":
        model = TemplateExtractor().extract(report)
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
    print(f"Report:      {args.report}")
    print(f"Extractor:   {args.extractor}" + (f" ({rejected} facts rejected)" if rejected is not None else ""))
    if traps and args.extractor != "oracle":
        print("Traps in the report:")
        for trap in traps:
            print(f"  {trap.kind:<27} {trap.asset:<10} {trap.detail:<18} -> {trap_outcome(model, trap)}")
    if args.inventory:
        found = reconcile(model, Inventory.from_environment(truth), correct=True)
        print(f"Inventory check: {len(found.discrepancies)} label(s) overruled by the trusted inventory")
        for item in found.discrepancies:
            print(f"  - {item.describe()}")
        model = found.model
    for warning in model_warnings(model):
        print(f"WARNING (planner input): {warning}")
    print(f"Modeled risk before plan: {total_risk(truth):.4f}; at-risk critical assets: {sorted(at_risk_assets(truth))}")
    print("\nTop attack paths (ground truth):")
    for path in enumerate_attack_paths(truth)[:args.top]:
        print(f"  {' -> '.join(path.nodes)}  p={path.probability:.3f}  risk={path.risk:.4f}")
        if args.attack:
            for step in map_path(truth, path.nodes):
                if step.technique is not None and step.vulnerability is not None:
                    print(f"      {step.src} -> {step.dst}: {step.technique.label()} "
                          f"[{step.technique.tactic}] via {step.vulnerability.cve_id} "
                          f"(CVSS {step.vulnerability.cvss:.1f})")
    plan = greedy_recommend(model, args.budget)
    print(f"\nRecommended plan (budget {args.budget}):")
    if not plan:
        print("  (none: the planner's model contains no attack path to a critical asset)")
    for control in plan:
        print(f"  - {control.describe()} (cost {control.cost:g})")
    after = apply_plan(truth, plan)
    before = total_risk(truth)
    print(f"\nTrue modeled risk: {before:.4f} -> {total_risk(after):.4f}")
    sim_before, sim_after = simulate_attacks(truth), simulate_attacks(after)
    print(f"\nAttacker simulation on the true environment ({sim_before.method}):")
    print(f"  attack success (any critical asset):  {sim_before.attack_success:.3f} -> {sim_after.attack_success:.3f}")
    print(f"  critical assets compromised (mean):   {sim_before.critical_compromised:.3f} -> "
          f"{sim_after.critical_compromised:.3f} of {len(truth.critical_assets())}")
    print(f"  expected loss:                        {sim_before.expected_loss:.4f} -> {sim_after.expected_loss:.4f}")
    return 0


def _inventory_check(args: argparse.Namespace) -> int:
    from .inventory_eval import run_inventory_check

    try:
        result = run_inventory_check(Path(args.out), Path(args.cache_dir), seeds=args.seeds)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("Inventory check (Gemini on hard reports; risk reduction / attack success after plan):")
    for row in result["summary"]:
        if row["policy"] == "flag_only":
            continue
        fooled = sum(row[f"{k}_fooled"] or 0 for k in ("injection_instruction", "injection_unverified",
                                                       "injection_plausible_update"))
        print(f"  {row['variant']:<14} {row['setting']:<12} {row['policy']:<10} "
              f"{row['risk_reduction_mean']:.3f} [{row['risk_reduction_ci95_low']:.3f}, "
              f"{row['risk_reduction_ci95_high']:.3f}] / {row['attack_success_after_mean']:.3f}"
              f"   injections fooled: {fooled}")
    return 0


def _real_cve(args: argparse.Namespace) -> int:
    from .real_cve_eval import run_real_cve

    summary = run_real_cve(Path(args.out), seeds=args.seeds)
    print(f"Real-CVE evaluation ({summary[0]['catalog_size']} CVEs, {summary[0]['n']} environments, budget 4):")
    for row in summary:
        print(f"{row['config']:<28} risk reduction {row['risk_reduction_mean']:.3f} ± {row['risk_reduction_sd']:.3f}"
              f"   attack success {row['attack_success_before']:.3f} -> {row['attack_success_after']:.3f}"
              f"   loss reduction {row['loss_reduction_mean']:.3f}")
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    from .experiments import run

    llm = None
    if args.llm == "gemini":
        from .extraction import GeminiExtractor

        llm = GeminiExtractor(cache_dir=Path(args.out) / "llm_cache")
    try:
        result = run(Path(args.out), seeds=args.seeds, llm_extractor=llm,
                     llm_robustness_seeds=args.llm_robustness_seeds, hard_llm_seeds=args.hard_llm_seeds)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for row in result["summary"]:
        lo, hi = row["loss_reduction_ci95"]
        print(f"{row['config']:<28} risk reduction {row['risk_reduction_mean']:.3f} ± {row['risk_reduction_sd']:.3f}"
              f"   attack success {row['attack_success_before_mean']:.3f} -> {row['attack_success_after_mean']:.3f}"
              f"   loss reduction {row['loss_reduction_mean']:.3f} [{lo:.3f}, {hi:.3f}]")
    print("\nBudget sweep (risk reduction):")
    for row in result["budget_sweep"]:
        print(f"  budget {row['budget']:g}  {row['config']:<28} {row['risk_reduction_mean']:.3f}"
              f"   loss reduction {row['loss_reduction_mean']:.3f}")
    print("\nHard reports (vuln F1 / link F1 / criticality acc. / risk reduction):")
    for row in result["hard_text"]:
        crit = row["criticality_acc_mean"]
        print(f"  {row['variant']:<14} {row['extractor']:<16} {row['vuln_f1_mean']:.3f} / {row['link_f1_mean']:.3f} / "
              f"{'n/a' if crit is None else f'{crit:.3f}'} / {row['risk_reduction_mean']:.3f}")
    print("\nTraps fooled (when tested):")
    for row in result["hard_text_traps"]:
        if row["extractor"] == "llm" or row["fooled"]:
            rate = row["fooled_rate_when_tested"]
            print(f"  {row['variant']:<14} {row['extractor']:<16} {row['kind']:<27} "
                  f"{'untested' if rate is None else f'{rate:.2f}'} ({row['fooled']}/{row['n'] - row['missing']})")
    print("\nPaired tests (A - B, 95% stratified bootstrap CI, Wilcoxon p):")
    for row in result["significance"]:
        print(f"  {row['setting']:<9} {row['metric']:<15} {row['a']} - {row['b']}: {row['mean_diff']:+.3f} "
              f"[{row['diff_ci95_low']:+.3f}, {row['diff_ci95_high']:+.3f}]  p={row['wilcoxon_p']:.2g}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberrisk")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the pipeline on one synthetic environment")
    demo.add_argument("--template", choices=sorted(TEMPLATES), default="small_lab")
    demo.add_argument("--seed", type=int, default=0)
    demo.add_argument("--report", choices=["easy", "hard", "hard_injected"], default="easy",
                      help="easy: templated report; hard: free-form text with tables, negations and corrections; "
                           "hard_injected: hard plus planted injections")
    demo.add_argument("--show-report", action="store_true", help="print the report text")
    demo.add_argument("--extractor", choices=["rules", "template", "oracle", "gemini"], default="oracle",
                      help="oracle: plan on ground truth; rules: plan on rule-based extraction of the report; "
                           "template: parser for all 12 easy-report phrasings; "
                           "gemini: plan on LLM extraction (needs GEMINI_API_KEY unless cached)")
    demo.add_argument("--cache-dir", default="results/llm_cache",
                      help="response cache for --extractor gemini")
    demo.add_argument("--catalog", choices=["synthetic", "real"], default="synthetic",
                      help="synthetic: fictional SYN-CVE ids; real: well-known CVEs from the bundled NVD sample "
                           "(oracle extractor only)")
    demo.add_argument("--attack", action="store_true",
                      help="label each step of the top attack paths with its MITRE ATT&CK technique")
    demo.add_argument("--inventory", action="store_true",
                      help="let a trusted inventory (built from the ground truth) overrule the extracted "
                           "exposure and criticality labels before planning")
    demo.add_argument("--budget", type=float, default=4.0)
    demo.add_argument("--top", type=int, default=5)
    demo.set_defaults(func=_demo)

    inv = sub.add_parser("inventory-check",
                         help="measure how much a trusted asset inventory repairs plans broken by planted text")
    inv.add_argument("--seeds", type=int, default=20)
    inv.add_argument("--out", default="results")
    inv.add_argument("--cache-dir", default="results/llm_cache",
                     help="Gemini response cache (reports not in it need GEMINI_API_KEY)")
    inv.set_defaults(func=_inventory_check)

    rc = sub.add_parser("real-cve", help="evaluate the planner and baselines on environments built from real CVEs")
    rc.add_argument("--seeds", type=int, default=20)
    rc.add_argument("--out", default="results")
    rc.set_defaults(func=_real_cve)

    ev = sub.add_parser("evaluate", help="run the full evaluation and write results/")
    ev.add_argument("--seeds", type=int, default=20)
    ev.add_argument("--out", default="results")
    ev.add_argument("--llm", choices=["none", "gemini"], default="none",
                    help="add the LLM-extraction configuration (gemini needs GEMINI_API_KEY unless cached)")
    ev.add_argument("--llm-robustness-seeds", type=int, default=5,
                    help="seeds per template for the LLM text-robustness run (0 to skip)")
    ev.add_argument("--hard-llm-seeds", type=int, default=20,
                    help="seeds per template for the LLM on hard reports (0 to skip; rules/template always run)")
    ev.set_defaults(func=_evaluate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
