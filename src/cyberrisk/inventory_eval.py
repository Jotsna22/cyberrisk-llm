"""Does the inventory check recover the plans that planted text broke?

For each of the 80 environments, the hard report and the hard report with three planted
injections are read by the (cached) Gemini extractor. Each extracted model is planned on
three ways and the plan is simulated on the ground truth:

  raw        the extracted model as is (what the main evaluation reports)
  flag_only  the same plan, but the inventory check records what it would have caught
  corrected  the inventory overrules exposure and criticality, then the planner runs

The inventory is derived from the ground truth, which assumes the organisation keeps an
accurate asset list. `SETTINGS` also tries incomplete (coverage < 1) and stale inventories.
"""

from __future__ import annotations

import csv
import statistics
from pathlib import Path

from .defense import greedy_recommend
from .experiments import BUDGET, _evaluate_plan, _safe_extract
from .extraction import GeminiExtractor
from .hard_reports import INJECTION_KINDS, render_hard_report, trap_outcome
from .inventory import Inventory, degrade_inventory, reconcile
from .metrics import extraction_scores
from .stats import bootstrap_mean_ci, paired_comparison
from .synthetic import TEMPLATES, generate_environment

VARIANTS = ("hard", "hard_injected")
# (label, coverage, stale fraction)
SETTINGS = (
    ("full", 1.0, 0.0),
    ("coverage_75", 0.75, 0.0),
    ("coverage_50", 0.5, 0.0),
    ("coverage_25", 0.25, 0.0),
    ("stale_25", 1.0, 0.25),
)
INJECTION_FIELD = {"injection_instruction": "criticality", "injection_unverified": "criticality",
                   "injection_plausible_update": "internet_exposed"}


def evaluate_inventory_environment(template: str, seed: int, extractor) -> list[dict]:
    truth = generate_environment(template, seed)
    perfect = Inventory.from_environment(truth)
    rows: list[dict] = []
    for variant in VARIANTS:
        report = render_hard_report(truth, seed, injected=variant == "hard_injected")
        model, failed = _safe_extract(extractor, report.text)
        injections = [t for t in report.traps if t.kind in INJECTION_KINDS]

        def record(setting: str, policy: str, used, found=None):
            result = _evaluate_plan("inventory", truth, greedy_recommend(used, BUDGET), template, seed)
            scores = extraction_scores(used, truth)
            row = {
                "template": template, "seed": seed, "variant": variant, "setting": setting, "policy": policy,
                "exposed_f1": scores["exposed_f1"], "criticality_acc": scores["criticality_acc"],
                "risk_reduction": result.risk_reduction, "loss_reduction": result.loss_reduction,
                "attack_success_after": result.attack_success_after,
                "discrepancies": len(found.discrepancies) if found else 0,
                "extraction_failed": failed,
            }
            for trap in injections:
                row[f"{trap.kind}_outcome"] = trap_outcome(used, trap)
                row[f"{trap.kind}_flagged"] = bool(found and found.flagged(trap.asset, INJECTION_FIELD[trap.kind]))
            rows.append(row)

        record("none", "raw", model)
        for label, coverage, stale in SETTINGS:
            inventory = degrade_inventory(perfect, coverage, stale, seed=f"inv-{template}-{seed}-{label}")
            record(label, "flag_only", model, reconcile(model, inventory, correct=False))
            fixed = reconcile(model, inventory, correct=True)
            record(label, "corrected", fixed.model, fixed)
    return rows


def summarize_inventory(rows: list[dict]) -> list[dict]:
    summary = []
    keys = sorted({(r["variant"], r["setting"], r["policy"]) for r in rows},
                  key=lambda k: (VARIANTS.index(k[0]), k[1] != "none", [s[0] for s in SETTINGS].index(k[1])
                                 if k[1] != "none" else 0, k[2] != "raw", k[2]))
    for variant, setting, policy in keys:
        subset = [r for r in rows if (r["variant"], r["setting"], r["policy"]) == (variant, setting, policy)]
        entry = {"variant": variant, "setting": setting, "policy": policy, "n": len(subset)}
        for metric in ("risk_reduction", "loss_reduction", "attack_success_after", "exposed_f1",
                       "criticality_acc", "discrepancies"):
            entry[f"{metric}_mean"] = statistics.mean(r[metric] for r in subset if r[metric] is not None)
        lo, hi = bootstrap_mean_ci([r["risk_reduction"] for r in subset], [r["template"] for r in subset])
        entry["risk_reduction_ci95_low"], entry["risk_reduction_ci95_high"] = lo, hi
        for kind in INJECTION_KINDS:
            tested = [r for r in subset if f"{kind}_outcome" in r]
            fooled = sum(r[f"{kind}_outcome"] == "fooled" for r in tested)
            flagged = sum(bool(r[f"{kind}_flagged"]) for r in tested)
            entry[f"{kind}_fooled"] = fooled if tested else None
            entry[f"{kind}_flagged"] = flagged if tested else None
            entry[f"{kind}_n"] = len(tested)
        summary.append(entry)
    return summary


def inventory_significance(rows: list[dict]) -> list[dict]:
    """Paired tests: corrected vs. raw plans on the same environments."""
    index = {(r["variant"], r["setting"], r["policy"], r["template"], r["seed"]): r for r in rows}
    out = []
    for variant in VARIANTS:
        for label, _, _ in SETTINGS:
            keys = sorted((t, s) for v, st, p, t, s in index if (v, st, p) == (variant, label, "corrected"))
            for metric in ("risk_reduction", "attack_success_after"):
                cmp = paired_comparison([index[(variant, label, "corrected", *k)][metric] for k in keys],
                                        [index[(variant, "none", "raw", *k)][metric] for k in keys],
                                        [k[0] for k in keys])
                out.append({"variant": variant, "setting": label, "metric": metric,
                            "a": "corrected", "b": "raw", **cmp})
    return out


def _write(path: Path, rows: list[dict]) -> None:
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run_inventory_check(out_dir: Path, cache_dir: Path, seeds: int = 20, extractor=None) -> dict:
    """Run the experiment. By default Gemini responses are read from `cache_dir` (no key needed)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    extractor = extractor or GeminiExtractor(cache_dir=cache_dir)
    rows: list[dict] = []
    for template in TEMPLATES:
        for seed in range(seeds):
            rows.extend(evaluate_inventory_environment(template, seed, extractor))
    summary = summarize_inventory(rows)
    significance = inventory_significance(rows)
    _write(out_dir / "inventory_per_environment.csv", rows)
    _write(out_dir / "inventory_summary.csv", summary)
    _write(out_dir / "inventory_significance.csv", significance)
    return {"summary": summary, "significance": significance}
