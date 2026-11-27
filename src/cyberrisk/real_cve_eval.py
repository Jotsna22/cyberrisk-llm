"""Evaluate the planner and the baselines on environments built from real NVD CVEs.

Same 4 topologies, seeds, budget and metrics as the main evaluation, but the weaknesses
are drawn from the bundled real-CVE sample instead of the synthetic SYN-CVE catalog.
Only configurations that need no text extraction are run: the extractors' regular
expressions and the cached Gemini responses were built for SYN-CVE ids.
"""

from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path

from .baselines import cvss_only_plan, rule_based_plan
from .experiments import BUDGET, ConfigResult, _evaluate_plan, _graph_config, summarize
from .nvd import real_catalog
from .synthetic import TEMPLATES, generate_environment


def evaluate_real_environment(template: str, seed: int, catalog=None) -> list[ConfigResult]:
    truth = generate_environment(template, seed, catalog=catalog if catalog is not None else real_catalog())
    return [
        _evaluate_plan("cvss_only", truth, cvss_only_plan(truth, BUDGET), template, seed),
        _evaluate_plan("rule_based", truth, rule_based_plan(truth, BUDGET), template, seed),
        _graph_config("graph_oracle_upper_bound", truth, truth, template, seed),
    ]


def run_real_cve(out_dir: Path, seeds: int = 20) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    catalog = real_catalog()
    rows: list[ConfigResult] = []
    for template in TEMPLATES:
        for seed in range(seeds):
            rows.extend(evaluate_real_environment(template, seed, catalog))

    fields = list(asdict(rows[0]).keys())
    with (out_dir / "real_cve_per_environment.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(r) for r in rows)

    summary = []
    for entry in summarize(rows):
        lo, hi = entry["risk_reduction_ci95"]
        summary.append({
            "config": entry["config"], "n": entry["n"],
            "risk_reduction_mean": entry["risk_reduction_mean"], "risk_reduction_sd": entry["risk_reduction_sd"],
            "risk_reduction_ci95_low": lo, "risk_reduction_ci95_high": hi,
            "attack_success_before": entry["attack_success_before_mean"],
            "attack_success_after": entry["attack_success_after_mean"],
            "loss_reduction_mean": entry["loss_reduction_mean"],
            "catalog_size": len(catalog),
        })
    with (out_dir / "real_cve_summary.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        writer.writerows(summary)
    return summary
