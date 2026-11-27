"""Confidence intervals and paired significance tests for the evaluation (pure Python, no SciPy).

Every configuration is run on the same 80 environments, so comparisons are paired:
we test the per-environment difference, not two independent samples.

* Bootstrap CIs resample environments *within each topology template* (stratified),
  so every resample keeps the 4-template design. Seeds within a template share a
  topology, so the 80 environments are not fully independent; stratifying keeps the
  CI from mixing templates, but the CIs still describe these 4 topologies only.
* The Wilcoxon signed-rank test uses the normal approximation with tie and continuity
  correction, and drops zero differences (the standard Wilcoxon convention). With
  n >= 20 non-zero pairs the approximation is accurate. The exact one-sided sign
  test is reported alongside, since it needs no distributional assumption.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import defaultdict
from typing import Sequence

N_BOOT = 5000
ALPHA = 0.05


def _stratified_indices(strata: Sequence[str]) -> list[list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for i, s in enumerate(strata):
        groups[s].append(i)
    return [groups[k] for k in sorted(groups)]


def bootstrap_mean_ci(values: Sequence[float], strata: Sequence[str] | None = None,
                      n_boot: int = N_BOOT, alpha: float = ALPHA, seed: int = 0) -> tuple[float, float]:
    """Percentile bootstrap CI for the mean, resampling within strata."""
    if not values:
        return float("nan"), float("nan")
    groups = _stratified_indices(strata if strata is not None else ["all"] * len(values))
    rng = random.Random(seed)
    means = []
    for _ in range(n_boot):
        total = 0.0
        for group in groups:
            total += sum(values[rng.choice(group)] for _ in group)
        means.append(total / len(values))
    means.sort()
    lo = means[int(math.floor(alpha / 2 * n_boot))]
    hi = means[min(n_boot - 1, int(math.ceil((1 - alpha / 2) * n_boot)) - 1)]
    return lo, hi


def wilcoxon_signed_rank(diffs: Sequence[float], eps: float = 1e-12) -> tuple[int, float]:
    """Two-sided Wilcoxon signed-rank test. Returns (number of non-zero pairs, p-value)."""
    nonzero = [d for d in diffs if abs(d) > eps]
    n = len(nonzero)
    if n == 0:
        return 0, 1.0
    order = sorted(range(n), key=lambda i: abs(nonzero[i]))
    ranks = [0.0] * n
    tie_term = 0.0
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(abs(nonzero[order[j + 1]]) - abs(nonzero[order[i]])) <= eps:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        t = j - i + 1
        tie_term += t ** 3 - t
        i = j + 1
    w_plus = sum(r for r, d in zip(ranks, nonzero) if d > 0)
    mean = n * (n + 1) / 4
    var = n * (n + 1) * (2 * n + 1) / 24 - tie_term / 48
    if var <= 0:
        return n, 1.0
    z = (abs(w_plus - mean) - 0.5) / math.sqrt(var)
    return n, min(1.0, math.erfc(max(z, 0.0) / math.sqrt(2)))


def sign_test(diffs: Sequence[float], eps: float = 1e-12) -> float:
    """Exact two-sided sign test p-value on the non-zero differences."""
    wins = sum(d > eps for d in diffs)
    losses = sum(d < -eps for d in diffs)
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def paired_comparison(a: Sequence[float], b: Sequence[float], strata: Sequence[str],
                      seed: int = 0) -> dict:
    """Compare configuration A against B on the same environments (difference = A - B)."""
    if len(a) != len(b) or len(a) != len(strata):
        raise ValueError("paired samples must have equal length")
    diffs = [x - y for x, y in zip(a, b)]
    lo, hi = bootstrap_mean_ci(diffs, strata, seed=seed)
    n_nonzero, p_wilcoxon = wilcoxon_signed_rank(diffs)
    return {
        "n": len(diffs),
        "mean_a": statistics.mean(a),
        "mean_b": statistics.mean(b),
        "mean_diff": statistics.mean(diffs),
        "diff_ci95_low": lo,
        "diff_ci95_high": hi,
        "a_better": sum(d > 1e-12 for d in diffs),
        "ties": sum(abs(d) <= 1e-12 for d in diffs),
        "b_better": sum(d < -1e-12 for d in diffs),
        "wilcoxon_n_nonzero": n_nonzero,
        "wilcoxon_p": p_wilcoxon,
        "sign_test_p": sign_test(diffs),
    }
