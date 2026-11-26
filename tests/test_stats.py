import json

import pytest

from cyberrisk.stats import bootstrap_mean_ci, paired_comparison, sign_test, wilcoxon_signed_rank


def test_sign_test_exact_value():
    assert sign_test([1.0] * 10) == pytest.approx(2 / 1024)
    assert sign_test([0.0] * 5) == 1.0


def test_wilcoxon_edge_cases():
    assert wilcoxon_signed_rank([0.0, 0.0]) == (0, 1.0)
    n, p = wilcoxon_signed_rank([1.0, -1.0] * 20)
    assert n == 40 and p > 0.9
    _, p = wilcoxon_signed_rank([0.1 * (i + 1) for i in range(30)])
    assert p < 1e-5


def test_wilcoxon_matches_reference_value():
    # scipy.stats.wilcoxon(d, zero_method="wilcox", correction=True, method="approx").pvalue
    d = [0.5, 1.2, -0.3, 0.8, 2.0, -0.1, 0.4, 1.1, 0.9, -0.6, 0.7, 1.5, 0.2, -0.4, 1.3, 0.6, 0.35, 1.8, -0.2, 0.45]
    assert wilcoxon_signed_rank(d)[1] == pytest.approx(0.0028137, abs=1e-6)


def test_bootstrap_ci_is_deterministic_and_brackets_the_mean():
    values = [0.1 * i for i in range(40)]
    strata = ["a", "b"] * 20
    lo, hi = bootstrap_mean_ci(values, strata)
    assert lo < sum(values) / len(values) < hi
    assert (lo, hi) == bootstrap_mean_ci(values, strata)
    assert bootstrap_mean_ci([0.5] * 10, ["x"] * 10) == (0.5, 0.5)


def test_paired_comparison_counts_and_validates():
    out = paired_comparison([1.0, 0.5, 0.2], [0.5, 0.5, 0.4], ["t", "t", "t"])
    assert (out["a_better"], out["ties"], out["b_better"]) == (1, 1, 1)
    assert out["mean_diff"] == pytest.approx(0.1)
    with pytest.raises(ValueError):
        paired_comparison([1.0], [1.0, 2.0], ["t"])


def test_run_writes_simulation_and_significance(tmp_path):
    from cyberrisk.experiments import run

    result = run(tmp_path, seeds=2)
    assert (tmp_path / "significance.csv").exists()
    saved = json.loads((tmp_path / "summary.json").read_text())
    rows = {r["config"]: r for r in saved["summary"]}
    oracle = rows["graph_oracle_upper_bound"]
    assert 0.0 <= oracle["attack_success_after_mean"] <= oracle["attack_success_before_mean"] <= 1.0
    assert len(oracle["loss_reduction_ci95"]) == 2
    settings = {(r["setting"], r["a"], r["b"]) for r in result["significance"]}
    assert ("budget 1", "graph_oracle_upper_bound", "rule_based") in settings
    assert ("budget 4", "graph_oracle_upper_bound", "cvss_only") in settings
