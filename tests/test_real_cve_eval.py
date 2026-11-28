from cyberrisk.cli import main
from cyberrisk.real_cve_eval import evaluate_real_environment, run_real_cve


def test_evaluate_real_environment_configs_and_oracle_dominates():
    rows = {r.config: r for r in evaluate_real_environment("small_lab", 0)}
    assert set(rows) == {"cvss_only", "rule_based", "graph_oracle_upper_bound"}
    assert rows["graph_oracle_upper_bound"].risk_reduction >= rows["cvss_only"].risk_reduction


def test_run_real_cve_writes_files(tmp_path):
    summary = run_real_cve(tmp_path, seeds=2)
    assert {r["config"] for r in summary} == {"cvss_only", "rule_based", "graph_oracle_upper_bound"}
    assert (tmp_path / "real_cve_summary.csv").exists()
    assert (tmp_path / "real_cve_per_environment.csv").exists()
    assert all(r["n"] == 8 for r in summary)  # 4 templates x 2 seeds


def test_cli_demo_real_catalog_prints_attack_techniques(capsys):
    assert main(["demo", "--template", "hpc", "--seed", "3", "--catalog", "real", "--attack", "--top", "2"]) == 0
    out = capsys.readouterr().out
    assert "T1190" in out and "CVE-" in out and "SYN-CVE" not in out


def test_cli_real_catalog_rejects_text_extractors(capsys):
    assert main(["demo", "--catalog", "real", "--extractor", "rules"]) == 2
    assert "oracle" in capsys.readouterr().err
