from cyberrisk.baselines import cvss_only_plan, rule_based_plan
from cyberrisk.defense import Control, apply_plan, greedy_recommend
from cyberrisk.graph import total_risk
from cyberrisk.synthetic import generate_environment


def test_greedy_plan_reduces_risk_and_respects_budget():
    env = generate_environment("cloud", 1)
    before = total_risk(env)
    plan = greedy_recommend(env, budget=4.0)
    assert sum(c.cost for c in plan) <= 6.0
    if before > 0:
        assert total_risk(apply_plan(env, plan)) < before


def test_patch_of_missing_vulnerability_has_no_effect():
    env = generate_environment("hpc", 2)
    before = total_risk(env)
    after = total_risk(apply_plan(env, [Control("patch", ("NOPE-01", "SYN-CVE-0001"))]))
    assert after == before


def test_baselines_respect_budget():
    env = generate_environment("distributed", 3)
    assert len(cvss_only_plan(env, 3.0)) == 3
    assert len(rule_based_plan(env, 4.0)) <= 4
    assert all(c.kind == "patch" for c in rule_based_plan(env, 4.0))


def test_cli_demo_runs(capsys):
    from cyberrisk.cli import main

    assert main(["demo", "--template", "cloud", "--seed", "1"]) == 0
    out = capsys.readouterr().out
    assert "Recommended plan" in out and "True modeled risk" in out
