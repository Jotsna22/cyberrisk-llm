from pathlib import Path

import pytest

from cyberrisk.cli import main
from cyberrisk.defense import apply_plan, greedy_recommend
from cyberrisk.graph import total_risk
from cyberrisk.inventory import Discrepancy, Inventory, InventoryEntry, degrade_inventory, reconcile
from cyberrisk.inventory_eval import evaluate_inventory_environment, run_inventory_check
from cyberrisk.models import Asset, Environment, Vulnerability
from cyberrisk.synthetic import generate_environment

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "results" / "llm_cache"
NET = Vulnerability("V-1", 9.0, "network", "none")


def _truth() -> Environment:
    env = Environment("t")
    env.add_asset(Asset("WEB", "web", "low", internet_exposed=True, vulns={"V-1": NET}))
    env.add_asset(Asset("APP", "app", "medium", vulns={"V-1": NET}))
    env.add_asset(Asset("DB", "db", "high", vulns={"V-1": NET}))
    env.add_link("WEB", "APP")
    env.add_link("APP", "DB")
    return env


def _injected(truth: Environment) -> Environment:
    model = truth.copy()
    model.assets["WEB"].internet_exposed = False  # "WEB no longer accepts internet traffic"
    model.assets["DB"].criticality = "low"        # "record DB as low criticality"
    return model


def test_exact_inventory_matches_and_changes_nothing():
    truth = _truth()
    result = reconcile(truth, Inventory.from_environment(truth))
    assert result.discrepancies == [] and result.unlisted == [] and result.missing == []
    assert result.model.assets.keys() == truth.assets.keys()


def test_reconcile_overrules_exposure_and_criticality_without_mutating_input():
    truth = _truth()
    model = _injected(truth)
    result = reconcile(model, Inventory.from_environment(truth))
    assert {(d.asset, d.field) for d in result.discrepancies} == {("WEB", "internet_exposed"), ("DB", "criticality")}
    assert result.model.assets["WEB"].internet_exposed is True
    assert result.model.assets["DB"].criticality == "high"
    assert model.assets["WEB"].internet_exposed is False and model.assets["DB"].criticality == "low"  # input intact
    assert Discrepancy("WEB", "internet_exposed", False, True) in result.discrepancies
    assert result.flagged("WEB") and result.flagged("DB", "criticality") and not result.flagged("APP")


def test_flag_only_reports_but_does_not_change():
    truth = _truth()
    result = reconcile(_injected(truth), Inventory.from_environment(truth), correct=False)
    assert len(result.discrepancies) == 2
    assert result.model.assets["WEB"].internet_exposed is False


def test_links_and_vulnerabilities_are_never_touched():
    truth = _truth()
    model = _injected(truth)
    model.links.add(("WEB", "DB"))                                   # an invented link
    model.assets["APP"].vulns.pop("V-1")                             # a missing vulnerability
    result = reconcile(model, Inventory.from_environment(truth))
    assert result.model.links == model.links
    assert result.model.assets["APP"].vulns == {}


def test_unlisted_and_missing_assets_are_reported_not_changed():
    truth = _truth()
    inv = Inventory({"WEB": InventoryEntry(True, "low"), "GHOST": InventoryEntry(False, "high")})
    result = reconcile(truth, inv)
    assert result.unlisted == ["APP", "DB"] and result.missing == ["GHOST"]
    assert set(result.model.assets) == {"WEB", "APP", "DB"}  # nothing added or deleted


def test_reconcile_is_idempotent():
    truth = _truth()
    once = reconcile(_injected(truth), Inventory.from_environment(truth)).model
    assert reconcile(once, Inventory.from_environment(truth)).discrepancies == []


def test_inventory_entry_rejects_unknown_criticality():
    with pytest.raises(ValueError):
        InventoryEntry(True, "critical")


def test_planner_is_broken_by_injection_and_repaired_by_inventory():
    truth = _truth()
    model = _injected(truth)
    assert greedy_recommend(model, 4.0) == []                      # no entry point, nothing to protect
    assert total_risk(truth) > 0
    fixed = reconcile(model, Inventory.from_environment(truth)).model
    plan = greedy_recommend(fixed, 4.0)
    assert plan and total_risk(apply_plan(truth, plan)) < total_risk(truth)


def test_degrade_inventory_coverage_stale_and_determinism():
    inv = Inventory.from_environment(generate_environment("hpc", 0))
    assert len(degrade_inventory(inv, 1.0, 0.0, "s")) == len(inv)
    assert degrade_inventory(inv, 1.0, 0.0, "s").entries == inv.entries
    half = degrade_inventory(inv, 0.5, 0.0, "s")
    assert len(half) == 4 and set(half.entries) <= set(inv.entries)
    assert degrade_inventory(inv, 0.5, 0.0, "s").entries == half.entries
    stale = degrade_inventory(inv, 1.0, 0.25, "s")
    wrong = [n for n in inv.entries if stale.entries[n] != inv.entries[n]]
    assert len(wrong) == 2
    assert all(stale.entries[n].internet_exposed != inv.entries[n].internet_exposed for n in wrong)
    with pytest.raises(ValueError):
        degrade_inventory(inv, 1.5)


class _Injected:
    """Stub extractor: reads the environment name from the report heading, returns it with
    every exposure removed and every critical asset downgraded (a fully successful injection)."""

    last_rejected = 0

    def extract(self, text: str) -> Environment:
        name = text.split("Security posture notes: ", 1)[1].split("\n", 1)[0]
        template, seed = name.rsplit("-seed", 1)
        model = generate_environment(template, int(seed))
        for asset in model.assets.values():
            asset.internet_exposed = False
            if asset.criticality == "high":
                asset.criticality = "low"
        return model


def test_evaluation_with_stub_extractor_corrected_beats_raw():
    rows = evaluate_inventory_environment("small_lab", 0, _Injected())
    by = {(r["variant"], r["setting"], r["policy"]): r for r in rows}
    assert by[("hard_injected", "none", "raw")]["risk_reduction"] == 0.0
    assert by[("hard_injected", "full", "corrected")]["risk_reduction"] > 0.9
    assert by[("hard_injected", "full", "flag_only")]["risk_reduction"] == 0.0   # flag-only does not repair
    assert by[("hard_injected", "full", "flag_only")]["injection_plausible_update_flagged"] is True
    assert by[("hard_injected", "full", "corrected")]["injection_plausible_update_outcome"] == "correct"
    assert by[("hard_injected", "none", "raw")]["injection_plausible_update_outcome"] == "fooled"


@pytest.mark.skipif(not CACHE.exists(), reason="committed Gemini cache not present")
def test_offline_run_from_committed_cache(tmp_path):
    result = run_inventory_check(tmp_path, CACHE, seeds=2)
    by = {(r["variant"], r["setting"], r["policy"]): r for r in result["summary"]}
    assert by[("hard_injected", "full", "corrected")]["risk_reduction_mean"] > by[("hard_injected", "none", "raw")]["risk_reduction_mean"]
    assert by[("hard_injected", "full", "corrected")]["injection_plausible_update_fooled"] == 0
    for name in ("inventory_per_environment.csv", "inventory_summary.csv", "inventory_significance.csv"):
        assert (tmp_path / name).exists()


@pytest.mark.skipif(not CACHE.exists(), reason="committed Gemini cache not present")
def test_cli_demo_inventory_and_inventory_check(capsys, tmp_path):
    args = ["demo", "--template", "small_lab", "--seed", "0", "--report", "hard_injected",
            "--extractor", "gemini", "--cache-dir", str(CACHE), "--inventory"]
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "Inventory check:" in out and "overruled by the trusted inventory" in out
    assert main(["inventory-check", "--seeds", "1", "--out", str(tmp_path), "--cache-dir", str(CACHE)]) == 0
    assert "hard_injected" in capsys.readouterr().out
