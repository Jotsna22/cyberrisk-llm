import pytest

from cyberrisk.graph import at_risk_assets, enumerate_attack_paths, model_warnings, total_risk
from cyberrisk.models import INTERNET, Asset, Environment, Vulnerability


def chain_env() -> Environment:
    """Internet -> WEB (exposed) -> DB (high criticality), one network vuln each."""
    env = Environment("chain")
    env.add_asset(Asset("WEB", "web", "low", internet_exposed=True))
    env.add_asset(Asset("DB", "db", "high"))
    env.assets["WEB"].add_vulnerability(Vulnerability("V1", 9.8, "network", "none"))
    env.assets["DB"].add_vulnerability(Vulnerability("V2", 8.0, "network", "none"))
    env.add_link("WEB", "DB")
    return env


def test_chain_path_probability_and_risk():
    paths = enumerate_attack_paths(chain_env())
    assert len(paths) == 1
    path = paths[0]
    assert path.nodes == (INTERNET, "WEB", "DB")
    assert path.probability == pytest.approx(0.9 * 0.9)
    assert path.risk == pytest.approx(0.81 * 0.9 * 0.8)


def test_unexploitable_target_has_no_path():
    env = chain_env()
    env.assets["DB"].vulns.clear()
    assert enumerate_attack_paths(env) == []
    assert total_risk(env) == 0.0


def test_missing_link_breaks_path():
    env = chain_env()
    env.links.clear()
    assert enumerate_attack_paths(env) == []


def test_at_risk_threshold_uses_probability():
    assert at_risk_assets(chain_env()) == {"DB"}


def test_unknown_link_endpoints_are_ignored():
    env = chain_env()
    env.add_link("GHOST", "DB")
    env.add_link("WEB", "GHOST")
    assert total_risk(env) == pytest.approx(total_risk(chain_env()))


def test_model_warnings_flag_silent_failure_modes():
    assert model_warnings(chain_env()) == []
    no_entry = chain_env()
    no_entry.assets["WEB"].internet_exposed = False
    assert any("internet-exposed" in w for w in model_warnings(no_entry))
    downgraded = chain_env()
    downgraded.assets["DB"].criticality = "low"
    assert any("high-criticality" in w for w in model_warnings(downgraded))
    ghost = chain_env()
    ghost.add_link("WEB", "GHOST")
    assert any("GHOST" in w for w in model_warnings(ghost))
