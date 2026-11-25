import pytest

from cyberrisk.models import Asset, Environment, Vulnerability


def test_vulnerability_validation():
    with pytest.raises(ValueError):
        Vulnerability("X", 11.0, "network", "none")
    with pytest.raises(ValueError):
        Vulnerability("X", 5.0, "satellite", "none")
    with pytest.raises(ValueError):
        Vulnerability("X", 5.0, "network", "root")


def test_exploitability_combines_vector_and_privilege():
    v = Vulnerability("X", 9.8, "network", "none")
    assert v.exploitability == pytest.approx(0.9)
    assert Vulnerability("Y", 7.0, "local", "high").exploitability == pytest.approx(0.04)


def test_criticality_threshold():
    assert Asset("a", "db", "high").is_critical
    assert not Asset("b", "web", "medium").is_critical


def test_environment_copy_is_independent():
    env = Environment("e")
    env.add_asset(Asset("a", "web", "low"))
    env.assets["a"].add_vulnerability(Vulnerability("X", 5.0, "network", "none"))
    clone = env.copy()
    clone.assets["a"].vulns.clear()
    assert "X" in env.assets["a"].vulns
