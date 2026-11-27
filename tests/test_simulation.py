import pytest

from cyberrisk.defense import apply_plan, greedy_recommend
from cyberrisk.graph import enumerate_attack_paths
from cyberrisk.models import Asset, Environment, Vulnerability
from cyberrisk.simulation import simulate_attacks
from cyberrisk.synthetic import generate_environment


def chain_env() -> Environment:
    env = Environment("chain")
    env.add_asset(Asset("WEB", "web", "low", internet_exposed=True))
    env.add_asset(Asset("DB", "db", "high"))
    env.assets["WEB"].add_vulnerability(Vulnerability("V1", 9.8, "network", "none"))
    env.assets["DB"].add_vulnerability(Vulnerability("V2", 8.0, "network", "none"))
    env.add_link("WEB", "DB")
    return env


def test_chain_matches_hand_calculation():
    out = simulate_attacks(chain_env())
    assert out.method == "exact"
    assert out.attack_success == pytest.approx(0.81)
    assert out.critical_compromised == pytest.approx(0.81)
    assert out.expected_loss == pytest.approx(0.81 * 0.9 * 0.8)
    assert out.compromise_probability == {"DB": pytest.approx(0.81)}


def test_second_route_raises_compromise_probability_above_worst_path():
    """The risk engine scores only the worst path; the simulation counts every route."""
    env = chain_env()
    env.add_asset(Asset("VPN", "vpn", "low", internet_exposed=True))
    env.assets["VPN"].add_vulnerability(Vulnerability("V3", 9.8, "network", "none"))
    env.add_link("VPN", "DB")
    best_path = max(p.probability for p in enumerate_attack_paths(env))
    out = simulate_attacks(env)
    assert best_path == pytest.approx(0.81)
    # P(reach DB) = 1 - (1 - 0.81)^2 when both routes are independent and equally likely
    assert out.attack_success == pytest.approx(1 - 0.19 ** 2)


def test_no_entry_point_means_no_compromise():
    env = chain_env()
    env.assets["WEB"].internet_exposed = False
    out = simulate_attacks(env)
    assert out.attack_success == 0.0 and out.expected_loss == 0.0


def test_monte_carlo_agrees_with_exact():
    env = generate_environment("hpc", 3)
    exact = simulate_attacks(env)
    mc = simulate_attacks(env, runs=40_000, exact_max_edges=0)
    assert exact.method == "exact" and mc.method == "monte_carlo"
    assert mc.attack_success == pytest.approx(exact.attack_success, abs=0.01)
    assert mc.expected_loss == pytest.approx(exact.expected_loss, rel=0.02)


def test_monte_carlo_is_reproducible():
    env = generate_environment("cloud", 5)
    a = simulate_attacks(env, runs=2000, exact_max_edges=0)
    b = simulate_attacks(env, runs=2000, exact_max_edges=0)
    assert a == b


def test_defense_plan_lowers_simulated_loss():
    for template, seed in (("small_lab", 0), ("hpc", 1), ("cloud", 2), ("distributed", 3)):
        env = generate_environment(template, seed)
        after = apply_plan(env, greedy_recommend(env, 4.0))
        assert simulate_attacks(after).expected_loss <= simulate_attacks(env).expected_loss + 1e-12
