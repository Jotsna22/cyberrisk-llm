from cyberrisk.attack_mapping import (
    INITIAL_ACCESS, PRIVILEGE_ESCALATION, REMOTE_SERVICES, map_path, step_vulnerability, technique_for_step,
)
from cyberrisk.graph import enumerate_attack_paths
from cyberrisk.models import INTERNET, Asset, Environment, Vulnerability
from cyberrisk.nvd import real_catalog
from cyberrisk.synthetic import generate_environment

NET = Vulnerability("CVE-1", 9.0, "network", "none")
LOCAL = Vulnerability("CVE-2", 7.0, "local", "low")


def _env():
    env = Environment("t")
    env.add_asset(Asset("WEB", "web", "low", internet_exposed=True, vulns={"CVE-1": NET}))
    env.add_asset(Asset("APP", "app", "medium", vulns={"CVE-1": NET}))
    env.add_asset(Asset("DB", "db", "high", vulns={"CVE-2": LOCAL}))
    env.add_link("WEB", "APP")
    env.add_link("APP", "DB")
    return env


def test_technique_rules():
    assert technique_for_step(INTERNET, NET) is INITIAL_ACCESS
    assert technique_for_step("WEB", NET) is REMOTE_SERVICES
    assert technique_for_step("APP", LOCAL) is PRIVILEGE_ESCALATION
    assert technique_for_step("APP", None) is None


def test_map_path_labels_every_hop():
    steps = map_path(_env(), (INTERNET, "WEB", "APP", "DB"))
    assert [s.technique for s in steps] == [INITIAL_ACCESS, REMOTE_SERVICES, PRIVILEGE_ESCALATION]
    assert [s.vulnerability.cve_id for s in steps] == ["CVE-1", "CVE-1", "CVE-2"]


def test_step_vulnerability_is_the_most_exploitable_then_highest_cvss():
    env = Environment("t")
    weak = Vulnerability("CVE-A", 9.9, "local", "high")
    a = Vulnerability("CVE-B", 7.0, "network", "none")
    b = Vulnerability("CVE-C", 8.0, "network", "none")
    env.add_asset(Asset("X", "x", "low", vulns={"CVE-A": weak, "CVE-B": a, "CVE-C": b}))
    assert step_vulnerability(env, "X").cve_id == "CVE-C"
    assert step_vulnerability(env, "missing") is None


def test_every_attack_path_hop_gets_a_technique_on_real_environments():
    env = generate_environment("cloud", 2, catalog=real_catalog())
    paths = enumerate_attack_paths(env)
    assert paths
    for path in paths:
        assert all(step.technique is not None for step in map_path(env, path.nodes))
