"""Attack graph construction, attack-path enumeration and the risk engine.

Nodes are assets plus a synthetic Internet node. An edge u -> v means an
attacker positioned at u can compromise v, with probability equal to the
best exploitability among v's vulnerabilities. Path probability is the
product of edge probabilities; path risk weighs that probability by the
target's business criticality and by its worst CVSS impact.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .models import INTERNET, Environment

MAX_PATH_EDGES: int | None = None  # longest attack path considered, in hops; None = no limit.
# The environments have at most 8 assets, so enumerating every simple path is cheap. An
# earlier cap of 4 hops silently dropped critical assets 5 hops from the Internet
# (VAULT-01 in cloud, RES-DATA in distributed) from every risk score.
AT_RISK_PROBABILITY = 0.1  # a critical asset is "at risk" if a path reaches it with p >= this


@dataclass(frozen=True)
class AttackPath:
    nodes: tuple[str, ...]
    probability: float
    risk: float

    @property
    def target(self) -> str:
        return self.nodes[-1]


def _step_probability(env: Environment, dst: str) -> float:
    asset = env.assets.get(dst)
    if asset is None or not asset.vulns:
        return 0.0
    return max(v.exploitability for v in asset.vulns.values())


def _target_impact(env: Environment, name: str) -> float:
    asset = env.assets[name]
    return max((v.impact for v in asset.vulns.values()), default=0.0)


def build_attack_graph(env: Environment) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node(INTERNET)
    graph.add_nodes_from(env.assets)
    for name, asset in env.assets.items():
        if asset.internet_exposed:
            p = _step_probability(env, name)
            if p > 0:
                graph.add_edge(INTERNET, name, p=p)
    for src, dst in env.links:
        if src != INTERNET and src not in env.assets:
            continue
        if dst not in env.assets or src == dst:
            continue
        p = _step_probability(env, dst)
        if p > 0:
            graph.add_edge(src, dst, p=p)
    return graph


def enumerate_attack_paths(
    env: Environment, graph: nx.DiGraph | None = None, max_edges: int | None = MAX_PATH_EDGES
) -> list[AttackPath]:
    """All simple Internet-to-critical-asset paths, highest risk first."""
    graph = graph if graph is not None else build_attack_graph(env)
    paths: list[AttackPath] = []
    for target in env.critical_assets():
        if target not in graph:
            continue
        for nodes in nx.all_simple_paths(graph, INTERNET, target, cutoff=max_edges):
            probability = 1.0
            for u, v in zip(nodes, nodes[1:]):
                probability *= graph[u][v]["p"]
            criticality = env.assets[target].criticality_value
            risk = probability * criticality * _target_impact(env, target)
            paths.append(AttackPath(tuple(nodes), probability, risk))
    paths.sort(key=lambda p: (-p.risk, p.nodes))
    return paths


def total_risk(env: Environment) -> float:
    """Sum over critical assets of the worst path risk reaching each one."""
    best: dict[str, float] = {}
    for path in enumerate_attack_paths(env):
        best[path.target] = max(best.get(path.target, 0.0), path.risk)
    return sum(best.values())


def model_warnings(env: Environment) -> list[str]:
    """Sanity checks on a (possibly extracted) model before the planner trusts it.

    The planner fails silently when its input is degenerate: with no entry point or no
    critical asset there is no attack path, so it recommends nothing. These checks turn
    that silent failure into a visible one. They don't prove the model is right.
    """
    warnings: list[str] = []
    if not env.assets:
        return ["model contains no assets"]
    if not any(a.internet_exposed for a in env.assets.values()):
        warnings.append("no internet-exposed asset: no attack path can start")
    if not env.critical_assets():
        warnings.append("no high-criticality asset: nothing for the planner to protect")
    unknown = sorted({n for link in env.links for n in link if n != INTERNET and n not in env.assets})
    if unknown:
        warnings.append(f"links reference assets missing from the inventory: {', '.join(unknown)}")
    no_vulns = sorted(n for n, a in env.assets.items() if not a.vulns)
    if no_vulns and len(no_vulns) == len(env.assets):
        warnings.append("no vulnerabilities on any asset")
    if not warnings and not enumerate_attack_paths(env):
        warnings.append("no attack path reaches any critical asset (check links and exposure)")
    return warnings


def at_risk_assets(env: Environment) -> set[str]:
    """Critical assets reachable by some path with probability >= AT_RISK_PROBABILITY."""
    best: dict[str, float] = {}
    for path in enumerate_attack_paths(env):
        best[path.target] = max(best.get(path.target, 0.0), path.probability)
    return {name for name, p in best.items() if p >= AT_RISK_PROBABILITY}
