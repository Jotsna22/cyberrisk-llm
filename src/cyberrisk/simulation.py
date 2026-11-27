"""Attacker simulation on an environment: attack success, critical assets compromised, expected loss.

The risk engine in graph.py scores each critical asset by its single worst attack path.
That is a ranking score, not a probability of compromise: a second route to the same
asset adds nothing to it, so blocking that route also gains nothing. This module asks
a different question: if an attacker starts on the Internet and tries every exploit
available to them, what actually gets compromised?

Model (independent-cascade attacker):
  * The attacker starts at the Internet node.
  * Every edge u -> v of the attack graph is one exploitation attempt. It succeeds
    independently with the edge's probability (the best exploitability on v).
  * The attacker compromises every asset reachable from the Internet over succeeded
    edges. Path length is unlimited and every route counts.

Outcomes per run, averaged over runs:
  * attack_success       - 1 if at least one critical asset is compromised
  * critical_compromised - number of critical assets compromised
  * loss                 - sum over compromised critical assets of criticality x worst
                           CVSS impact (the same weighting the risk engine uses)

Graphs with at most EXACT_MAX_EDGES edges (all environments here) are evaluated
exactly, by enumerating every success/failure combination of the edges. Larger graphs
fall back to Monte Carlo with a fixed seed, so results are always reproducible.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .graph import build_attack_graph
from .models import INTERNET, Environment

EXACT_MAX_EDGES = 16
DEFAULT_RUNS = 20_000


@dataclass(frozen=True)
class AttackOutcome:
    attack_success: float  # P(at least one critical asset is compromised)
    critical_compromised: float  # expected number of critical assets compromised
    expected_loss: float  # E[sum of criticality x impact over compromised critical assets]
    compromise_probability: dict[str, float]  # per critical asset
    method: str  # "exact" or "monte_carlo"


def _loss_weight(env: Environment, name: str) -> float:
    asset = env.assets[name]
    return asset.criticality_value * max((v.impact for v in asset.vulns.values()), default=0.0)


def simulate_attacks(env: Environment, runs: int = DEFAULT_RUNS, seed: int = 0,
                     exact_max_edges: int = EXACT_MAX_EDGES) -> AttackOutcome:
    graph = build_attack_graph(env)
    critical = env.critical_assets()
    edges = sorted((u, v, d["p"]) for u, v, d in graph.edges(data=True))
    nodes = sorted(graph.nodes)
    index = {n: i for i, n in enumerate(nodes)}
    edge_ix = [(index[u], index[v], p) for u, v, p in edges]
    start = index[INTERNET]
    critical_ix = [index[c] for c in critical if c in index]
    weights = {index[c]: _loss_weight(env, c) for c in critical if c in index}

    def reached(is_open: list[bool]) -> set[int]:
        adjacency: dict[int, list[int]] = {}
        for (u, v, _), ok in zip(edge_ix, is_open):
            if ok:
                adjacency.setdefault(u, []).append(v)
        seen, stack = {start}, [start]
        while stack:
            for nxt in adjacency.get(stack.pop(), ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    per_asset = {c: 0.0 for c in critical_ix}
    success = compromised = loss = 0.0

    def record(seen: set[int], weight: float) -> None:
        nonlocal success, compromised, loss
        hit = [c for c in critical_ix if c in seen]
        if hit:
            success += weight
        compromised += weight * len(hit)
        loss += weight * sum(weights[c] for c in hit)
        for c in hit:
            per_asset[c] += weight

    if len(edge_ix) <= exact_max_edges:
        method = "exact"
        probs = [p for _, _, p in edge_ix]
        for mask in range(1 << len(edge_ix)):
            is_open = [bool(mask >> i & 1) for i in range(len(edge_ix))]
            weight = 1.0
            for ok, p in zip(is_open, probs):
                weight *= p if ok else 1.0 - p
            if weight > 0.0:
                record(reached(is_open), weight)
    else:
        method = "monte_carlo"
        rng = random.Random(f"attack-sim-{env.name}-{seed}")
        for _ in range(runs):
            record(reached([rng.random() < p for _, _, p in edge_ix]), 1.0 / runs)

    return AttackOutcome(
        attack_success=success,
        critical_compromised=compromised,
        expected_loss=loss,
        compromise_probability={nodes[c]: per_asset[c] for c in critical_ix},
        method=method,
    )
