"""Scoring helpers: set precision/recall/F1 and path-ranking precision."""

from __future__ import annotations

from typing import Hashable, Iterable

from .graph import AttackPath
from .models import Environment


def prf(predicted: Iterable[Hashable], truth: Iterable[Hashable]) -> tuple[float, float, float]:
    pred, gold = set(predicted), set(truth)
    if not gold and not pred:
        return 1.0, 1.0, 1.0
    tp = len(pred & gold)
    precision = tp / len(pred) if pred else 0.0
    recall = tp / len(gold) if gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def extraction_facts(env: Environment) -> dict[str, set]:
    """Flatten an environment into comparable fact sets."""
    return {
        "assets": set(env.assets),
        "exposed": {n for n, a in env.assets.items() if a.internet_exposed},
        "vulns": {(n, cve) for n, a in env.assets.items() for cve in a.vulns},
        "links": set(env.links),
    }


def attribute_accuracy(predicted: Environment, truth: Environment) -> dict[str, float | None]:
    """Accuracy of attribute values on facts both models contain.

    Set F1 only checks that an asset or (asset, CVE) pair was found. It cannot see an
    extractor that finds DB-01 but labels it low criticality, or records the wrong CVSS
    or attack vector. Those errors change the risk score, so they are scored here.
    None means no fact was shared, so accuracy is undefined.
    """
    shared_assets = [n for n in truth.assets if n in predicted.assets]
    crit_ok = sum(predicted.assets[n].criticality == truth.assets[n].criticality for n in shared_assets)
    shared_vulns = [
        (n, cve) for n in shared_assets for cve in truth.assets[n].vulns if cve in predicted.assets[n].vulns
    ]
    vuln_ok = 0
    for n, cve in shared_vulns:
        pv, tv = predicted.assets[n].vulns[cve], truth.assets[n].vulns[cve]
        vuln_ok += (abs(pv.cvss - tv.cvss) < 0.05 and pv.attack_vector == tv.attack_vector
                    and pv.privilege == tv.privilege)
    return {
        "criticality_acc": crit_ok / len(shared_assets) if shared_assets else None,
        "vuln_attr_acc": vuln_ok / len(shared_vulns) if shared_vulns else None,
    }


def extraction_scores(predicted: Environment, truth: Environment) -> dict[str, float | None]:
    p, t = extraction_facts(predicted), extraction_facts(truth)
    out: dict[str, float | None] = {}
    for key in ("assets", "exposed", "vulns", "links"):
        precision, recall, f1 = prf(p[key], t[key])
        out[f"{key}_precision"] = precision
        out[f"{key}_recall"] = recall
        out[f"{key}_f1"] = f1
    out.update(attribute_accuracy(predicted, truth))
    return out


def top_k_path_precision(predicted: list[AttackPath], truth: list[AttackPath], k: int = 5) -> float:
    """Share of the predicted top-k attack paths that also appear in the true top-k."""
    gold = {p.nodes for p in truth[:k]}
    pred = [p.nodes for p in predicted[:k]]
    if not pred and not gold:
        return 1.0
    if not pred:
        return 0.0
    return sum(1 for nodes in pred if nodes in gold) / len(pred)
