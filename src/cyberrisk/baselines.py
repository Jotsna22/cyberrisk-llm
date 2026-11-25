"""Non-graph baselines for the evaluation.

Both baselines use the vulnerability scanner output and asset inventory
(the ground-truth environment's vulnerabilities and exposure flags), but
neither reasons about network topology. They therefore represent what a
team could do without attack-path analysis.
"""

from __future__ import annotations

from .defense import Control, PATCH_COST
from .models import Environment


def _all_patches(env: Environment) -> list[tuple[float, str, str]]:
    rows = []
    for name, asset in env.assets.items():
        for cve, vuln in asset.vulns.items():
            rows.append((vuln.cvss, name, cve))
    return rows


def cvss_only_plan(env: Environment, budget: float) -> list[Control]:
    """Patch the highest-CVSS vulnerabilities first, ignoring exposure and topology."""
    rows = sorted(_all_patches(env), key=lambda r: (-r[0], r[1], r[2]))
    return _take(rows, budget)


def rule_based_plan(env: Environment, budget: float) -> list[Control]:
    """Predefined rules: exposed assets with CVSS >= 7 first, then all others by CVSS."""

    def priority(row: tuple[float, str, str]) -> tuple[int, float, str, str]:
        cvss, name, cve = row
        urgent = env.assets[name].internet_exposed and cvss >= 7.0
        return (0 if urgent else 1, -cvss, name, cve)

    rows = sorted(_all_patches(env), key=priority)
    return _take(rows, budget)


def _take(rows: list[tuple[float, str, str]], budget: float) -> list[Control]:
    chosen: list[Control] = []
    spent = 0.0
    for _, name, cve in rows:
        if spent + PATCH_COST > budget + 1e-9:
            break
        chosen.append(Control("patch", (name, cve)))
        spent += PATCH_COST
    return chosen
