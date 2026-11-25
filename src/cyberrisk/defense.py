"""Defense planning: candidate controls, greedy selection and simulation.

Two control types are considered:
  * patch  - remove one vulnerability from one asset (cost 1)
  * block  - remove one permitted network link, e.g. a firewall rule (cost 2)

The planner optimizes on whatever model it is given (ground truth or an
extracted model). Its output is then simulated on the ground-truth
environment, so extraction errors show up as wasted or missing controls.
"""

from __future__ import annotations

from dataclasses import dataclass

from .graph import total_risk
from .models import Environment

PATCH_COST = 1.0
BLOCK_COST = 2.0


@dataclass(frozen=True)
class Control:
    kind: str  # "patch" or "block"
    target: tuple[str, ...]  # (asset, cve_id) for patch, (src, dst) for block

    @property
    def cost(self) -> float:
        return PATCH_COST if self.kind == "patch" else BLOCK_COST

    def describe(self) -> str:
        if self.kind == "patch":
            return f"patch {self.target[0]} for {self.target[1]}"
        return f"block {self.target[0]} -> {self.target[1]}"


def apply_control(env: Environment, control: Control) -> Environment:
    new = env.copy()
    if control.kind == "patch":
        asset, cve = control.target
        if asset in new.assets:
            new.assets[asset].vulns.pop(cve, None)
    else:
        new.links.discard(control.target)  # type: ignore[arg-type]
    return new


def apply_plan(env: Environment, controls: list[Control]) -> Environment:
    for control in controls:
        env = apply_control(env, control)
    return env


def candidate_controls(env: Environment) -> list[Control]:
    controls = []
    for name in sorted(env.assets):
        for cve in sorted(env.assets[name].vulns):
            controls.append(Control("patch", (name, cve)))
    for src, dst in sorted(env.links):
        controls.append(Control("block", (src, dst)))
    return controls


def greedy_recommend(model: Environment, budget: float) -> list[Control]:
    """Pick controls that maximize risk reduction per unit cost until the budget is spent."""
    chosen: list[Control] = []
    spent = 0.0
    current = model
    current_risk = total_risk(current)
    candidates = candidate_controls(model)
    while True:
        best: Control | None = None
        best_ratio = 0.0
        best_risk = current_risk
        for control in candidates:
            if control in chosen or spent + control.cost > budget + 1e-9:
                continue
            trial_risk = total_risk(apply_control(current, control))
            gain = current_risk - trial_risk
            if gain <= 1e-12:
                continue
            ratio = gain / control.cost
            if ratio > best_ratio:
                best, best_ratio, best_risk = control, ratio, trial_risk
        if best is None:
            break
        chosen.append(best)
        spent += best.cost
        current = apply_control(current, best)
        current_risk = best_risk
    return chosen
