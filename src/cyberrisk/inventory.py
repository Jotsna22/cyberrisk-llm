"""Trusted-inventory check for extracted models.

An LLM extractor reads whatever text it is given, so a planted line such as "host X no
longer accepts traffic from the internet" can flip a label in the extracted model. The
planner then trusts that label. Exposure and business criticality are facts that normally
live in an authoritative asset inventory (a CMDB), not in free-form report text, so this
module lets the inventory overrule the extractor on exactly those two fields.

`reconcile` compares an extracted model with the inventory:

* for every asset listed in the inventory, `internet_exposed` and `criticality` must match;
  a mismatch is recorded as a `Discrepancy` and (with `correct=True`) overwritten;
* assets in the model that the inventory does not list are left alone and reported as
  `unlisted` (an incomplete inventory must not delete assets);
* assets in the inventory that the model lacks are reported as `missing` (nothing is added,
  because the inventory does not say what vulnerabilities or links they have);
* links and vulnerabilities are never touched: the inventory is no authority on them.

The check is only as good as the inventory. A stale or wrong entry overrides a correct
extraction, so `degrade_inventory` exists to measure that.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .models import CRITICALITY_VALUE, Environment

FIELDS = ("internet_exposed", "criticality")


@dataclass(frozen=True)
class InventoryEntry:
    internet_exposed: bool
    criticality: str

    def __post_init__(self) -> None:
        if self.criticality not in CRITICALITY_VALUE:
            raise ValueError(f"unknown criticality {self.criticality!r}")


@dataclass
class Inventory:
    entries: dict[str, InventoryEntry] = field(default_factory=dict)

    @classmethod
    def from_environment(cls, env: Environment) -> "Inventory":
        """An exact inventory of `env` (what a well-kept CMDB would say)."""
        return cls({n: InventoryEntry(a.internet_exposed, a.criticality) for n, a in env.assets.items()})

    def __len__(self) -> int:
        return len(self.entries)


@dataclass(frozen=True)
class Discrepancy:
    asset: str
    field: str  # "internet_exposed" or "criticality"
    model_value: object
    inventory_value: object

    def describe(self) -> str:
        return f"{self.asset}: {self.field} is {self.model_value!r} in the extracted model, {self.inventory_value!r} in the inventory"


@dataclass
class Reconciliation:
    model: Environment
    discrepancies: list[Discrepancy] = field(default_factory=list)
    unlisted: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def flagged(self, asset: str, field_name: str | None = None) -> bool:
        return any(d.asset == asset and (field_name is None or d.field == field_name) for d in self.discrepancies)


def reconcile(model: Environment, inventory: Inventory, correct: bool = True) -> Reconciliation:
    """Compare `model` with `inventory`. The input model is never modified.

    With `correct=False` the returned model is an unchanged copy and only the findings are
    reported (the "flag only" policy).
    """
    result = model.copy()
    discrepancies: list[Discrepancy] = []
    for name in sorted(inventory.entries):
        entry = inventory.entries[name]
        asset = result.assets.get(name)
        if asset is None:
            continue
        for field_name in FIELDS:
            have, want = getattr(asset, field_name), getattr(entry, field_name)
            if have != want:
                discrepancies.append(Discrepancy(name, field_name, have, want))
                if correct:
                    setattr(asset, field_name, want)
    return Reconciliation(
        model=result,
        discrepancies=discrepancies,
        unlisted=sorted(set(model.assets) - set(inventory.entries)),
        missing=sorted(set(inventory.entries) - set(model.assets)),
    )


def degrade_inventory(inventory: Inventory, coverage: float = 1.0, stale: float = 0.0,
                      seed: str = "inventory") -> Inventory:
    """An imperfect inventory, for measuring how much the check depends on it.

    coverage : fraction of assets the inventory lists at all (a random subset)
    stale    : fraction of the *listed* assets whose entry is wrong (exposure flipped and
               criticality changed), as if the CMDB had not been updated
    """
    if not 0.0 <= coverage <= 1.0 or not 0.0 <= stale <= 1.0:
        raise ValueError("coverage and stale must be between 0 and 1")
    rng = random.Random(seed)
    names = sorted(inventory.entries)
    listed = sorted(rng.sample(names, round(coverage * len(names))))
    wrong = set(rng.sample(listed, round(stale * len(listed))))
    entries: dict[str, InventoryEntry] = {}
    for name in listed:
        entry = inventory.entries[name]
        if name in wrong:
            entry = InventoryEntry(not entry.internet_exposed, "low" if entry.criticality == "high" else "high")
        entries[name] = entry
    return Inventory(entries)
