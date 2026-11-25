"""Core data model for CyberRisk-LLM.

An Environment is a set of assets, the directed network links that the
firewall permits between them, and the vulnerabilities present on each
asset. The attack graph, risk engine and defense planner all operate on
this model, whether it came from ground truth or from text extraction.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field

INTERNET = "Internet"

ATTACK_VECTOR_FACTOR = {"network": 0.9, "adjacent": 0.5, "local": 0.1}
PRIVILEGE_FACTOR = {"none": 1.0, "low": 0.7, "high": 0.4}
CRITICALITY_VALUE = {"low": 0.3, "medium": 0.6, "high": 0.9}
CRITICAL_THRESHOLD = 0.8


@dataclass(frozen=True)
class Vulnerability:
    """A single CVE-style weakness on an asset."""

    cve_id: str
    cvss: float  # CVSS base score, 0-10
    attack_vector: str  # network | adjacent | local
    privilege: str  # privilege the attacker needs: none | low | high

    def __post_init__(self) -> None:
        if not 0.0 <= self.cvss <= 10.0:
            raise ValueError(f"{self.cve_id}: CVSS {self.cvss} outside 0-10")
        if self.attack_vector not in ATTACK_VECTOR_FACTOR:
            raise ValueError(f"{self.cve_id}: unknown attack vector {self.attack_vector!r}")
        if self.privilege not in PRIVILEGE_FACTOR:
            raise ValueError(f"{self.cve_id}: unknown privilege {self.privilege!r}")

    @property
    def exploitability(self) -> float:
        """Probability-like score that one exploitation attempt succeeds."""
        return ATTACK_VECTOR_FACTOR[self.attack_vector] * PRIVILEGE_FACTOR[self.privilege]

    @property
    def impact(self) -> float:
        return self.cvss / 10.0


@dataclass
class Asset:
    name: str
    kind: str
    criticality: str  # low | medium | high
    internet_exposed: bool = False
    vulns: dict[str, Vulnerability] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.criticality not in CRITICALITY_VALUE:
            raise ValueError(f"{self.name}: unknown criticality {self.criticality!r}")

    @property
    def criticality_value(self) -> float:
        return CRITICALITY_VALUE[self.criticality]

    @property
    def is_critical(self) -> bool:
        return self.criticality_value >= CRITICAL_THRESHOLD

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulns[vuln.cve_id] = vuln


@dataclass
class Environment:
    name: str
    assets: dict[str, Asset] = field(default_factory=dict)
    links: set[tuple[str, str]] = field(default_factory=set)  # permitted src -> dst

    def add_asset(self, asset: Asset) -> None:
        self.assets[asset.name] = asset

    def add_link(self, src: str, dst: str) -> None:
        self.links.add((src, dst))

    def critical_assets(self) -> list[str]:
        return sorted(a.name for a in self.assets.values() if a.is_critical)

    def copy(self) -> "Environment":
        return deepcopy(self)
