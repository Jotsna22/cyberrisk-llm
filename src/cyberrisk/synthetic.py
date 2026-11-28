"""Synthetic research environments and the analyst-style text reports that describe them.

All assets, CVE identifiers and scores here are fictional. The CVE IDs use
the prefix SYN-CVE so they cannot be mistaken for real NVD entries.
"""

from __future__ import annotations

import random

from .models import Asset, Environment, Vulnerability

# (cve_id, cvss, attack_vector, privilege)
CVE_CATALOG: list[tuple[str, float, str, str]] = [
    ("SYN-CVE-0001", 9.8, "network", "none"),
    ("SYN-CVE-0002", 9.1, "network", "none"),
    ("SYN-CVE-0003", 8.8, "network", "low"),
    ("SYN-CVE-0004", 8.1, "network", "none"),
    ("SYN-CVE-0005", 7.5, "network", "none"),
    ("SYN-CVE-0006", 7.2, "network", "low"),
    ("SYN-CVE-0007", 8.8, "adjacent", "none"),
    ("SYN-CVE-0008", 7.8, "local", "low"),
    ("SYN-CVE-0009", 7.8, "local", "none"),
    ("SYN-CVE-0010", 6.5, "network", "high"),
    ("SYN-CVE-0011", 5.5, "local", "low"),
    ("SYN-CVE-0012", 4.3, "adjacent", "high"),
]

# (name, kind, criticality, internet_exposed)

TEMPLATES: dict[str, dict] = {
    "small_lab": {
        "assets": [
            ("WEB-01", "web", "low", True),
            ("APP-01", "app", "medium", False),
            ("DB-01", "db", "high", False),
            ("FS-01", "research-data", "high", False),
            ("WS-01", "workstation", "low", False),
            ("MON-01", "monitor", "medium", False),
        ],
        "links": [
            ("WEB-01", "APP-01"),
            ("APP-01", "DB-01"),
            ("APP-01", "FS-01"),
            ("WS-01", "APP-01"),
            ("MON-01", "DB-01"),
            ("WS-01", "FS-01"),
        ],
    },
    "hpc": {
        "assets": [
            ("LOGIN-01", "login", "low", True),
            ("LDAP-01", "directory", "high", False),
            ("SCHED-01", "scheduler", "medium", False),
            ("CN-01", "compute", "medium", False),
            ("CN-02", "compute", "medium", False),
            ("CN-03", "compute", "low", False),
            ("STOR-01", "research-data", "high", False),
            ("BKP-01", "backup", "high", False),
        ],
        "links": [
            ("LOGIN-01", "SCHED-01"),
            ("LOGIN-01", "CN-01"),
            ("LOGIN-01", "LDAP-01"),
            ("SCHED-01", "CN-01"),
            ("SCHED-01", "CN-02"),
            ("SCHED-01", "CN-03"),
            ("CN-01", "STOR-01"),
            ("CN-02", "STOR-01"),
            ("CN-03", "STOR-01"),
            ("STOR-01", "BKP-01"),
        ],
    },
    "cloud": {
        "assets": [
            ("LB-01", "loadbalancer", "low", True),
            ("WEB-01", "web", "low", False),
            ("API-01", "api", "medium", False),
            ("AUTH-01", "auth", "high", False),
            ("DB-01", "db", "high", False),
            ("VAULT-01", "secrets", "high", False),
            ("DATA-01", "research-data", "high", False),
        ],
        "links": [
            ("LB-01", "WEB-01"),
            ("WEB-01", "API-01"),
            ("API-01", "AUTH-01"),
            ("API-01", "DB-01"),
            ("AUTH-01", "VAULT-01"),
            ("DB-01", "DATA-01"),
            ("API-01", "DATA-01"),
        ],
    },
    "distributed": {
        "assets": [
            ("GW-A", "gateway", "low", True),
            ("GW-B", "gateway", "low", True),
            ("SITE-A-DB", "db", "medium", False),
            ("SITE-B-DB", "db", "medium", False),
            ("SYNC-01", "sync", "medium", False),
            ("CORE-DB", "db", "high", False),
            ("RES-DATA", "research-data", "high", False),
        ],
        "links": [
            ("GW-A", "SITE-A-DB"),
            ("GW-B", "SITE-B-DB"),
            ("SITE-A-DB", "SYNC-01"),
            ("SITE-B-DB", "SYNC-01"),
            ("SYNC-01", "CORE-DB"),
            ("CORE-DB", "RES-DATA"),
        ],
    },
}

AV_PHRASE = {"network": "over the network", "adjacent": "from the same network segment", "local": "only with local access"}
PRIV_PHRASE = {"none": "no credentials", "low": "a low-privilege account", "high": "administrative privileges"}
DISTRACTORS = [
    "Quarterly review meeting moved to Thursday.",
    "Patch window for lab systems is still under discussion.",
    "Backups run nightly at 02:00.",
    "This inventory was last audited last quarter.",
]


def generate_environment(
    template: str, seed: int, catalog: list[tuple[str, float, str, str]] | None = None
) -> Environment:
    """Deterministically build one environment from a topology template and a seed.

    `catalog` is the pool of (cve_id, cvss, attack_vector, privilege) to draw from; the
    default is the synthetic SYN-CVE catalog. Pass `nvd.real_catalog()` for real CVEs.
    """
    pool = catalog if catalog is not None else CVE_CATALOG
    spec = TEMPLATES[template]
    rng = random.Random(f"{template}-{seed}")
    env = Environment(name=f"{template}-seed{seed}")
    for name, kind, crit, exposed in spec["assets"]:
        env.add_asset(Asset(name=name, kind=kind, criticality=crit, internet_exposed=exposed))
    for src, dst in spec["links"]:
        env.add_link(src, dst)
    for asset in env.assets.values():
        count = rng.choice([1, 2, 2, 3])  # every asset carries at least one weakness
        if asset.internet_exposed:
            count = max(count, 2)
        for cve, cvss, av, priv in rng.sample(pool, count):
            asset.add_vulnerability(Vulnerability(cve, cvss, av, priv))
    return env


def _asset_line(rng: random.Random, asset: Asset) -> str:
    variant = rng.randrange(3)
    if variant == 0:
        return f"Asset {asset.name} is a {asset.kind} with {asset.criticality} business criticality."
    if variant == 1:
        return f"{asset.name} ({asset.kind}) is rated {asset.criticality} criticality for the research mission."
    return f"The {asset.kind} {asset.name} carries {asset.criticality} business criticality in the inventory."


def _exposure_line(rng: random.Random, name: str) -> str:
    variant = rng.randrange(3)
    if variant == 0:
        return f"{name} is internet-facing."
    if variant == 1:
        return f"{name} accepts connections from the public internet."
    return f"Public internet clients can open sessions to {name}."


def _vuln_line(rng: random.Random, name: str, vuln: Vulnerability) -> str:
    variant = rng.randrange(3)
    if variant == 0:
        return (
            f"{name} has {vuln.cve_id} (CVSS {vuln.cvss:.1f}). "
            f"Attack vector: {vuln.attack_vector}. Privilege required: {vuln.privilege}."
        )
    if variant == 1:
        return (
            f"{vuln.cve_id} affects {name} with a CVSS score of {vuln.cvss:.1f}; "
            f"it is exploitable {AV_PHRASE[vuln.attack_vector]} and needs {PRIV_PHRASE[vuln.privilege]}."
        )
    return (
        f"Scanner finding on {name}: {vuln.cve_id}, scored {vuln.cvss:.1f}, "
        f"exploitable {AV_PHRASE[vuln.attack_vector]}, needing {PRIV_PHRASE[vuln.privilege]}."
    )


def _link_line(rng: random.Random, src: str, dst: str) -> str:
    variant = rng.randrange(3)
    if variant == 0:
        return f"{src} can reach {dst} over the internal network."
    if variant == 1:
        return f"Firewall rules allow {src} to connect to {dst}."
    return f"Traffic from {src} to {dst} is permitted."


def render_report(env: Environment, seed: int) -> str:
    """Render the environment as an analyst-style text report with mixed phrasings.

    Each fact is one line. Roughly one third of facts use the canonical
    phrasing that the rule-based extractor understands; the rest are
    paraphrases. Distractor lines are mixed in.
    """
    rng = random.Random(f"report-{env.name}-{seed}")
    lines: list[str] = []
    for name in sorted(env.assets):
        asset = env.assets[name]
        lines.append(_asset_line(rng, asset))
        if asset.internet_exposed:
            lines.append(_exposure_line(rng, name))
        for vuln in asset.vulns.values():
            lines.append(_vuln_line(rng, name, vuln))
    for src, dst in sorted(env.links):
        lines.append(_link_line(rng, src, dst))
    for distractor in rng.sample(DISTRACTORS, 2):
        lines.append(distractor)
    rng.shuffle(lines)
    return "\n".join(lines) + "\n"
