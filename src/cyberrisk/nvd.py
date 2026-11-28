"""Import vulnerabilities from NVD (NIST National Vulnerability Database) JSON.

The parser reads the NVD CVE API 2.0 layout (`vulnerabilities[].cve`) and keeps the
three CVSS v3.x fields the risk engine uses: base score, attack vector and privileges
required. A small sample of well-known CVEs, refreshed from the live NVD, ships with the
package in `data/nvd_sample.json`; `scripts/verify_nvd.py` rechecks it against the live NVD.

When a record lists several CVSS scores, NVD's own (source nvd@nist.gov) is used; see `_pick_entry`.

Mapping into the model's categories:
  attackVector        NETWORK -> network; ADJACENT_NETWORK / ADJACENT -> adjacent;
                      LOCAL / PHYSICAL -> local (the model has no physical category)
  privilegesRequired  NONE / LOW / HIGH -> none / low / high
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from .models import Vulnerability

ATTACK_VECTOR_MAP = {
    "NETWORK": "network",
    "ADJACENT_NETWORK": "adjacent",
    "ADJACENT": "adjacent",
    "LOCAL": "local",
    "PHYSICAL": "local",
}
PRIVILEGE_MAP = {"NONE": "none", "LOW": "low", "HIGH": "high"}
METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30")  # newest first; CVSS v2 has no comparable fields


NVD_SOURCE = "nvd@nist.gov"


def _pick_entry(metrics: dict[str, Any]) -> dict[str, Any] | None:
    """Choose the CVSS v3.x entry to use for a record.

    A record can list several scores, one per source (NVD itself, the CNA that assigned the
    CVE, other CNAs), and the order is not meaningful. In order of preference:
      1. NVD's own score (source nvd@nist.gov), v3.1 before v3.0
      2. an entry typed "Primary"
      3. the first entry
    Taking the first entry is wrong for records that have no "Primary" entry and list a
    vendor's score first: CVE-2020-1472 would read as 5.5 local instead of NVD's 10.0 network.
    """
    entries = [e for key in METRIC_KEYS for e in (metrics.get(key) or [])]
    for entry in entries:
        if entry.get("source") == NVD_SOURCE:
            return entry
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    return entries[0] if entries else None


def _pick_metric(metrics: dict[str, Any]) -> dict[str, Any] | None:
    entry = _pick_entry(metrics)
    return entry["cvssData"] if entry else None


def metric_source(cve: dict[str, Any]) -> str | None:
    """Which source's score `vulnerability_from_nvd` uses for this record."""
    entry = _pick_entry(cve.get("metrics", {}))
    return entry.get("source") if entry else None


def vulnerability_from_nvd(cve: dict[str, Any]) -> Vulnerability | None:
    """Convert one NVD `cve` object. Returns None if it has no CVSS v3.x score."""
    data = _pick_metric(cve.get("metrics", {}))
    if data is None:
        return None
    return Vulnerability(
        cve_id=cve["id"],
        cvss=float(data["baseScore"]),
        attack_vector=ATTACK_VECTOR_MAP[data["attackVector"]],
        privilege=PRIVILEGE_MAP[data["privilegesRequired"]],
    )


def parse_nvd(document: dict[str, Any]) -> tuple[list[Vulnerability], list[str]]:
    """Parse an NVD API 2.0 document. Returns (vulnerabilities, ids skipped for lacking CVSS v3.x)."""
    vulns: list[Vulnerability] = []
    skipped: list[str] = []
    for item in document.get("vulnerabilities", []):
        cve = item["cve"]
        vuln = vulnerability_from_nvd(cve)
        if vuln is None:
            skipped.append(cve["id"])
        else:
            vulns.append(vuln)
    return vulns, skipped


def load_nvd_file(path: str | Path | None = None) -> list[Vulnerability]:
    """Load vulnerabilities from an NVD JSON file (default: the bundled sample)."""
    if path is None:
        text = resources.files("cyberrisk").joinpath("data/nvd_sample.json").read_text()
    else:
        text = Path(path).read_text()
    vulns, _ = parse_nvd(json.loads(text))
    return vulns


def real_catalog(path: str | Path | None = None) -> list[tuple[str, float, str, str]]:
    """Real CVEs in the same tuple layout as `synthetic.CVE_CATALOG`."""
    return [(v.cve_id, v.cvss, v.attack_vector, v.privilege) for v in load_nvd_file(path)]
