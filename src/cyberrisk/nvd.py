"""Import vulnerabilities from NVD (NIST National Vulnerability Database) JSON.

The parser reads the NVD CVE API 2.0 layout (`vulnerabilities[].cve`) and keeps the
three CVSS v3.x fields the risk engine uses: base score, attack vector and privileges
required. A small sample of well-known CVEs, refreshed from the live NVD, ships with the
package in `data/nvd_sample.json`; `scripts/verify_nvd.py` rechecks it against the live NVD.

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


def _pick_metric(metrics: dict[str, Any]) -> dict[str, Any] | None:
    for key in METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = [e for e in entries if e.get("type") == "Primary"]
        return (primary or entries)[0]["cvssData"]
    return None


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
