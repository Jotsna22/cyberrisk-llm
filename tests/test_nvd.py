import json
import re
from importlib import resources

import pytest

from cyberrisk.models import Vulnerability
from cyberrisk.nvd import _pick_metric, load_nvd_file, parse_nvd, real_catalog, vulnerability_from_nvd
from cyberrisk.synthetic import CVE_CATALOG, TEMPLATES, generate_environment


def _cve(cve_id, metrics):
    return {"cve": {"id": cve_id, "metrics": metrics}}


def _metric(score, av, pr, kind="Primary"):
    return {"type": kind, "cvssData": {"baseScore": score, "attackVector": av, "privilegesRequired": pr}}


def test_parse_maps_vector_and_privilege():
    doc = {"vulnerabilities": [_cve("CVE-2000-0001", {"cvssMetricV31": [_metric(9.8, "NETWORK", "NONE")]})]}
    vulns, skipped = parse_nvd(doc)
    assert vulns == [Vulnerability("CVE-2000-0001", 9.8, "network", "none")]
    assert skipped == []


@pytest.mark.parametrize("nvd,model", [
    ("ADJACENT_NETWORK", "adjacent"), ("ADJACENT", "adjacent"), ("LOCAL", "local"), ("PHYSICAL", "local"),
])
def test_attack_vector_mapping(nvd, model):
    v = vulnerability_from_nvd(_cve("CVE-2000-0002", {"cvssMetricV31": [_metric(5.0, nvd, "LOW")]})["cve"])
    assert v.attack_vector == model and v.privilege == "low"


def test_prefers_v31_then_v30_and_primary_source():
    both = {"cvssMetricV30": [_metric(5.0, "LOCAL", "HIGH")], "cvssMetricV31": [_metric(9.0, "NETWORK", "NONE")]}
    assert vulnerability_from_nvd(_cve("CVE-2000-0003", both)["cve"]).cvss == 9.0
    only30 = {"cvssMetricV30": [_metric(5.0, "LOCAL", "HIGH")]}
    assert vulnerability_from_nvd(_cve("CVE-2000-0003", only30)["cve"]).cvss == 5.0
    two = {"cvssMetricV31": [_metric(4.0, "LOCAL", "LOW", "Secondary"), _metric(8.0, "NETWORK", "LOW", "Primary")]}
    assert vulnerability_from_nvd(_cve("CVE-2000-0003", two)["cve"]).cvss == 8.0


def test_records_without_cvss_v3_are_skipped_and_reported():
    doc = {"vulnerabilities": [_cve("CVE-2000-0004", {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}),
                               _cve("CVE-2000-0005", {})]}
    vulns, skipped = parse_nvd(doc)
    assert vulns == [] and skipped == ["CVE-2000-0004", "CVE-2000-0005"]


def test_unknown_vector_raises_instead_of_guessing():
    with pytest.raises(KeyError):
        vulnerability_from_nvd(_cve("CVE-2000-0006", {"cvssMetricV31": [_metric(5.0, "TELEPATHIC", "NONE")]})["cve"])


def test_bundled_sample_is_well_formed():
    vulns = load_nvd_file()
    assert len(vulns) >= 20
    ids = [v.cve_id for v in vulns]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"CVE-\d{4}-\d{4,}", i) for i in ids)
    assert {v.attack_vector for v in vulns} == {"network", "adjacent", "local"}


def test_sample_vector_strings_agree_with_parsed_fields():
    text = resources.files("cyberrisk").joinpath("data/nvd_sample.json").read_text()
    vector = {"N": {"NETWORK"}, "A": {"ADJACENT_NETWORK", "ADJACENT"}, "L": {"LOCAL"}}
    privilege = {"N": "NONE", "L": "LOW", "H": "HIGH"}
    for item in json.loads(text)["vulnerabilities"]:
        data = _pick_metric(item["cve"]["metrics"])  # live NVD records may carry v3.1 or only v3.0
        assert data is not None, item["cve"]["id"]
        vec = dict(part.split(":") for part in data["vectorString"].split("/")[1:])
        assert data["attackVector"] in vector[vec["AV"]]
        assert data["privilegesRequired"] == privilege[vec["PR"]]


def test_vector_string_check_accepts_v30_only_records():
    cve = {"id": "CVE-2000-0007", "metrics": {"cvssMetricV30": [
        {"type": "Primary", "cvssData": {"vectorString": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                          "attackVector": "NETWORK", "privilegesRequired": "LOW", "baseScore": 8.8}}]}}
    assert _pick_metric(cve["metrics"])["vectorString"].startswith("CVSS:3.0/")
    assert vulnerability_from_nvd(cve) == Vulnerability("CVE-2000-0007", 8.8, "network", "low")


def test_real_catalog_matches_synthetic_layout():
    cat = real_catalog()
    assert all(len(row) == 4 for row in cat)
    assert all(row[0].startswith("CVE-") for row in cat)
    assert all(row[0].startswith("SYN-CVE-") for row in CVE_CATALOG)


def test_generate_environment_default_unchanged_and_real_option():
    default = generate_environment("hpc", 3)
    assert generate_environment("hpc", 3, catalog=None).assets.keys() == default.assets.keys()
    assert all(cve.startswith("SYN-CVE-") for a in default.assets.values() for cve in a.vulns)
    real = generate_environment("hpc", 3, catalog=real_catalog())
    assert all(cve.startswith("CVE-") for a in real.assets.values() for cve in a.vulns)
    assert all(a.vulns for a in real.assets.values())  # every asset still carries a weakness


@pytest.mark.parametrize("template", sorted(TEMPLATES))
def test_real_environments_are_deterministic(template):
    a = generate_environment(template, 1, catalog=real_catalog())
    b = generate_environment(template, 1, catalog=real_catalog())
    assert {n: sorted(x.vulns) for n, x in a.assets.items()} == {n: sorted(x.vulns) for n, x in b.assets.items()}
