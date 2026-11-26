from cyberrisk.metrics import attribute_accuracy, extraction_scores, prf
from cyberrisk.synthetic import generate_environment


def test_prf_basic():
    p, r, f = prf({"a", "b", "c"}, {"a", "b", "d", "e"})
    assert p == 2 / 3 and r == 2 / 4
    assert round(f, 4) == round(2 * (2 / 3) * 0.5 / ((2 / 3) + 0.5), 4)


def test_prf_empty_sets():
    assert prf(set(), set()) == (1.0, 1.0, 1.0)
    assert prf(set(), {"a"})[2] == 0.0


def test_attribute_accuracy_catches_criticality_downgrade_that_f1_misses():
    truth = generate_environment("cloud", 2)
    tampered = truth.copy()
    for name in tampered.critical_assets():
        tampered.assets[name].criticality = "low"
    scores = extraction_scores(tampered, truth)
    assert scores["assets_f1"] == 1.0 and scores["vulns_f1"] == 1.0  # set F1 is blind to it
    assert scores["criticality_acc"] < 1.0
    assert attribute_accuracy(truth, truth) == {"criticality_acc": 1.0, "vuln_attr_acc": 1.0}
