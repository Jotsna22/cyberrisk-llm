from cyberrisk.metrics import prf


def test_prf_basic():
    p, r, f = prf({"a", "b", "c"}, {"a", "b", "d", "e"})
    assert p == 2 / 3 and r == 2 / 4
    assert round(f, 4) == round(2 * (2 / 3) * 0.5 / ((2 / 3) + 0.5), 4)


def test_prf_empty_sets():
    assert prf(set(), set()) == (1.0, 1.0, 1.0)
    assert prf(set(), {"a"})[2] == 0.0
