from cyberrisk.models import INTERNET
from cyberrisk.synthetic import TEMPLATES, generate_environment, render_report


def test_generation_is_deterministic():
    a = generate_environment("hpc", 7)
    b = generate_environment("hpc", 7)
    assert render_report(a, 7) == render_report(b, 7)


def test_every_template_has_an_internet_entry_point():
    for name in TEMPLATES:
        env = generate_environment(name, 0)
        assert any(a.internet_exposed for a in env.assets.values())
        assert INTERNET not in env.assets


def test_report_has_one_fact_per_line():
    env = generate_environment("small_lab", 4)
    report = render_report(env, 4)
    assert len(report.strip().splitlines()) >= len(env.assets) + len(env.links)
