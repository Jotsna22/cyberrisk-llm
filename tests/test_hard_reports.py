import pytest

from cyberrisk.extraction import RuleBasedExtractor, TemplateExtractor
from cyberrisk.hard_reports import INJECTION_KINDS, TRAP_KINDS, render_hard_report, trap_outcome
from cyberrisk.metrics import extraction_scores
from cyberrisk.models import Environment
from cyberrisk.synthetic import TEMPLATES, generate_environment, render_report

CASES = [(t, s) for t in TEMPLATES for s in (0, 7, 13)]


def test_hard_report_is_deterministic():
    env = generate_environment("hpc", 4)
    assert render_hard_report(env, 4).text == render_hard_report(env, 4).text
    assert render_hard_report(env, 4, injected=True).text == render_hard_report(env, 4, injected=True).text


@pytest.mark.parametrize("template,seed", CASES)
def test_injected_report_is_the_base_report_plus_injections(template, seed):
    env = generate_environment(template, seed)
    base, injected = render_hard_report(env, seed), render_hard_report(env, seed, injected=True)
    for block in base.text.split("\n\n"):
        assert block in injected.text
    assert injected.traps[: len(base.traps)] == base.traps
    assert {t.kind for t in injected.traps[len(base.traps):]} == set(INJECTION_KINDS)


@pytest.mark.parametrize("template,seed", CASES)
def test_every_true_fact_is_mentioned(template, seed):
    env = generate_environment(template, seed)
    text = render_hard_report(env, seed).text
    for name, asset in env.assets.items():
        assert name in text
        for cve in asset.vulns:
            assert cve in text
    for src, dst in env.links:
        assert src in text and dst in text


@pytest.mark.parametrize("template,seed", CASES)
def test_traps_disagree_with_the_truth_and_the_truth_passes_them(template, seed):
    env = generate_environment(template, seed)
    report = render_hard_report(env, seed, injected=True)
    assert {t.kind for t in report.traps} == set(TRAP_KINDS)
    for trap in report.traps:
        if trap.kind in ("revoked_link", "denied_link"):
            assert tuple(trap.detail.split("->")) not in env.links
        elif trap.kind in ("withdrawn_vuln", "negated_vuln"):
            assert trap.detail not in env.assets[trap.asset].vulns
        elif trap.kind == "decommissioned_asset":
            assert trap.asset not in env.assets
        else:
            assert trap.true_value != trap.trap_value
        assert trap_outcome(env, trap) == "correct", trap


def test_a_model_that_believes_every_trap_is_fooled_by_all_of_them():
    env = generate_environment("cloud", 3)
    report = render_hard_report(env, 3, injected=True)
    fooled = env.copy()
    from cyberrisk.models import Asset, Vulnerability

    for trap in report.traps:
        if trap.kind in ("revoked_link", "denied_link"):
            fooled.add_link(*trap.detail.split("->"))
        elif trap.kind in ("withdrawn_vuln", "negated_vuln"):
            fooled.assets[trap.asset].add_vulnerability(Vulnerability(trap.detail, 9.8, "network", "none"))
        elif trap.kind == "decommissioned_asset":
            fooled.add_asset(Asset(trap.asset, "retired", "low"))
        elif trap.kind == "cvss_correction":
            v = fooled.assets[trap.asset].vulns[trap.detail]
            fooled.assets[trap.asset].vulns[trap.detail] = Vulnerability(v.cve_id, trap.trap_value,
                                                                         v.attack_vector, v.privilege)
        elif trap.kind in ("negated_exposure", "injection_plausible_update"):
            fooled.assets[trap.asset].internet_exposed = trap.trap_value
        else:
            fooled.assets[trap.asset].criticality = trap.trap_value
    assert {trap_outcome(fooled, t) for t in report.traps} == {"fooled"}


def test_empty_model_leaves_traps_untested():
    env = generate_environment("small_lab", 1)
    report = render_hard_report(env, 1, injected=True)
    assert {trap_outcome(Environment("empty"), t) for t in report.traps} == {"missing"}


@pytest.mark.parametrize("template,seed", CASES)
def test_template_parser_is_perfect_on_easy_reports_and_blind_on_hard_ones(template, seed):
    env = generate_environment(template, seed)
    easy = extraction_scores(TemplateExtractor().extract(render_report(env, seed)), env)
    assert all(easy[k] == 1.0 for k in ("assets_f1", "exposed_f1", "vulns_f1", "links_f1",
                                        "criticality_acc", "vuln_attr_acc"))
    hard = extraction_scores(TemplateExtractor().extract(render_hard_report(env, seed).text), env)
    assert hard["vulns_f1"] == 0.0 and hard["links_f1"] == 0.0


def test_template_parser_beats_canonical_rules_on_easy_reports():
    env = generate_environment("hpc", 2)
    report = render_report(env, 2)
    rules = extraction_scores(RuleBasedExtractor().extract(report), env)
    template = extraction_scores(TemplateExtractor().extract(report), env)
    assert template["links_f1"] > rules["links_f1"]


class _OracleStub:
    """Stands in for an LLM that reads every report perfectly."""

    def __init__(self, truth):
        self.truth = truth
        self.last_rejected = 0

    def extract(self, text):
        return self.truth.copy()


def test_evaluate_hard_text_with_a_perfect_reader():
    from cyberrisk.experiments import evaluate_hard_text

    truth = generate_environment("distributed", 5)
    rows, traps = evaluate_hard_text("distributed", 5, _OracleStub(truth))
    llm = {r["variant"]: r for r in rows if r["extractor"] == "llm"}
    assert set(llm) == {"easy", "hard", "hard_injected"}
    assert all(r["vuln_f1"] == 1.0 and r["risk_reduction"] > 0.9 for r in llm.values())
    assert {t["outcome"] for t in traps if t["extractor"] == "llm"} == {"correct"}
    template_hard = next(r for r in rows if r["extractor"] == "template_parser" and r["variant"] == "hard")
    assert template_hard["risk_reduction"] == 0.0


def test_cli_demo_hard_report_with_template_parser(capsys):
    from cyberrisk.cli import main

    assert main(["demo", "--report", "hard_injected", "--extractor", "template", "--show-report"]) == 0
    out = capsys.readouterr().out
    assert "## Updates since the scan" in out and "injection_instruction" in out
