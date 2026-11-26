from types import SimpleNamespace

import pytest

from cyberrisk.extraction import ExtractionError, LLMExtractor, RuleBasedExtractor, environment_from_json
from cyberrisk.synthetic import generate_environment, render_report
from cyberrisk.metrics import extraction_scores


def test_rule_based_recovers_canonical_lines():
    text = "\n".join([
        "Asset WEB-01 is a web with low business criticality.",
        "WEB-01 is internet-facing.",
        "WEB-01 has SYN-CVE-0001 (CVSS 9.8). Attack vector: network. Privilege required: none.",
        "WEB-01 can reach DB-01 over the internal network.",
        "DB-01 has SYN-CVE-0003 (CVSS 8.8). Attack vector: network. Privilege required: low.",
        "Asset DB-01 is a db with high business criticality.",
    ])
    env = RuleBasedExtractor().extract(text)
    assert env.assets["WEB-01"].internet_exposed
    assert env.assets["DB-01"].criticality == "high"  # asset line arrived after its vuln line
    assert "SYN-CVE-0003" in env.assets["DB-01"].vulns
    assert ("WEB-01", "DB-01") in env.links


def test_rule_based_misses_paraphrases_but_never_invents():
    truth = generate_environment("small_lab", 0)
    report = render_report(truth, 0)
    scores = extraction_scores(RuleBasedExtractor().extract(report), truth)
    assert scores["links_precision"] == 1.0  # canonical matches are always correct
    assert scores["links_recall"] < 1.0      # paraphrased links are missed by design


def test_environment_from_json_validates_and_counts_rejections():
    raw = '```json\n{"assets": [{"name": "A", "criticality": "extreme", "vulnerabilities": ' \
          '[{"cve_id": "C", "cvss": 11, "attack_vector": "network", "privilege": "none"}, ' \
          '{"cve_id": "D", "cvss": 5, "attack_vector": "network", "privilege": "none"}]}], ' \
          '"links": [["A", "B"], "bad"]}\n```'
    env, rejected = environment_from_json(raw)
    assert env.assets["A"].criticality == "medium"
    assert set(env.assets["A"].vulns) == {"D"}
    assert ("A", "B") in env.links
    assert rejected == 3  # bad criticality, CVSS out of range, malformed link


class _StubMessages:
    def __init__(self, payload: str):
        self.payload = payload
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.payload)])


def test_llm_extractor_uses_stub_client():
    payload = '{"assets": [{"name": "WEB-01", "kind": "web", "criticality": "low", "internet_exposed": true, ' \
              '"vulnerabilities": [{"cve_id": "SYN-CVE-0001", "cvss": 9.8, "attack_vector": "network", "privilege": "none"}]}], ' \
              '"links": [["WEB-01", "APP-01"]]}'
    stub = SimpleNamespace(messages=_StubMessages(payload))
    env = LLMExtractor(client=stub, model="test-model").extract("some report")
    assert env.assets["WEB-01"].internet_exposed
    assert ("WEB-01", "APP-01") in env.links
    call = stub.messages.calls[0]
    assert call["model"] == "test-model"
    assert call["messages"][0] == {"role": "user", "content": "some report"}  # report is passed as user data


@pytest.mark.parametrize("raw", ["not json at all", "[]", '"a string"'])
def test_environment_from_json_rejects_non_objects_with_a_clear_error(raw):
    with pytest.raises(ExtractionError):
        environment_from_json(raw)


def test_environment_from_json_skips_nameless_assets_and_null_lists():
    env, rejected = environment_from_json(
        '{"assets": [{"kind": "web"}, {"name": "B", "vulnerabilities": null}], "links": null}')
    assert set(env.assets) == {"B"}
    assert rejected == 1


def test_links_with_null_endpoints_are_rejected_not_turned_into_assets():
    # Seen in a live Gemini response (small_lab seed 15): a link endpoint came back as null.
    env, rejected = environment_from_json('{"assets": [{"name": "A"}], "links": [["A", null], ["A", ""], ["A", "B"]]}')
    assert env.links == {("A", "B")}
    assert rejected == 2
