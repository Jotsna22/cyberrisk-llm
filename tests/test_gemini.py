import json

import pytest

from cyberrisk.extraction import GeminiExtractor

PAYLOAD = {"assets": [{"name": "WEB-01", "kind": "web", "criticality": "low", "internet_exposed": True,
                       "vulnerabilities": [{"cve_id": "SYN-CVE-0001", "cvss": 9.8,
                                            "attack_vector": "network", "privilege": "none"}]}],
           "links": [["WEB-01", "APP-01"]]}


def _response(text: str) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


def test_requires_key_when_no_transport(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        GeminiExtractor()


def test_parses_response_and_sends_key_in_header(tmp_path):
    calls = []

    def transport(url, headers, body):
        calls.append((url, headers, body))
        return _response(json.dumps(PAYLOAD))

    env = GeminiExtractor(api_key="test-key", model="m1", transport=transport).extract("report text")
    assert env.assets["WEB-01"].internet_exposed
    assert ("WEB-01", "APP-01") in env.links
    url, headers, body = calls[0]
    assert url.endswith("/models/m1:generateContent")
    assert headers["x-goog-api-key"] == "test-key"
    assert "key=" not in url  # key must not appear in the URL
    assert body["contents"][0]["parts"][0]["text"] == "report text"


def test_cache_avoids_second_call(tmp_path):
    calls = []

    def transport(url, headers, body):
        calls.append(1)
        return _response(json.dumps(PAYLOAD))

    extractor = GeminiExtractor(api_key="k", transport=transport, cache_dir=tmp_path)
    extractor.extract("same text")
    extractor.extract("same text")
    assert len(calls) == 1
