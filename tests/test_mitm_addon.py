"""Tests for mitm_addon request filtering and prompt-text extraction."""

import mitm_addon


class DummyRequest:
    def __init__(self, method: str, path: str):
        self.method = method
        self.path = path


def test_should_scan_chat_submission_path():
    req = DummyRequest("POST", "/backend-api/f/conversation")
    assert mitm_addon._should_scan_request(req.method, req.path) is True


def test_should_skip_telemetry_path():
    req = DummyRequest("POST", "/ces/v1/telemetry/intake")
    assert mitm_addon._should_scan_request(req.method, req.path) is False


def test_should_skip_prepare_path():
    req = DummyRequest("POST", "/backend-api/f/conversation/prepare")
    assert mitm_addon._should_scan_request(req.method, req.path) is False


def test_should_skip_non_post_methods():
    req = DummyRequest("GET", "/backend-api/f/conversation")
    assert mitm_addon._should_scan_request(req.method, req.path) is False


def test_extracts_prompt_text_from_chat_payload():
    body = (
        '{"model":"gpt-4.1","messages":[{"role":"user","content":{"parts":'
        '[{"type":"text","text":"Explain list vs tuple in Python"}]}}]}'
    )
    extracted = mitm_addon._extract_text_to_scan(body, "application/json")
    assert "Explain list vs tuple in Python" in extracted


def test_ignores_metadata_heavy_payload_with_no_prompt_fields():
    body = '{"tracking":{"session":"abc"},"conversation_id":"xyz","model":"gpt-4.1"}'
    extracted = mitm_addon._extract_text_to_scan(body, "application/json")
    assert extracted == ""


def test_non_json_body_falls_back_to_raw_text():
    body = "plain text body"
    extracted = mitm_addon._extract_text_to_scan(body, "text/plain")
    assert extracted == "plain text body"
