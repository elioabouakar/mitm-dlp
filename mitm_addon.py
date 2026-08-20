"""
mitmproxy addon: intercepts outbound requests to approved AI domains, runs the
request body through the DLP pipeline (dlp/pipeline.py), and blocks it if anything
sensitive is found.

Run with:
    mitmdump -s mitm_addon.py --listen-port 8080

The generated CA certificate (needed to trust decrypted HTTPS traffic) is created
automatically the first time mitmproxy runs, at:
    ~/.mitmproxy/mitmproxy-ca-cert.pem
"""

import logging
import os
import sys
import json

from dotenv import load_dotenv
from mitmproxy import http

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

from dlp import pipeline  # noqa: E402

log = logging.getLogger("mitm_addon")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Domains to inspect. Add to this list as you approve more AI tools.
# Matching is exact-or-subdomain (see _is_ai_domain below) so this can never
# accidentally catch an unrelated domain that just shares a substring
# (e.g. "a-api.anthropic.com" is NOT a subdomain of "api.anthropic.com").
AI_DOMAINS = [
    "api.anthropic.com",
    "claude.ai",
    "api.openai.com",
    "chatgpt.com",
]

# Skip known non-prompt/background endpoints to avoid false positives from
# telemetry payloads and control-plane calls.
NON_PROMPT_PATH_HINTS = (
    "/telemetry",
    "/sentinel/",
    "/chat-requirements",
    "/prepare",
    "/finalize",
    "/ping",
    "/rgstr",
    "/ces/",
)

# Keys that usually hold user-entered text across common AI vendor payloads.
PROMPT_CONTEXT_KEYS = {
    "prompt",
    "input",
    "inputs",
    "message",
    "messages",
    "content",
    "contents",
    "parts",
    "text",
    "query",
    "question",
}

# Keys that are metadata-heavy and should not be scanned as user prompt text.
METADATA_KEYS = {
    "id",
    "conversation_id",
    "parent_message_id",
    "model",
    "timezone",
    "tracking",
    "metadata",
    "client_contextual_info",
    "websocket_request_id",
}

def _is_ai_domain(host: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in AI_DOMAINS)


def _should_scan_request(method: str, path: str) -> bool:
    if method.upper() not in {"POST", "PUT", "PATCH"}:
        return False
    lowered = (path or "").lower()
    return not any(hint in lowered for hint in NON_PROMPT_PATH_HINTS)


def _collect_prompt_strings(node: object, in_prompt_context: bool = False) -> list[str]:
    texts: list[str] = []

    if isinstance(node, str):
        value = node.strip()
        if in_prompt_context and value:
            texts.append(value)
        return texts

    if isinstance(node, list):
        for item in node:
            texts.extend(_collect_prompt_strings(item, in_prompt_context=in_prompt_context))
        return texts

    if isinstance(node, dict):
        for key, value in node.items():
            key_lower = str(key).lower()
            if key_lower in METADATA_KEYS:
                continue

            next_context = in_prompt_context or key_lower in PROMPT_CONTEXT_KEYS

            if isinstance(value, str):
                if next_context and value.strip():
                    texts.append(value.strip())
            else:
                texts.extend(_collect_prompt_strings(value, in_prompt_context=next_context))

    return texts


def _extract_text_to_scan(body_text: str, content_type: str) -> str:
    ct = (content_type or "").lower()
    if "json" not in ct:
        return body_text

    try:
        payload = json.loads(body_text)
    except Exception:
        return body_text

    prompt_texts = _collect_prompt_strings(payload)
    if not prompt_texts:
        return ""

    return "\n".join(prompt_texts)


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    path = flow.request.path

    if not _is_ai_domain(host):
        return  # not an approved AI domain, let it pass through untouched

    if not _should_scan_request(flow.request.method, path):
        log.info("allowed host=%s path=%s reason=non_prompt_endpoint", host, path)
        return

    try:
        body_text = flow.request.get_text()
    except Exception:
        log.warning("could not decode request body for %s, letting it pass", host)
        return

    if not body_text or not body_text.strip():
        return

    content_type = flow.request.headers.get("Content-Type", "")
    text_to_scan = _extract_text_to_scan(body_text, content_type)
    if not text_to_scan or not text_to_scan.strip():
        log.info("allowed host=%s path=%s reason=no_prompt_text", host, path)
        return

    verdict = pipeline.evaluate_text(
        text_to_scan,
        request_id=f"{flow.client_conn.address[0]}:{flow.client_conn.address[1]}",
    )

    if verdict.action == "deny":
        log.info("BLOCKED host=%s reference=%s", host, verdict.reference_id)
        flow.response = http.Response.make(
            403,
            (verdict.deny_reason or "Blocked by company DLP policy - sensitive content detected.").encode(),
            {"Content-Type": "text/plain"},
        )
    else:
        log.info("allowed host=%s", host)
