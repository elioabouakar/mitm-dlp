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

# Whether to run the optional Layer 3 (Claude-based contextual classifier) on live
# proxy traffic. It adds real latency to every request it processes, since it's a
# live API call in the request path. Start with this off, confirm the fast layers
# behave well in shadow testing, then turn on once you're comfortable with the
# added latency.
USE_LLM_CLASSIFIER = os.environ.get("USE_LLM_CLASSIFIER", "false").lower() == "true"


def _is_ai_domain(host: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in AI_DOMAINS)


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host

    if not _is_ai_domain(host):
        return  # not an approved AI domain, let it pass through untouched

    try:
        body_text = flow.request.get_text()
    except Exception:
        log.warning("could not decode request body for %s, letting it pass", host)
        return

    if not body_text or not body_text.strip():
        return

    verdict = pipeline.evaluate_text(
        body_text,
        request_id=f"{flow.client_conn.address[0]}:{flow.client_conn.address[1]}",
        use_classifier=USE_LLM_CLASSIFIER,
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
