"""
Layer 3: semantic/contextual classification via a Claude API call.

Regex and PII layers catch structured, pattern-matchable leaks. This layer catches
what they can't: unmarked business-confidential text with no obvious "secret" shape -
financial figures, contract terms, unreleased roadmap details, source code that
reveals proprietary logic even without an embedded credential.

This is a *separate* Anthropic API key/account from any Claude Enterprise seats -
it's just using Claude as a text classifier.

Cost/latency control: only call this when the cheap layers found nothing AND the
text is long enough to plausibly contain something they'd miss. Since this runs
inline on live proxy traffic, keep SKIP_BELOW_CHARS conservative and expect this
layer to add real latency to any request it processes.
"""

import json
import os
from dataclasses import dataclass

import anthropic

SKIP_BELOW_CHARS = 200

# Customize this to your company's actual confidentiality categories.
CATEGORIES = """
- Unreleased product names, features, or roadmap details
- Financial data not yet publicly disclosed (revenue, forecasts, budgets, pricing)
- Customer/client identities or their confidential data
- Internal strategy, contract terms, or legal matters
- Source code that reveals proprietary algorithms or business logic
  (routine boilerplate, public-library usage, or generic scaffolding is NOT sensitive)
""".strip()

SYSTEM_PROMPT = f"""You are a corporate data-loss-prevention classifier. You will be shown \
text a company employee is about to send to an AI assistant. Decide whether it contains \
confidential company information in any of these categories:

{CATEGORIES}

Respond with ONLY a JSON object, no other text:
{{"confidential": true|false, "category": "<one category above, or null>", "reason": "<one \
sentence a non-technical employee would understand, or null>"}}

Be conservative: routine questions, public knowledge, and generic technical discussion are \
NOT confidential. Only flag clear, specific instances of the categories above."""


@dataclass
class Verdict:
    confidential: bool
    category: str | None
    reason: str | None


_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _client


def should_run(text: str) -> bool:
    return len(text) >= SKIP_BELOW_CHARS


def classify(text: str, timeout_s: float = 3.0) -> Verdict:
    """Calls Claude as a classifier. Raises on API failure - caller decides how to
    handle that (see dlp/pipeline.py)."""
    model = os.environ.get("CLASSIFIER_MODEL", "claude-haiku-4-5-20251001")

    response = _get_client().messages.create(
        model=model,
        max_tokens=200,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": text[:8000]}],  # cap input for latency/cost
        timeout=timeout_s,
    )

    raw = response.content[0].text.strip()
    # Models sometimes wrap JSON in markdown fences despite instructions - strip defensively.
    raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    parsed = json.loads(raw)
    return Verdict(
        confidential=bool(parsed.get("confidential", False)),
        category=parsed.get("category"),
        reason=parsed.get("reason"),
    )
