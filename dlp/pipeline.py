"""
Combines all three layers into one verdict for the mitmproxy addon to act on.

Order matters for latency: cheap/fast layers run first and short-circuit the
expensive LLM call. This operates on raw text pulled straight from an intercepted
request body - it doesn't assume any particular JSON schema, since different AI
vendors (and even different endpoints on the same vendor) structure their request
bodies differently.
"""

import logging
from dataclasses import dataclass

from dlp import regex_rules, pii_scan, llm_classifier

log = logging.getLogger("dlp.pipeline")


@dataclass
class Verdict:
    action: str  # "allow" or "deny"
    deny_reason: str | None = None
    reference_id: str | None = None


def evaluate_text(text: str, request_id: str = "unknown", use_classifier: bool = True) -> Verdict:
    if not text or not text.strip():
        return Verdict(action="allow")

    # Layer 1: regex - fast, near-zero false positives.
    regex_findings = regex_rules.scan(text)
    if regex_findings:
        rule = regex_findings[0].rule
        log.info("deny request_id=%s layer=regex rule=%s count=%d", request_id, rule, len(regex_findings))
        return Verdict(
            action="deny",
            deny_reason=(
                f"This message appears to contain a {rule.replace('_', ' ')}. "
                "Remove any credentials, keys, or account numbers before resending."
            ),
            reference_id=f"regex:{rule}",
        )

    # Layer 2: PII / company dictionary.
    pii_findings = pii_scan.scan(text)
    if pii_findings:
        rule = pii_findings[0].rule
        log.info("deny request_id=%s layer=pii rule=%s count=%d", request_id, rule, len(pii_findings))
        if rule == "company_dictionary":
            reason = (
                "This message references an internal project or client name that shouldn't "
                "be shared with this tool. Remove it and rephrase generically."
            )
        else:
            reason = (
                f"This message appears to contain personal data ({rule.replace('pii_', '')}). "
                "Remove or anonymize it before resending."
            )
        return Verdict(action="deny", deny_reason=reason, reference_id=f"pii:{rule}")

    # Layer 3: LLM classifier - only for longer text the fast layers didn't already flag,
    # and only if the caller wants it (it adds real latency to live proxy traffic).
    if use_classifier and llm_classifier.should_run(text):
        try:
            result = llm_classifier.classify(text)
        except Exception:
            log.exception("classifier call failed request_id=%s", request_id)
            # Fail open at this layer specifically - the fast layers already ran clean.
            return Verdict(action="allow")

        if result.confidential:
            log.info("deny request_id=%s layer=llm category=%s", request_id, result.category)
            return Verdict(
                action="deny",
                deny_reason=result.reason or "This message appears to contain confidential company information.",
                reference_id=f"llm:{result.category}",
            )

    return Verdict(action="allow")
