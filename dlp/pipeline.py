"""Combines the local DLP layers into one verdict for the mitmproxy addon."""

import logging
from dataclasses import dataclass

from dlp import regex_rules, pii_scan

log = logging.getLogger("dlp.pipeline")


@dataclass
class Verdict:
    action: str  # "allow" or "deny"
    deny_reason: str | None = None
    reference_id: str | None = None


def evaluate_text(text: str, request_id: str = "unknown") -> Verdict:
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

    return Verdict(action="allow")
