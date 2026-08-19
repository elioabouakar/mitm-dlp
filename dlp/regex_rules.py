"""
Layer 1: high-confidence structured-secret detection via regex.

This layer should have a near-zero false-positive rate - it only flags things
that are almost certainly a real secret or ID, not "possibly sensitive text."

Sources worth pulling from as you extend this:
  - https://github.com/gitleaks/gitleaks (gitleaks.toml has hundreds of vendor-specific rules)
  - https://github.com/Yelp/detect-secrets
"""

import re
from dataclasses import dataclass


@dataclass
class Finding:
    rule: str
    snippet: str  # short, redacted context - never log the full secret


RULES: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("private_key_block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db_connection_string", re.compile(r"(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"@]+@")),
]


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
SSN_CANDIDATE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for name, pattern in RULES:
        for match in pattern.finditer(text):
            findings.append(Finding(rule=name, snippet=_redact(match.group(0))))

    for match in CARD_CANDIDATE.finditer(text):
        candidate = match.group(0)
        if _luhn_valid(candidate):
            findings.append(Finding(rule="credit_card", snippet=_redact(candidate)))

    for match in SSN_CANDIDATE.finditer(text):
        findings.append(Finding(rule="ssn", snippet=_redact(match.group(0))))

    return findings


def _redact(value: str, keep: int = 4) -> str:
    """Keep only enough of a matched string to identify the rule in logs - never store
    the full secret."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{'*' * 4}...{value[-keep:]}"
