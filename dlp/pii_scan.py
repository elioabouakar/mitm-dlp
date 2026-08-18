"""
Layer 2: PII detection via Presidio, plus a simple company-dictionary matcher for
internal codenames / client names / unreleased product names.

Presidio setup requires a spaCy model:
    python -m spacy download en_core_web_lg
"""

import os
from dataclasses import dataclass
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine


@dataclass
class Finding:
    rule: str
    snippet: str


# Entities worth flagging for a corporate DLP use case. Presidio supports more (e.g.
# CRYPTO, IBAN_CODE, MEDICAL_LICENSE) - trim or extend this list to your risk profile.
ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
    "US_SSN",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IP_ADDRESS",
    "LOCATION",
]


@lru_cache(maxsize=1)
def _analyzer() -> AnalyzerEngine:
    # Loaded once per process - spaCy model load is the slow part, don't repeat it per request.
    return AnalyzerEngine()


@lru_cache(maxsize=1)
def _company_terms() -> tuple[str, ...]:
    path = os.environ.get("COMPANY_DICTIONARY_PATH", "./company_dictionary.txt")
    if not os.path.exists(path):
        return ()
    terms = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line.lower())
    return tuple(terms)


def scan(text: str, min_score: float = 0.6) -> list[Finding]:
    findings: list[Finding] = []

    results = _analyzer().analyze(text=text, entities=ENTITIES, language="en")
    for r in results:
        if r.score >= min_score:
            snippet = text[r.start:r.end]
            findings.append(Finding(rule=f"pii_{r.entity_type.lower()}", snippet=_redact(snippet)))

    lowered = text.lower()
    for term in _company_terms():
        if term in lowered:
            findings.append(Finding(rule="company_dictionary", snippet=term))

    return findings


def _redact(value: str, keep: int = 2) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{'*' * 4}...{value[-keep:]}"
