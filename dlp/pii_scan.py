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
from presidio_analyzer.nlp_engine import NlpEngineProvider


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

# Per-entity confidence cutoffs. One global threshold doesn't work well here -
# some entities (EMAIL_ADDRESS, IP_ADDRESS) are near-binary in Presidio's own
# scoring, while others (PERSON, LOCATION) have much noisier score
# distributions and need a different bar. US_SSN is intentionally left high
# (effectively "rarely trust Presidio alone") since the regex layer already
# catches the standard NNN-NN-NNNN pattern with a validated format; Presidio's
# SSN recognizer only adds value for atypically-formatted SSNs, at real risk
# of false-firing on any 5-9 digit sequence with SSN-adjacent context words.
#
# PERSON is a special case, not just a threshold tuning problem: verified on
# the production en_core_web_lg model that "Slack", "Nirvana", "Michael Chen",
# and "Sarah Connor" all score an IDENTICAL 0.85. Presidio's spaCy-based PERSON
# recognizer assigns a flat confidence to anything it POS/NER-tags as a proper
# noun, regardless of context - no threshold value can separate real names
# from brand/tool names here. Instead of a threshold, PERSON findings require
# corroboration: see REQUIRE_CORROBORATION below and the logic in scan(). A
# bare name mention alone is allowed through; a name alongside another PII/
# secret/dictionary hit is denied. This means a message that's sensitive
# *purely* because of who's named, with nothing else alongside it, will not
# be caught - a known, deliberate tradeoff, not an oversight.
#
# LOCATION showed the same flat-score problem on the small model during
# development; it's kept at a high bar as a "mostly off" default. Re-run
# tests/tune_thresholds.py against production traffic periodically - if
# LOCATION never achieves clean separation, consider dropping it from
# ENTITIES entirely, same as was done conceptually for PERSON below.
DEFAULT_THRESHOLD = 0.6
ENTITY_THRESHOLDS = {
    "EMAIL_ADDRESS": 0.5,
    "PHONE_NUMBER": 0.3,
    "PERSON": 0.5,
    "US_SSN": 0.85,
    "US_BANK_NUMBER": 0.3,
    "CREDIT_CARD": 0.5,
    "IP_ADDRESS": 0.7,
    "LOCATION": 0.9,
}

# Entity types that must not deny on their own - only when at least one other
# finding (any other entity, or a company-dictionary hit) is also present in
# the same message. See the PERSON note above for why.
REQUIRE_CORROBORATION = {"PERSON"}


# Real deployment must use en_core_web_lg (best accuracy). Override with
# SPACY_MODEL=en_core_web_sm for fast local dev/test iteration only - the
# small model is noticeably less accurate on PERSON/LOCATION and should never
# be used to make production allow/deny decisions.
SPACY_MODEL = os.environ.get("SPACY_MODEL", "en_core_web_lg")


@lru_cache(maxsize=1)
def _analyzer() -> AnalyzerEngine:
    # Loaded once per process - spaCy model load is the slow part, don't repeat it per request.
    config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": SPACY_MODEL}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=config).create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine)


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


def scan(text: str) -> list[Finding]:
    strong_findings: list[Finding] = []
    corroboration_findings: list[Finding] = []

    results = _analyzer().analyze(text=text, entities=ENTITIES, language="en")
    for r in results:
        threshold = ENTITY_THRESHOLDS.get(r.entity_type, DEFAULT_THRESHOLD)
        if r.score >= threshold:
            snippet = text[r.start:r.end]
            finding = Finding(rule=f"pii_{r.entity_type.lower()}", snippet=_redact(snippet))
            if r.entity_type in REQUIRE_CORROBORATION:
                corroboration_findings.append(finding)
            else:
                strong_findings.append(finding)

    lowered = text.lower()
    for term in _company_terms():
        if term in lowered:
            strong_findings.append(Finding(rule="company_dictionary", snippet=term))

    # Findings that require corroboration (currently: PERSON) only count if
    # something else was also found in this message - see REQUIRE_CORROBORATION.
    if strong_findings:
        return strong_findings + corroboration_findings
    return strong_findings


def _redact(value: str, keep: int = 2) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{'*' * 4}...{value[-keep:]}"
