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
# These starting values came from tests/tune_thresholds.py run against the
# small (en_core_web_sm) model on a small labeled set - re-run that script on
# this VM with SPACY_MODEL=en_core_web_lg (the production model) and your own
# example prompts before trusting these for real traffic. LOCATION in
# particular showed no clean separation between true and false positives at
# any threshold in that run; it's kept enabled here but at a high bar as a
# deliberate "mostly off" default until re-tuned - consider dropping it from
# ENTITIES entirely if re-tuning on the lg model doesn't improve separation.
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
    findings: list[Finding] = []

    results = _analyzer().analyze(text=text, entities=ENTITIES, language="en")
    for r in results:
        threshold = ENTITY_THRESHOLDS.get(r.entity_type, DEFAULT_THRESHOLD)
        if r.score >= threshold:
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
