"""
Empirical threshold tuner for dlp/pii_scan.py.

pipeline.py currently applies one global min_score (0.6) across every Presidio
entity type. In practice different entity types have very different confidence
distributions (e.g. IP_ADDRESS and EMAIL_ADDRESS are near-binary; PERSON and
LOCATION are much noisier), so one global cutoff is either too loose for the
noisy entities or too strict for the reliable ones.

This script scores a labeled set of "should deny" and "should allow" texts at
every threshold from 0.0 to 1.0 (step 0.05), per entity type, and reports:
  - the score each entity actually got on each example
  - the threshold range (if any) that correctly separates true positives from
    false positives for that entity, given this test set
  - a suggested per-entity threshold you can wire into pii_scan.py

Run from repo root with the venv active:
    python tests/tune_thresholds.py

Expand LABELED_CASES with real examples from your own traffic/logs (redacted)
before trusting the suggested thresholds - the built-in set is a starting
point, not a substitute for your own data.
"""

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dlp.pii_scan import _analyzer, ENTITIES  # noqa: E402

# (text, entity_type, should_fire) - should_fire=True means this text SHOULD
# trigger this entity type; False means it's a known false-positive risk that
# should NOT trigger it. Only entries relevant to a given entity_type affect
# that entity's report.
LABELED_CASES: list[tuple[str, str, bool]] = [
    # EMAIL_ADDRESS
    ("send the invoice to accounts@ourvendor.com", "EMAIL_ADDRESS", True),
    ("reach out at john.doe+work@example.co.uk", "EMAIL_ADDRESS", True),
    ("the format is name@domain.com generally", "EMAIL_ADDRESS", False),

    # PHONE_NUMBER
    ("her direct line is +1 (415) 555-0182, call before noon", "PHONE_NUMBER", True),
    ("call me at 555-867-5309 tomorrow", "PHONE_NUMBER", True),
    ("room 404 is booked until 3pm", "PHONE_NUMBER", False),
    ("the invoice total was 1234.56 dollars", "PHONE_NUMBER", False),

    # PERSON
    ("Please loop in Michael Chen on this", "PERSON", True),
    ("Sarah Connor will lead the meeting", "PERSON", True),
    ("Reach out to Karen in accounting", "PERSON", True),
    ("Reach out to the on-call engineer if the build breaks", "PERSON", False),
    ("the API returns a User object with an id field", "PERSON", False),

    # US_SSN
    ("employee SSN on file: 123-45-6789", "US_SSN", True),
    ("meeting room is 123-45", "US_SSN", False),

    # US_BANK_NUMBER
    ("wire the deposit to account number 000123456789", "US_BANK_NUMBER", True),
    ("order number is 000123456789 for tracking", "US_BANK_NUMBER", False),

    # CREDIT_CARD (regex layer already Luhn-validates; this is Presidio's own pass)
    ("card on file ends in 4111 1111 1111 1111", "CREDIT_CARD", True),
    ("tracking number 1234 5678 9012 3456", "CREDIT_CARD", False),

    # IP_ADDRESS
    ("the server IP is 10.0.0.15", "IP_ADDRESS", True),
    ("build version is 10.0.0.15 released today", "IP_ADDRESS", False),

    # LOCATION - the noisiest entity in practice; expect this section to need
    # the most tuning or possibly removal from ENTITIES entirely.
    ("I live near the Eiffel Tower", "LOCATION", True),
    ("the client is based in our Singapore office", "LOCATION", True),
    ("Ping me on Slack about the deploy", "LOCATION", False),
    ("My favorite band is Nirvana", "LOCATION", False),
    ("Our office is a ten minute walk from the train station", "LOCATION", False),
]


def sweep():
    analyzer = _analyzer()
    thresholds = [round(t * 0.05, 2) for t in range(0, 21)]  # 0.00 .. 1.00

    # score[entity][(text, should_fire)] = max score seen for that entity on that text
    scores: dict[str, dict[tuple, float]] = defaultdict(dict)

    for text, entity, should_fire in LABELED_CASES:
        results = analyzer.analyze(text=text, entities=[entity], language="en")
        best = max((r.score for r in results if r.entity_type == entity), default=0.0)
        scores[entity][(text, should_fire)] = best

    print(f"{'ENTITY':<18} {'TEXT':<62} {'SHOULD':<7} {'SCORE'}")
    print("-" * 100)
    for entity in ENTITIES:
        cases = scores.get(entity, {})
        if not cases:
            continue
        for (text, should_fire), score in cases.items():
            label = "fire" if should_fire else "SILENT"
            print(f"{entity:<18} {text[:60]:<62} {label:<7} {score:.2f}")
        print()

    print("=" * 100)
    print("SUGGESTED PER-ENTITY THRESHOLD (highest cutoff that still catches every")
    print("true positive in this set; '--' means no clean separation was found)")
    print("=" * 100)
    for entity in ENTITIES:
        cases = scores.get(entity, {})
        if not cases:
            continue
        pos_scores = [s for (_, should_fire), s in cases.items() if should_fire]
        neg_scores = [s for (_, should_fire), s in cases.items() if not should_fire]
        min_pos = min(pos_scores) if pos_scores else None
        max_neg = max(neg_scores) if neg_scores else 0.0

        if min_pos is None:
            print(f"{entity:<18} no labeled positive cases - add some to LABELED_CASES")
        elif min_pos > max_neg:
            suggested = round((min_pos + max_neg) / 2 + 0.001, 2)
            print(f"{entity:<18} clean separation -> suggested threshold ~{suggested:.2f} "
                  f"(true positives >= {min_pos:.2f}, false positives <= {max_neg:.2f})")
        else:
            print(f"{entity:<18} NO clean separation with this test set "
                  f"(lowest true positive {min_pos:.2f} <= highest false positive {max_neg:.2f}). "
                  f"Consider: more context words, a custom recognizer, or dropping this "
                  f"entity from ENTITIES and relying on the regex layer / manual review instead.")


if __name__ == "__main__":
    sweep()
