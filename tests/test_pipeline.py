"""
Broad regression suite for dlp/pipeline.py.

Run from repo root with the venv active:
    pytest tests/ -v

Cases are grouped so a failure tells you *which layer* regressed:
  - TestRegexTruePositives  : real secrets that MUST be blocked
  - TestRegexEdgeCases      : near-misses that must NOT be blocked (regex false-positive guard)
  - TestPiiTruePositives    : real PII that MUST be blocked
  - TestPiiFalsePositives   : clean text that looks PII-ish but must pass (Presidio false-positive guard)
  - TestCompanyDictionary   : internal terms, case-insensitivity, substring-boundary checks
  - TestCleanAllow          : realistic day-to-day prompts that must pass through untouched

Notes on maintenance:
  - When you add a new regex rule or company term, add both a true-positive AND a
    near-miss case here. A detector with only true-positive tests will happily let
    its false-positive rate climb without anyone noticing.
  - TestPiiFalsePositives is the most valuable/fragile group: PERSON and LOCATION
    recognizers are the most prone to false-firing on common words. If you see this
    group start failing after a spaCy/Presidio version bump, that's a real signal,
    not noise - investigate before silencing.
"""

import pytest

from dlp import pipeline


def deny(text: str) -> pipeline.Verdict:
    v = pipeline.evaluate_text(text)
    assert v.action == "deny", f"expected DENY, got ALLOW for: {text!r}"
    return v


def allow(text: str) -> pipeline.Verdict:
    v = pipeline.evaluate_text(text)
    assert v.action == "allow", (
        f"expected ALLOW, got DENY (reference={v.reference_id}) for: {text!r}\n"
        f"reason: {v.deny_reason}"
    )
    return v


# ---------------------------------------------------------------------------
# Layer 1: regex - true positives
# ---------------------------------------------------------------------------

class TestRegexTruePositives:
    def test_aws_access_key(self):
        v = deny("here's my key AKIAIOSFODNN7EXAMPLE for the s3 bucket")
        assert v.reference_id == "regex:aws_access_key_id"

    def test_aws_secret_key(self):
        deny('aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')

    def test_private_key_block(self):
        deny("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----")

    def test_private_key_block_openssh(self):
        deny("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...")

    def test_generic_api_key(self):
        # Built from parts, not a literal, so it doesn't trip GitHub's push-protection
        # secret scanner (it still exercises the same regex at runtime either way).
        fake_key = "sk_" + "live_" + "51H8xyzABCDEFGHIJKLMNOPQR"
        deny(f'api_key = "{fake_key}"')

    def test_slack_token(self):
        fake_token = "xoxb-" + "1234567890" + "-abcdefghijklmnop"
        deny(f"our bot token is {fake_token}")

    def test_github_token(self):
        fake_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12"
        deny(f"use {fake_token} to auth")

    def test_anthropic_api_key(self):
        fake_key = "sk-ant-" + "api03-" + "abcdefghijklmnopqrstuvwxyz1234567890"
        deny(f"ANTHROPIC_API_KEY={fake_key}")

    def test_openai_api_key(self):
        fake_key = "sk-" + "abcdefghijklmnopqrstuvwx1234567890"
        deny(f"OPENAI_API_KEY={fake_key}")

    def test_jwt(self):
        deny(
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

    def test_db_connection_string(self):
        deny("prod db: postgresql://admin:S3cretPass!@db.internal.company.com:5432/orders")

    def test_credit_card_valid_luhn(self):
        # 4111 1111 1111 1111 is a valid test Visa number (passes Luhn)
        v = deny("please charge card 4111 1111 1111 1111 for the invoice")
        assert v.reference_id == "regex:credit_card"

    def test_ssn(self):
        v = deny("employee SSN on file: 123-45-6789")
        assert v.reference_id == "regex:ssn"

    def test_multiple_secrets_in_one_message(self):
        # Should still deny (on the first rule hit), not silently pick only one
        deny("key1: AKIAIOSFODNN7EXAMPLE, ssn: 123-45-6789")


# ---------------------------------------------------------------------------
# Layer 1: regex - near-misses that must NOT trip the regex layer
# (they may still be allowed to fall through to PII/dictionary, or pass clean)
# ---------------------------------------------------------------------------

class TestRegexEdgeCases:
    def test_invalid_luhn_card_number_not_flagged_as_card(self):
        # 16 digits, fails Luhn - a phone/order number, not a real card
        v = pipeline.evaluate_text("order number 1234 5678 9012 3456 shipped today")
        assert v.reference_id != "regex:credit_card"

    def test_short_random_digit_string_not_ssn(self):
        v = pipeline.evaluate_text("meeting room is 123-45")
        assert v.reference_id != "regex:ssn"

    def test_aws_like_but_wrong_prefix_not_flagged(self):
        # AKIA prefix + correct length is required; this is one char short
        v = pipeline.evaluate_text("random id AKIAIOSFODNN7EXAMPL used in old docs")
        assert v.reference_id != "regex:aws_access_key_id"

    def test_short_token_not_flagged_as_generic_api_key(self):
        # generic_api_key requires 20+ chars after key/secret/token; this is short
        v = pipeline.evaluate_text("the api key is short123")
        assert v.reference_id != "regex:generic_api_key"

    def test_talking_about_keys_conceptually_not_flagged(self):
        v = allow("we should rotate our API keys quarterly as a policy")

    def test_partial_jwt_looking_string_not_flagged(self):
        v = pipeline.evaluate_text("the token starts with eyJ but nothing else")
        assert v.reference_id != "regex:jwt"

    def test_http_url_with_user_no_password_not_flagged_as_db_string(self):
        # db_connection_string requires user:password@ - no password here
        v = pipeline.evaluate_text("see https://user@example.com/docs for the API reference")
        assert v.reference_id != "regex:db_connection_string"


# ---------------------------------------------------------------------------
# Layer 2: PII - true positives
# ---------------------------------------------------------------------------

class TestPiiTruePositives:
    def test_name_and_email_combo(self):
        v = deny("Please loop in Michael Chen at michael.chen@example.com")
        assert v.reference_id.startswith("pii:")

    def test_email_alone(self):
        deny("send the invoice to accounts@ourvendor.com")

    def test_phone_number(self):
        deny("her direct line is +1 (415) 555-0182, call before noon")

    def test_bank_number(self):
        deny("wire the deposit to account number 000123456789")

    def test_location_mention(self):
        # Regression test for a real bug: LOCATION was originally set to a
        # 0.9 threshold (defensive default from small-model testing), which
        # on the production en_core_web_lg model was ABOVE the score a real
        # location mention gets (0.85) - a false negative. Threshold lowered
        # to 0.7. If this test fails, someone raised the threshold back up
        # without re-checking against the lg model.
        deny("the client is based in our Singapore office, loop in their team")

    def test_name_corroborated_by_company_dictionary(self, tmp_path, monkeypatch):
        # PERSON alone doesn't deny (see TestPiiFalsePositives), but PERSON
        # alongside another finding - here a company-dictionary hit - does.
        dict_path = tmp_path / "company_dictionary.txt"
        dict_path.write_text("project-phoenix\n")
        monkeypatch.setenv("COMPANY_DICTIONARY_PATH", str(dict_path))
        _reload_company_terms()

        deny("Sarah Connor is leading project-phoenix starting Monday")


# ---------------------------------------------------------------------------
# Layer 2: PII - false-positive guards
# These are the most important/fragile tests in the suite. If these start
# failing, it usually means a threshold, entity-list, or corroboration-rule
# change made the detector too trigger-happy on ordinary business language.
# ---------------------------------------------------------------------------

class TestPiiFalsePositives:
    def test_tool_name_not_flagged_as_person(self):
        # Verified on the production en_core_web_lg model: Presidio's PERSON
        # recognizer scores "Slack" here identically (0.85) to a real name
        # like "Michael Chen" - a threshold can't separate them. PERSON
        # findings require corroboration (see dlp/pii_scan.py) instead, so a
        # bare mention like this passes through.
        allow("Ping me on Slack about the deploy")

    def test_brand_name_not_flagged_as_person(self):
        allow("My favorite band is Nirvana, we should use it for the demo playlist")

    def test_generic_role_reference_not_flagged_as_person(self):
        allow("Reach out to the on-call engineer if the build breaks")

    def test_quarter_and_business_terms_not_flagged(self):
        allow("Please review the Q3 numbers with the team before Friday")

    def test_generic_geography_not_business_sensitive(self):
        # Not every LOCATION hit is a DLP concern - public/well-known places in
        # a generic sentence shouldn't block a prompt about travel or logistics
        allow("Our office is a ten minute walk from the train station")

    def test_science_fact_no_pii(self):
        allow("The mitochondria is the powerhouse of the cell")

    def test_first_name_only_casual_mention_allowed(self):
        # Deliberate design decision (see REQUIRE_CORROBORATION in
        # dlp/pii_scan.py): a bare name with nothing else alongside it is
        # allowed through. This is the accepted tradeoff - a message that's
        # sensitive purely because of who's named, with no other PII/secret/
        # dictionary hit present, won't be caught by this layer.
        allow("Reach out to Karen in accounting")


# ---------------------------------------------------------------------------
# Company dictionary
# ---------------------------------------------------------------------------

class TestCompanyDictionary:
    """
    These reference placeholder terms. Once company_dictionary.txt has real
    entries, mirror a few of them here (using safe stand-ins in this file if
    the real terms are themselves sensitive) so the matching behavior stays
    covered by regression tests.
    """

    def test_case_insensitive_match(self, tmp_path, monkeypatch):
        dict_path = tmp_path / "company_dictionary.txt"
        dict_path.write_text("project-phoenix\n")
        monkeypatch.setenv("COMPANY_DICTIONARY_PATH", str(dict_path))
        _reload_company_terms()

        deny("quick update on PROJECT-PHOENIX status")

    def test_substring_boundary_false_positive(self, tmp_path, monkeypatch):
        """
        Known limitation: matching is substring, not word-boundary. A short or
        common codename can false-positive inside an unrelated word. This test
        documents the behavior so it's a deliberate, known tradeoff rather than
        a silent surprise - e.g. a codename "nova" would match inside "renovate".
        """
        dict_path = tmp_path / "company_dictionary.txt"
        dict_path.write_text("nova\n")
        monkeypatch.setenv("COMPANY_DICTIONARY_PATH", str(dict_path))
        _reload_company_terms()

        v = pipeline.evaluate_text("we need to renovate the office kitchen")
        assert v.action == "deny", (
            "documents current substring-match behavior; if this ever starts "
            "failing it means matching was changed to word-boundary, which is "
            "good - update the dictionary section of the README to match"
        )

    def test_commented_and_blank_lines_ignored(self, tmp_path, monkeypatch):
        dict_path = tmp_path / "company_dictionary.txt"
        dict_path.write_text("# comment\n\nacme-contract\n")
        monkeypatch.setenv("COMPANY_DICTIONARY_PATH", str(dict_path))
        _reload_company_terms()

        allow("just a normal status update with nothing sensitive")
        deny("the acme-contract renewal is due next week")


def _reload_company_terms():
    """company_dictionary.txt is cached with lru_cache; clear it between tests
    that swap COMPANY_DICTIONARY_PATH via monkeypatch."""
    from dlp import pii_scan
    pii_scan._company_terms.cache_clear()


# ---------------------------------------------------------------------------
# Realistic clean prompts - the "does this tool get in people's way" check
# ---------------------------------------------------------------------------

class TestCleanAllow:
    @pytest.mark.parametrize("text", [
        "Can you help me write a regex to validate email addresses?",
        "Summarize the attached changelog into three bullet points",
        "What's the time complexity of a binary search?",
        "Draft a polite follow-up email about a delayed shipment",
        "Explain the difference between TCP and UDP",
        "Refactor this function to use list comprehension",
        "What are best practices for naming Python variables?",
        "Help me plan a workout routine for next week",
        "Give me five headline ideas for a blog post about remote work",
        "How do I configure a systemd service to restart on failure?",
    ])
    def test_generic_developer_and_office_prompts_pass(self, text):
        allow(text)
