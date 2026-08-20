# mitmproxy DLP addon

A two-layer local DLP scanner wired into [mitmproxy](https://mitmproxy.org) to inspect
and block outbound prompts to AI tools that contain confidential company data.

## How it works

1. A device with the mitmproxy CA certificate installed sends an HTTPS request to
   an approved AI domain (Claude, ChatGPT, etc.)
2. mitmproxy intercepts and decrypts the connection
3. `mitm_addon.py` checks if the destination is one of the approved `AI_DOMAINS`
4. If so, the request body is handed to `dlp/pipeline.py`, which runs it through:
   - `dlp/regex_rules.py` - structured secrets (API keys, credit cards, SSNs, etc.)
   - `dlp/pii_scan.py` - Presidio PII detection + your company dictionary
5. If anything is found, mitmproxy returns a `403` with a plain-text reason instead
   of forwarding the request. Otherwise, it passes through untouched.

## Setup

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
cp .env.example .env
```

Edit `company_dictionary.txt` with your actual internal codenames / client names.

## Run it

```bash
source venv/bin/activate
mitmdump -s mitm_addon.py --listen-port 8080
```

The first run auto-generates a CA certificate at `~/.mitmproxy/mitmproxy-ca-cert.pem`.

## Test it locally before touching real devices

**Confirm non-AI traffic passes through untouched:**
```bash
curl -x http://localhost:8080 -I http://neverssl.com
```

**Confirm the detection logic works, without needing the CA cert trusted anywhere:**
```bash
python3 -c "
from dlp import pipeline
v = pipeline.evaluate_text('here is my key AKIAIOSFODNN7EXAMPLE')
print(v.action, v.deny_reason)
"
```

**Full end-to-end HTTPS test (requires the CA cert trusted on the test client - see below):**
```bash
curl -x http://<vm-ip>:8080 --ssl-no-revoke --globoff \
  -X POST https://api.anthropic.com/v1/messages \
  -H "Content-Type: application/json" \
  --data-binary '{"messages":[{"role":"user","content":"here is my key AKIAIOSFODNN7EXAMPLE"}]}'
```
Expected: a `403` with a plain-text DLP message, not a real Anthropic API error - meaning
the request was blocked before it ever reached Anthropic's servers.

## Trusting the certificate on a test client

1. Copy `~/.mitmproxy/mitmproxy-ca-cert.pem` off the VM to the test machine
2. Install it into that machine's trusted root certificate store
3. Point that machine's network traffic at the proxy (`<vm-ip>:8080`)

For a real company rollout, this certificate gets pushed to every managed device
automatically via your MDM (e.g., a Microsoft Intune Trusted Certificate profile) -
never installed manually one device at a time.

## Configuration

- `AI_DOMAINS` (top of `mitm_addon.py`) - which domains get inspected. Matching is
  exact-or-subdomain, so it won't accidentally catch an unrelated domain that just
  shares a substring (e.g. an analytics subdomain like `a-api.anthropic.com`).
- `company_dictionary.txt` - one internal term per line, case-insensitive substring
  match. Grouped by category with guidance comments - fill in real values before
  deploying. See the "known limitation" note in that file about substring matching.
- `dlp/pii_scan.py`'s `ENTITY_THRESHOLDS` - per-entity Presidio confidence cutoffs.
  See "Testing and tuning" below for how these were derived and how to re-derive
  them for your own traffic.

## Testing and tuning

```bash
source venv/bin/activate
pip install pytest  # not in requirements.txt - dev-only dependency
pytest tests/ -v
```

`tests/test_pipeline.py` is grouped by what it's actually protecting against:

- **Regex true positives / edge cases** - real secrets must be caught; near-misses
  (e.g. a Luhn-invalid 16-digit number) must not false-positive.
- **PII true positives / false positives** - the false-positive group is the most
  important one to keep green. `PERSON` and `LOCATION` are the recognizers most
  prone to firing on ordinary words (tool names, band names, generic geography).
  If this group starts failing after a dependency bump, treat it as a real signal.
- **Company dictionary** - case-insensitivity, comment/blank-line handling, and a
  test that documents the substring-matching tradeoff explicitly rather than
  leaving it as a silent surprise.
- **Clean allow** - a batch of ordinary developer/office prompts that must never
  be blocked. This is the "does the tool get in people's way" check.

**Tuning entity thresholds:** `dlp/pii_scan.py` applies a per-entity confidence
cutoff (`ENTITY_THRESHOLDS`) rather than one global number, because entities like
`EMAIL_ADDRESS` score near-binary while `PERSON`/`LOCATION` are much noisier.
`tests/tune_thresholds.py` sweeps a labeled set of should-fire / should-not-fire
examples against the live analyzer and suggests a threshold per entity:

```bash
python tests/tune_thresholds.py
```

Expand `LABELED_CASES` in that script with real (redacted) examples from your own
traffic before trusting its suggestions - the built-in set is a starting point.
Run it with the production model (`en_core_web_lg`, the default) for numbers you'd
actually deploy; for fast local iteration only, override with
`SPACY_MODEL=en_core_web_sm python tests/tune_thresholds.py` (the small model is
noticeably less accurate and should never be the basis for a production threshold).

## What this does not catch

- Devices without the CA certificate installed (personal/unmanaged devices, or any
  device off the network this proxy sits on)
- Apps that use certificate pinning (they'll simply fail to connect at all rather
  than being silently unblocked - see the project notes on handling this)
- File/image content inside a request (raw bytes are captured, but not parsed -
  would need an explicit decode/OCR step to inspect PDFs or screenshots)
- Anything routed over a personal VPN that tunnels past this proxy
