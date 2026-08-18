# mitmproxy DLP addon

A three-layer DLP scanner wired into [mitmproxy](https://mitmproxy.org) to inspect
and block outbound prompts to AI tools that contain confidential company data.

## How it works

1. A device with the mitmproxy CA certificate installed sends an HTTPS request to
   an approved AI domain (Claude, ChatGPT, etc.)
2. mitmproxy intercepts and decrypts the connection
3. `mitm_addon.py` checks if the destination is one of the approved `AI_DOMAINS`
4. If so, the request body is handed to `dlp/pipeline.py`, which runs it through:
   - `dlp/regex_rules.py` - structured secrets (API keys, credit cards, SSNs, etc.)
   - `dlp/pii_scan.py` - Presidio PII detection + your company dictionary
   - `dlp/llm_classifier.py` - optional Claude-based contextual classifier (off by
     default - see `USE_LLM_CLASSIFIER` below)
5. If anything is found, mitmproxy returns a `403` with a plain-text reason instead
   of forwarding the request. Otherwise, it passes through untouched.

## Setup

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
cp .env.example .env   # fill in ANTHROPIC_API_KEY only if you'll use the classifier layer
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
- `USE_LLM_CLASSIFIER` (env var, default `false`) - whether Layer 3 runs on live
  traffic. It's a real API call in the request path and adds latency to every
  request it processes - start with it off, confirm the fast layers behave well,
  then turn on once you're comfortable with the added latency.
- `company_dictionary.txt` - one internal term per line, case-insensitive match.

## What this does not catch

- Devices without the CA certificate installed (personal/unmanaged devices, or any
  device off the network this proxy sits on)
- Apps that use certificate pinning (they'll simply fail to connect at all rather
  than being silently unblocked - see the project notes on handling this)
- File/image content inside a request (raw bytes are captured, but not parsed -
  would need an explicit decode/OCR step to inspect PDFs or screenshots)
- Anything routed over a personal VPN that tunnels past this proxy
