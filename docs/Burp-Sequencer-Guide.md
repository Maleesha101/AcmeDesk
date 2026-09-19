# Burp Sequencer Guide — Capturing and Analyzing AcmeDesk Tokens

This guide walks through using **Burp Suite Sequencer** to capture and analyze AcmeDesk password-reset tokens. It applies to all six token strategies.

## Why Sequencer?

Sequencer is the standard tool for analyzing the quality of session tokens. It applies statistical tests to samples to detect bias, correlation, and structure. For this lab it doubles as the "test harness" — the same tools a penetration tester would use against a real token.

## Prerequisites

- Burp Suite Professional (Community Edition can run Sequencer but with a live-capture token limit of 100 samples; labs that need 200 samples → use attack tokens with the built-in browser or manually configure Python series)
- AcmeDesk running (see README §4)
- A modern browser (Chrome/Firefox) with Burp proxy configured
- Burp CA certificate installed and trusted

> **Community Edition note:** Burp Sequencer in Community Edition allows token capture up to the live capture button; the **token limit** is 1000 tokens for live capture in Community Edition. For labs collecting 100–200 samples this is fine. Analysis "Best quality" load is fine too. Some aggressive analysis (400k requests) may hit Community limits — "Fast" analysis is enough for all exercises.

## Capturing Tokens — Manual Method

### Method A — Burp Repeater

1. Obtain one token by any means (e.g., `GET /api/auth/forgot-password?strategy=...`)
2. In Burp, right-click the request → **Send to Repeater** (or **Engagement tools → Send to Repeater**)
3. In Repeater, right-click → **Send to Sequencer**
4. Sequencer will open with the token parameter pre-selected

### Method B — Intercept + Browser

1. Open the lab in Burp's built-in browser
2. Navigate to a reset-link endpoint, intercept, copy token, release
3. Paste the token into Repeater as a `GET /api/auth/validate?token=...`
4. Send to Sequencer

### Method C — Live Capture from a Tampered Request

Sometimes the token only appears inside the response body (e.g., the mailbox page shows the link). Burp can still grab it:

1. Right-click the HTML body → **Save item**
2. Or use **Repeater** and **Send to Sequencer** from the raw body
3. Set token location to "Response extract" — but for this lab the simple request-parameter method is fine

### Method D — Bulk generation

For the lab's `weak_prng`, `hash`, `secure` strategies, live capture from the **validate** endpoint works perfectly because every token returns the same validation URL.

For a robust approach, install the **acmedesk_bulk_generator** into Burp:

1. **Proxy → Options → Misc → 2. Sessions → Session handling rules** (not needed for this)
2. The simplest automation is Burp **Intruder**:

**Intruder bulk capture:**
1. Right-click the `GET /api/auth/validate?token=SAMPLETOKEN` request → **Send to Intruder**
2. Set payload position on the token value with `§TOKEN§`
3. Payload type: **Brute forcer** with charset covering the token alphabet
4. **Resource pool → Requests per thread**: 1 (Sequencer needs sequential tokens)
5. **Intruder → Attack**

> ⚠️ Do **not** use Intruder to *create* new tokens for analysis — use the app's own `forgot-password` + `generate-samples` flow, then feed those into the validate endpoint.

## Configuring the Token Location

After sending to Sequencer:

1. In the **Sequencer** tab, click **Token configuration** (gear)
2. Set **Token location**:
   - **Request parameter** — token appears in URL query string
   - **Custom location** — for header or form-field analysis
3. Burp will highlight the token region in yellow

> For tokens that live in *request headers* (like `X-Reset-Token`), set location to that header.

## Live Capture

1. Click **Start live capture**
2. Switch to the browser and perform the action that triggers a new token
3. Burp stores each sample
4. When you have enough samples (>100, ideally 200+), click **Stop capture**

### If live capture doesn't run

- The token must appear in the **request** — use the validate endpoint
- The browser must go through Burp proxy (check Proxy → HTTP history for your requests)
- Don't let Burp block the request — pass it through

### Manual sample entry

If you prefer, you can paste raw tokens directly:

1. **Sequencer → Manually load**
2. Paste each token on its own line
3. Click **Load**

## Running Analysis

1. After capturing samples, click **Analysis** tab
2. Choose analysis level:
   - **Fast** — quick tests, enough for educational comparison
   - **Best quality** — thorough tests, more requests to server
3. Click **Start analysis**

Burp will now send each captured token to the live server (the target of the original request) **many times** to gather statistical information about the response. It will:

- Send 100 requests during the level-1 (factor) phase
- Maybe 1,000+ requests during deeper analysis
- Monitor for token changes

> This is why the **validate** endpoint exists: it returns the same token in the same way every time (200, no consumption), giving Sequencer a stable target — a stable token helps Sequencer's analysis.

## Interpretation Table

| Metric | What it means | Effect on judgement |
|---|---|---|
| **Entropy estimation** | Total effective bits of uncertainty | Higher = better |
| **Significance level** | Confidence that the measured bias isn't due to chance | > 0.95 means bias detected |
| **FIPS 140-2** | Randomness tests | All pass = looks random |
| **Character-level analysis** | Frequencies per position | Uniform = less structure |
| **Chi-square** | Bias of character distribution | High = bad |
| **Correlations** | Inter-position correlations | None = good |
| **Uniqueness** | How many distinct values | 100% = good |
| **Repetition** | Repeated tokens in sample | 0% = good |

## Common Gotchas

1. **Token in URL & Sequencer copies old token** — make sure your intercept captures the request *with* the token; don't sanitize it
2. **`...` (ellipsis) truncation** — some token strings contain 2 `-` and `_`; Burp may truncate at 50 chars in the display but the full token is sent
3. **Sequencer won't capture tokens in the response** — use the validate-request method
4. **Rate limiting** — none in this lab, but a real app might block rapid sampling. Solve it by spacing requests (Sequencer's "Live capture" already spaces them)
5. **HSTS intercept** — if the browser keeps upgrading HTTP→HTTPS and failing, disable HSTS enforcement in the browser or MITM the 8080 host as HTTP only

## Sequencer + High Token Volumes

The vulnerable strategies produce tokens that trigger **all** Sequencer's "suspicious" indicators:

- **REPETITION**: Counter strategy repeats tokens for large user counts (counter-only = 100% repeats)
- **POSSIBLE STRUCTURE**: Structured tokens (date part) clearly separated
- **TIMING DEPENDENCE**: Timestamp and weak-PRNG tokens correlate with generation time
- **WEAK SEQUENCER SCORE**: overall score in the "suspicious" range

Use the **Sequencer results comparison table** (README §17) to compare the strategies side by side.

## Automating Token Capture (Python)

For large-scale analysis, or if you prefer reproducibility:

```python
"""Fetch tokens from validated strategy via REST API."""
import requests

BASE = "http://localhost:8080"

def fetch_tokens(strategy: str, n: int = 200) -> list[str]:
    """Return n tokens for the given strategy."""
    tokens = []
    for _ in range(n):
        r = requests.get(f"{BASE}/api/auth/forgot-password",
                         params={"email": "alice@example.com",
                                 "strategy": strategy})
        r.raise_for_status()
        tokens.append(r.json()["reset_token"])
    return tokens
```

Save as `scripts/fetch_tokens.py` and run:

```bash
python scripts/fetch_tokens.py timestamp > tokens_timestamp.txt
```

Then paste contents into Sequencer → Manually load.

## Sequencer Reports

After analysis, Burp can produce an HTML report:

1. In the **Analysis** tab, click **Report** (or right-click → **Report**)
2. Choose HTML
3. Save to `reports/sequencer_timestamp.html`

Submit these with your lab report.
