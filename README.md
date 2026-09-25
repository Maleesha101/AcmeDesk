# AcmeDesk Token Security Lab

> **WARNING: This project intentionally contains insecure token-generation algorithms.** Run only in an isolated local environment. Never deploy the vulnerable configuration to the public internet. Never reuse the vulnerable token algorithms in production software.

---

## 1. Learning Objectives

After completing this lab, learners will be able to:

- Explain the difference between **token length**, **token space**, **entropy**, **randomness**, **unpredictability**, and **attackability**.
- Use **Burp Suite Sequencer** to perform statistical analysis on password-reset tokens.
- Identify at least three classes of token-generation weakness through empirical analysis.
- Distinguish between **statistical randomness** and **cryptographic unpredictability**.
- Implement a **cryptographically secure** password-reset token flow.

## 2. Scenario

AcmeDesk is a SaaS customer-support platform. Users can register, log in, request a password reset, receive a password-reset token, submit the token, and change their password.

The application contains **six** password-reset token implementations, each representing a different engineering mistake (or, for Strategy 6, the correct approach).

The learner's task: figure out which tokens are predictable, which are truly random, and why token length alone does not imply security.

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser / Burp Suite                     │
│                       (localhost:8080)                          │
└─────────────┬───────────────────────────────────────┬───────────┘
              │ HTTP requests                         │ Burp Suite
              │                                       │ intercepts
┌─────────────▼──────────┐             ┌──────────────▼────────────┐
│    Nginx (Reverse Proxy)│             │   AcmeDesk Backend         │
│    Port 8080            │◄────────────│   Port 8000                │
│    127.0.0.1 only       │   FastAPI   │                            │
│    + Security Headers   │             │   ├── Auth (register/login)│
│    + /static mount      │             │   ├── /api/*               │
│                         │             │   ├── /lab/*               │
│                         │             │   └── /reset               │
└─────────────┬───────────┘             └──────────────┬────────────┘
              │                                       │
┌─────────────▼───────────────────────────────────────▼────────────┐
│                     PostgreSQL 16                                │
│    users │ password_reset_tokens │ lab_token_samples │ sessions  │
└──────────────────────────────────────────────────────────────────┘
```

- **Nginx** serves static files and proxies `/api/*` and `/lab/*` to the backend, adding security headers (CSP, HSTS, etc.) and binding to `127.0.0.1:8080`.
- **Backend** exposes a FastAPI app with both public API endpoints (`/api/auth/*`) and lab-only endpoints (`/lab/*`).
- **Lab-only endpoints** (`/lab/*`) are gated by `LAB_MODE`. When `LAB_MODE=false`, all `/lab/*` routes return 404.
- **Instructor Mode** (`LAB_INSTRUCTOR_MODE=true`) reveals generation algorithms, entropy calculations, and expected Sequencer observations on `/lab/token-info` and `/lab/analyze-token` endpoints.
- **Production-style token storage** always stores `SHA-256(token)` in `password_reset_tokens`.
- **Lab-only plaintext sample storage** stores raw tokens in `lab_token_samples` for vulnerable strategies (documented as educational samples).

## 4. Installation

```bash
cd /home/maleesha/Labs/AcmeDesk

# Copy environment template
cp .env.example .env

# Build and start
docker compose up --build
```

The application will be available at `http://localhost:8080`.

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2

### Development (without Docker)

```bash
cd backend
pip install -r requirements.txt
export DATABASE_URL=postgresql+asyncpg://acmedesk:acmedesk_lab_password@localhost:5432/acmedesk
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## 5. Starting the Lab

```bash
# Fresh start (build images)
docker compose up --build

# Restart stopped services
docker compose up

# Stop
docker compose down

# Stop and wipe database
docker compose down -v
```

## 6. Test Accounts

Default seeded accounts (created by `scripts/seed_users.py`):

| Email | Password |
|---|---|
| alice@example.com | Password123! |
| bob@example.com | Password123! |
| admin@example.com | AdminPassword123! |

## 7. Token Strategies

Six strategies are available. When requesting a password reset via `/lab/forgot-password`, the `strategy` field selects which one to use.

### Strategy 1 — Long Timestamp Token

**Pattern:** `Base64URL(version | timestamp_ms | user_id | static_secret)`

**Weakness:** The only unpredictable component is the exact millisecond of generation. All other fields are fixed or known. Burp Sequencer will show extreme temporal correlation.

**Key lesson:** A 50-character Base64 string is meaningless security if it encodes a timestamp, a user ID, and a hardcoded secret.

### Strategy 2 — Long Counter Token

**Pattern:** `RESET-{counter:012d}-{user_id:06d}-{random_hex:8}`

**Weakness:** The counter increments by exactly 1 for each reset request per user. The 8-char random suffix is too small to meaningfully increase the search space.

**Key lesson:** A 40+ character hex string becomes trivial when most of it is sequential.

### Strategy 3 — Long Weak PRNG Token

**Pattern:** `hex(random.Random(seed).getrandbits(256))` where `seed = (user_id << 32) + int(time.time())`

**Weakness:** Python's `random.Random` uses the Mersenne Twister algorithm, which is **not** a CSPRNG. Given a known or guessable seed, the entire output is deterministic. With 624 consecutive 32-bit outputs, the full internal state can be reconstructed.

**Key lesson:** `random` ≠ `secrets`. Statistically "random-looking" output can be completely predictable if the seed space is small.

### Strategy 4 — Structured Token

**Pattern:** `v1-{date}-{user_id:06d}-{random_24bit:06x}-{signature_like:16x}`

**Weakness:** Despite looking like a JWT-signed token, only **24 bits** (6 hex chars) are truly random. The "signature" is SHA-256 of the other fields, so it provides no additional entropy. The date and user_id are typically known or guessable.

**Key lesson:** JWT-like structure does not imply cryptographic strength. A 50-char token with only 24 bits of entropy has an effective security margin of ~24 bits.

### Strategy 5 — Long Hash of Predictable Data

**Pattern:** `SHA256(email | timestamp | nonce)` where `nonce = (user_id * 1000000) + (timestamp_ms % 1000000)`

**Weakness:** A cryptographic hash does NOT create entropy — it preserves the entropy of its input. Since the input (email + timestamp + predictable nonce) has only ~35 bits of uncertainty, the 64-char hex output still has only ~35 bits of entropy.

**Key lesson:** `SHA256(weak_input) ≠ strong_token`. Hashing does not magically make predictable data unpredictable.

### Strategy 6 — Secure CSPRNG Token (Control Group)

**Pattern:** `secrets.token_urlsafe(32)`

**Strength:** 256 bits of cryptographically secure randomness from `os.urandom()`. No structure, no temporal correlation, no predictable components. The raw token is never stored — only its SHA-256 hash. Short expiration (15 min) and one-time use.

**Key lesson:** 43 Base64 characters ≈ 256 bits of true entropy. This is what production security looks like.

## 8. Token Length vs Entropy

These are different concepts:

| Concept | Definition |
|---|---|
| **Token length** | Number of characters in the token string |
| **Alphabet size** | Number of distinct symbols used (e.g., hex = 16, Base64 = 64) |
| **Possible combinations** | Alphabet size ^ token length |
| **Entropy** | The actual amount of uncertainty, measured in bits |
| **Effective entropy** | Entropy an attacker must brute-force, considering their knowledge |
| **Unpredictability** | Inability to predict future tokens from past observations |

A 64-character hexadecimal string has at most 64 × log₂(16) = 256 bits of **potential** entropy, but only if each character is independently and uniformly random from the full alphabet.

If the token is `SHA256("username")` (always the same value), its length is 64 but its effective entropy is **0 bits** — any information about the first character tells you the entire string.

## 9. Burp Suite Setup

### Step 0 — Prerequisites

- Burp Suite Professional (Community Edition can do basic Sequencer analysis)
- AcmeDesk running at `http://localhost:8080`

### Step 1 — Configure Burp Proxy

1. In Burp, navigate to **Proxy → Proxy settings**
2. Ensure Burp is listening on `127.0.0.1:8080` (default)
3. Configure your browser to use Burp as a proxy (or use Burp's built-in Chromium)
4. Install Burp's CA certificate in your browser to trust HTTPS interception

### Step 2 — Log in

1. Navigate to `http://localhost:8080/login`
2. Log in with seeded credentials (e.g., `alice@example.com` / `Password123!`)
3. Burp should intercept the login request — let it pass through

### Step 3 — Create a reset request

1. Navigate to `http://localhost:8080/lab/forgot-password`
2. Enter an email (e.g., `alice@example.com`)
3. Select a **Strategy** from the dropdown
4. Click "Send Reset Link" — Burp should intercept the POST request

### Step 4 — Capture the validation request

After sending, open the **simulated mailbox**:
1. Navigate to `http://localhost:8080/lab/mailbox/alice@example.com`
2. Copy the reset link (contains `token=...`)
3. Open a new tab and paste the URL — the token will be in `GET /lab/reset?token=...`

For Sequencer, we need a **validatable endpoint**. Use:

```
GET /api/auth/validate?token=TOKEN_HERE
```

This endpoint checks token validity **without** consuming it, making it ideal for repeated Sequencer analysis.

### Step 5 — Send to Sequencer

1. In Burp, intercept the `GET /api/auth/validate?token=...` request
2. Right-click → **Send to Sequencer** (or **Engagement tools → Send to Sequencer**)
3. Burp opens the Sequencer tab with the request loaded

### Step 6 — Configure token location

1. In Sequencer, go to the **Live Capture** tab
2. Click **Token configuration** (gear icon)
3. Set **Token location** to "Request parameter" if prompted
4. Confirm the token position in the request URL

### Step 7 — Start live capture

1. Click **Start live capture** (green play button)
2. Navigate to the validation endpoint in your browser (or run the request from Burp Repeater)
3. Burp will capture each new request

### Step 8 — Collect samples

Collect at least **100–200 samples** per strategy. Click **Stop capture** when done.

### Step 9 — Run analysis

1. Click the **Analysis** tab in Sequencer
2. Select analysis level: **Fast** for quick results, **Best quality** for thorough analysis
3. Click **Start analysis**
4. Burp will analyze:
   - **Overall randomness** (FIPS 140-2 tests)
   - **Character-level analysis** (frequency distribution per position)
   - **Bit-level analysis** (bias in individual bits)
   - **Distribution** (chi-square test)
   - **Repetition** (how often tokens repeat)
   - **Structure** (detected patterns, separators)
   - **Correlations** (between positions)

### Step 10 — Record results

For each strategy, document:

| Metric | Timestamp | Counter | Weak PRNG | Structured | Hash | Secure |
|---|---|---|---|---|---|---|
| FIPS 140-2 | | | | | | |
| Uniqueness | | | | | | |
| Repetition | | | | | | |
| Structure | | | | | | |
| Correlations | | | | | | |
| Overall | | | | | | |

### Step 11 — Compare strategies

After running all six strategies, compare results. You should observe:

- **Vulnerable strategies** show: high repetition, strong structure, predictable correlations, few unique values relative to samples
- **Secure strategy** shows: high randomness score, no detectable structure, high uniqueness, no correlations

> **Important:** Burp Sequencer is a statistical analysis tool. A "good" Sequencer result does **not** prove a token is secure against every class of attack. A token may pass all statistical tests and still be predictable if the underlying generation algorithm has a small seed space. Conversely, some vulnerable tokens may appear statistically random to Sequencer while remaining completely predictable through other means.

## 12. Exercise 1 — Timestamp Tokens

**Task:** Generate 100 tokens using the timestamp strategy, capture them, and analyze in Burp Sequencer.

1. Go to `http://localhost:8080/lab/forgot-password`
2. Set strategy to `timestamp`
3. Generate 100 tokens (or use `POST /lab/forgot-password` 100 times)
4. Open `GET /api/auth/validate?token=TOKEN` for each token in Sequencer
5. Analyze the results

**Questions to answer:**

1. How long are the tokens? (~44 characters)
2. What alphabet is used? (Base64URL)
3. Decode one: what components are inside? (version, timestamp, user_id, secret)
4. Which components are fixed vs. changing?
5. Are successive tokens correlated with time? (Yes!)
6. How much uncertainty does an attacker face if they know request timing to within 1 second? (Seconds-level timestamp, ~20 bits at most)

## 13. Exercise 2 — Counter Tokens

**Task:** Generate 100 counter-based tokens and analyze.

1. Select the `counter` strategy
2. Generate 100 tokens
3. Observe the counter field in decoded tokens

**Questions to answer:**

1. Which part of the token increments sequentially? (The 12-digit counter)
2. Is the user_id often predictable? (Often sequential across users)
3. Is the 8-char random suffix enough to prevent next-token prediction? (No — counter dominates)
4. Could you predict T(n+1) from T(n)? (Almost certainly)

## 14. Exercise 3 — Weak PRNG

**Task:** Collect 200 weak-PRNG tokens and analyze statistical randomness.

1. Select the `weak_prng` strategy
2. Generate 200 tokens
3. Analyze in Burp Sequencer

**Questions to answer:**

1. Does Burp Sequencer detect suspicious predictability? (Yes — Mersenne Twister patterns)
2. What is the seed formula? (`seed = (user_id << 32) + int(time.time())`)
3. If an attacker knows user_id ± a few seconds, what is the search space? (Seconds-level ≈ 120 possible seeds per minute)
4. Python's `random` module: CSPRNG? (No — Mersenne Twister)
5. Does `hex()` output from a deterministic PRNG look random? (Looks random, but isn't cryptographically)

## 15. Exercise 4 — Structured Tokens

**Task:** Analyze structured tokens with only 24 bits of entropy.

1. Select the `structured` strategy
2. Generate 100 tokens
3. Decode them and identify components

**Questions to answer:**

1. How many characters change between tokens? (6 hex + 16 derived sig)
2. Does the "signature" change independently? (No — derived from other fields)
3. How many bits of actual randomness exist? (24 bits = 6 hex chars)
4. What is the effective search space? (2^24 ≈ 16 million — brute-forceable in seconds)
5. What would a large encoding (Base64URL ~50 chars) provide if the entropy is only 24 bits? (No additional security)

## 16. Exercise 5 — Hash of Predictable Input

**Task:** Demonstrate that SHA-256 does not create entropy.

1. Select the `predictable_hash` strategy
2. Generate 100 tokens
3. Observe that all 64 characters appear random
4. Now: the input is `email | timestamp | nonce`, where:
   - email is known/guessable
   - timestamp is correlated with request time
   - nonce is deterministic from those inputs
5. Calculate: if timestamp is known ±1 minute, and user_id is known, how many possible inputs exist? (≈60 × a few possible user IDs)
6. The attacker computes SHA256 for each and matches against observed tokens.

**Critical insight:**
> SHA-256(a | b) where a and b are both predictable is itself predictable. A 64-character hex string has a large **representation** (it looks intimidating) but its **security** depends entirely on the entropy of the inputs that generated it.

## 17. Exercise 6 — Secure CSPRNG

**Task:** Compare statistical results with vulnerable strategies.

1. Select the `secure` strategy
2. Generate 200 tokens
3. Run Burp Sequencer analysis

**Expected observations:**

- **FIPS 140-2**: All tests pass
- **Uniqueness**: 100% (200/200 unique)
- **Structure**: None detected
- **Correlations**: None detected
- **Entropy**: ~256 bits per token

**Questions to answer:**

1. Why does the secure token look "simpler" (43 chars vs 64 hex) but provide more security? (Base64 ≈ 6 bits/char vs hex = 4 bits/char; 43 × 6 ≈ 258 bits)
2. How does the effective entropy compare to the vulnerable strategies? (Orders of magnitude higher)
3. Does token length alone explain the difference? (No — the secure token is *shorter* than most vulnerable ones but far more secure)

## 18. Comparing Sequencer Results

After completing all six exercises, compile a comparison table and answer:

| Strategy | Token Length | Alphabet | Looks Random? | Actually Random? | Predictable? | Secure? |
|---|---|---|---|---|---|---|
| Timestamp | ~44 | Base64url | Maybe | No | Yes | No |
| Counter | ~40 | Hex | No | No | Yes | No |
| Weak PRNG | 64 | Hex | Yes | No | Yes | No |
| Structured | ~50 | Hex | No | Partially | Yes | No |
| Predictable Hash | 64 | Hex | Yes | No | Yes | No |
| Secure CSPRNG | ~43 | Base64url | Yes | Yes | No | Yes |

## 19. Understanding Entropy

Entropy is **uncertainty**, not string length.

### Numerical Examples

**Example A: Short + Predictable**
- A 6-character lowercase-only password: `26^6 ≈ 308 million` possible combinations
- But if generated from a list of common words, effective entropy might be < 10 bits

**Example B: Long + Predictable**
- A 16-character lowercase token: `26^16 ≈ 2^75` possible combinations
- If generated by appending a timestamp, the attacker needs only seconds-level uncertainty: ~20 bits
- Despite 75 bits of "possible combinations", effective entropy is ~20 bits

**Example C: Hash of Predictable Input**
- SHA256("alice|1695000000|123"): 64 hex characters, but **0 bits of entropy** to the attacker who knows the inputs

**Example D: Secure 128-bit Random**
- 128 bits of entropy from `/dev/urandom` → `2^128 ≈ 3.4 × 10^38` possible values
- No structure, no temporal correlation, no predictability

**Key Takeaway:**
> `entropy ≠ string length` and `possible combinations ≠ effective security`

## 20. Why Hashing Does Not Create Entropy

A cryptographic hash function maps arbitrary-length input to fixed-length output deterministically.

```
H(predictable_input) → fixed_length_output
```

Properties:
- **Preimage resistance**: Given output y, finding x such that H(x)=y is hard
- **Collision resistance**: Hard to find two different x, x' with H(x)=H(x')
- **Deterministic**: Same input always produces same output

None of these mean the output is unpredictable when the input is known or guessable.

**Example:** If the attacker knows H(x) = SHA256("alice|timestamp|counter"), and can enumerate all plausible (timestamp, counter) pairs, they can compute SHA256 for each candidate and identify the original. The 64-char output doesn't "hide" 256 bits of information — it only preserves the entropy present in the input.

## 21. Remediation

### Production-Grade Recommendations

1. **Use a CSPRNG**:
   ```python
   import secrets
   token = secrets.token_urlsafe(32)  # 256 bits of entropy
   ```

2. **Generate at least 128 bits of cryptographically secure randomness** for appropriate use cases (32 bytes = 256 bits for password reset tokens).

3. **Store only a hash of the token**:
   ```python
   import hashlib
   token_hash = hashlib.sha256(token.encode()).hexdigest()
   store(token_hash)
   ```

4. **Set short expiration** (15 minutes is reasonable).

5. **Make tokens single-use**: Invalidate after successful use.

6. **Invalidate previous reset tokens** when a new one is issued.

### Do NOT derive reset tokens from:

- User ID
- Username
- Email address
- Timestamp
- Sequential ID
- Predictable counters
- Weak PRNGs (Python's `random` module)
- Client-controlled values

### Do NOT rely on:

- Token length as a security measure
- Base64 / hexadecimal encoding as obfuscation
- Cryptographic hashing of predictable values as entropy generation

## 22. Secure Implementation

```python
import hashlib
import secrets
from datetime import datetime, timedelta

def generate_secure_reset_token(user_id: int) -> str:
    """Generate a secure password reset token."""
    # 256 bits of CSPRNG entropy
    raw_token = secrets.token_urlsafe(32)

    # Store ONLY the hash (never the raw token)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    # Store with expiration and metadata
    store_token(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=15),
        used=False,
    )

    # Send raw token via email (simulated in this lab)
    send_email(user_id, raw_token)

    return raw_token  # For lab visibility; in production, only send via email


def validate_reset_token(user_id: int, submitted_token: str) -> bool:
    """Validate a reset token."""
    submitted_hash = hashlib.sha256(submitted_token.encode()).hexdigest()

    token_record = get_token(user_id, submitted_hash)

    if not token_record:
        return False  # Token doesn't exist
    if token_record.used_at:
        return False  # Already used
    if token_record.expires_at <= datetime.utcnow():
        return False  # Expired

    return True  # Valid
```

**Key properties:**
- CSPRNG generation (`secrets.token_urlsafe`)
- SHA-256 hashed storage (raw token never stored)
- 15-minute expiration
- One-time use (enforced via `used_at` check)
- Constant-time comparison (via hash comparison)

## 23. Common Developer Mistakes

| Mistake | Why It's Wrong | Correct Approach |
|---|---|---|
| `token = timestamp + user_id` | Easily predictable | `token = secrets.token_urlsafe(32)` |
| `token = SHA256(user_id + timestamp)` | Hash doesn't add entropy | `token = secrets.token_urlsafe(32)` |
| `token = str(secrets.token_urlsafe(64))` | Fine, but note: length ≠ entropy | `token = secrets.token_urlsafe(32)` |
| `random.random()` for tokens | `random` is not a CSPRNG | Use `secrets` module |
| `random.randint(0, N)` for tokens | Predictable with seed | `secrets.randbelow(N)` |
| `uuid.uuid4()` for tokens | **OK** — uses `os.urandom` | Acceptable alternative |
| `MD5()` or `SHA1()` for tokens | Broken hash algorithms | Use SHA-256 or BLAKE3 |

## 24. Detection Checklist

Questions for code review:

- [ ] Are tokens generated from a CSPRNG?
- [ ] Is the entropy source clearly documented and verified?
- [ ] Are tokens stored only as hashes?
- [ ] Are there any tokens derived from time, counters, or sequential IDs?
- [ ] Are all components of the token independently unpredictable?
- [ ] Does token length match intended security level? (128+ bits of entropy for high-security tokens)
- [ ] Are there any "security by obscurity" patterns (e.g., complex encoding that doesn't add entropy)?

## 25. Interview Questions

1. What is the difference between token length and token entropy?
2. Why is `random.random()` unsuitable for password reset tokens?
3. A colleague says: "SHA256(username + timestamp) produces a 64-char hex string — it's secure." What's wrong?
4. If a token is 43 Base64 characters, what is the maximum possible entropy? (≈258 bits) What is the minimum? (0 bits)
5. When would `secrets.token_urlsafe(16)` be sufficient vs `secrets.token_urlsafe(32)`?
6. How does `secrets.token_urlsafe` differ from `uuid.uuid4()`?
7. Why is storing a reset token in plaintext in a database a security issue, even with access controls?
8. What does Burp Suite Sequencer test, and what are its limitations?
9. Can a token pass all Sequencer tests and still be insecure? (Yes — e.g., MT seeded with known value)
10. How do short expiration and one-time use complement randomness as security controls?

## 26. Further Experiments

1. **Cross-strategy correlation**: Generate 100 tokens of each strategy and see which strategies share "random" tokens (e.g., hash of same input always produces same output).
2. **Time-based attack**: Record the exact time each timestamp token was generated and see if you can recover the secret string from the decoded Base64.
3. **Weak PRNG state recovery**: Research Mersenne Twister state recovery attacks and try to reconstruct the generator state from 624 samples.
4. **Burp Extensions**: Write a Burp extension that automatically decodes and visualizes the internal structure of AcmeDesk tokens.
5. **Entropy estimation**: Build a Python script that computes Shannon entropy for each strategy's output.

## 27. Cleanup

```bash
# Stop all services
docker compose down

# Remove database data entirely
docker compose down -v

# Or just clear lab data while keeping users
docker compose run --rm backend python scripts/reset_lab.py
```

---

> **This application is an educational tool. All data is local-only. No emails are sent. No external APIs are called. The vulnerable token algorithms must never be used in production software.**
