# AcmeDesk Token Lab — Student Worksheet

Name: ____________________________________  Date: ______________

Class / Section: ____________________________________

## Instructions

Follow the six exercises in the lab guide. For each, fill in the strategy table, record Sequencer results, and answer the exercise questions on this worksheet.

## Part A — Pre-Lab Questions

**Answer before starting the exercises.**

1. In your own words: what is "entropy" in the context of a password reset token?

2. A 32-character token made only of hex characters has how many possible values? (16^32 = ?)

3. A 32-character token made only of lowercase letters has how many possible values? (26^32 = ?)

4. If a token is `SHA256("password1234")` — how many bits of entropy does it have for an attacker who knows `"password1234"` is the input? (0)

5. True or False: A long random-looking string is always secure.

## Part B — Sequencer Data Log

For each strategy, record the Sequencer metrics you observe.

### Exercise 1 — Timestamp tokens

| Metric | Observed value |
|---|---|
| # samples | |
| Length | |
| Alphabet | |
| Entropy estimate | |
| Effective entropy | |
| Unique values | |
| FIPS results | |
| Structure | |
| Correlations | |

### Exercise 2 — Counter tokens

| Metric | Observed value |
|---|---|
| # samples | |
| Length | |
| Alphabet | |
| Entropy estimate | |
| Effective entropy | |
| Unique values | |
| FIPS results | |
| Structure | |
| Correlations | |

### Exercise 3 — Weak PRNG tokens

| Metric | Observed value |
|---|---|
| # samples | |
| Length | |
| Alphabet | |
| Entropy estimate | |
| Effective entropy | |
| Unique values | |
| FIPS results | |
| Structure | |
| Correlations | |

### Exercise 4 — Structured tokens

| Metric | Observed value |
|---|---|
| # samples | |
| Length | |
| Alphabet | |
| Entropy estimate | |
| Effective entropy | |
| Unique values | |
| FIPS results | |
| Structure | |
| Correlations | |

### Exercise 5 — Predictable hash tokens

| Metric | Observed value |
|---|---|
| # samples | |
| Length | |
| Alphabet | |
| Entropy estimate | |
| Effective entropy | |
| Unique values | |
| FIPS results | |
| Structure | |
| Correlations | |

### Exercise 6 — Secure CSPRNG tokens

| Metric | Observed value |
|---|---|
| # samples | |
| Length | |
| Alphabet | |
| Entropy estimate | |
| Effective entropy | |
| Unique values | |
| FIPS results | |
| Structure | |
| Correlations | |

## Part C — Exercise Questions

### Exercise 1 — Timestamp

1. What was the structure of token #3? (Decode it)

2. About how many bits of entropy did we estimate?

3. Which user-facing behavior makes timestamp tokens MORE dangerous than random 6-char tokens? (All generated at the same second share the timestamp component)

### Exercise 2 — Counter

1. Which part increased by exactly 1 between tokens?

2. Why doesn't the 8-char random suffix (+32 bits) help?

3. Estimate: if the attacker knows the counter and user, how many tokens must they try? (1 for the counter component, plus at most 2^32 for suffix — actually 2^32 for port)

### Exercise 3 — Weak PRNG

1. Did the tokens pass Sequencer? (Probably "suspicious" due to Mersenne Twister patterns)

2. What seed values feed the PRNG?

3. Why isn't `random.getrandbits` secure here?

### Exercise 4 — Structured

1. List the components:

2. How many bits of real entropy?

3. Estimate attack time if attacker knows timestamp ±60s and user ID (±60 values on average, so ≈3600 seconds * attempts/sec... actually 1 try per value = 3600 tries total for the 60s window... 60–120 candidates, not 3600. The user ID is a single guess)

### Exercise 5 — Predictable hash

1. What is the token length? (64 hex chars)

2. What are the three inputs to the hash?

3. How many candidate inputs must be tested per second? (timestamp ± 60 = 121 values × user_id)

### Exercise 6 — Secure

1. What is the entropy per character? (6 bits)

2. How many bits total? (≈256)

3. Is 128 bits enough for a reset token? (Yes, with margin)

## Part D — Reflection

1. Which strategy would you expect to have the *highest* Sequencer "effectiveness" score, yet still be insecure? Why?

2. In production, why don't we send the raw token in the URL? (Logs)

3. Should we tell users whether an email exists during password reset? (No — enumeration)

4. What is the single most important takeaway from this lab?

## Submission Checklist

- [ ] Pre-lab questions answered
- [ ] All 6 Sequencer data logs completed
- [ ] All exercise questions answered
- [ ] Final reflection completed
- [ ] Sequencer HTML reports (optional but recommended)
