"""
Secure CSPRNG token strategy (SECURE - CONTROL GROUP).

Generation algorithm:
    token = secrets.token_urlsafe(32)

This uses Python's `secrets` module, which wraps `os.urandom` (or
`getrandom` on Linux) — a cryptographically secure random number generator.

Properties:
- 32 bytes = 256 bits of cryptographically secure randomness
- URL-safe Base64 encoding (43-44 chars after padding removal)
- No predictable structure, no temporal correlation
- Each token is statistically independent
- Properly stored: only SHA-256 hash stored server-side

This is the CORRECT way to generate password reset tokens.
Use this as the control group when comparing Burp Sequencer results.

EFFECTIVE ENTROPY: 256 bits (cryptographically secure).
"""
import secrets
from typing import Any, Dict

from . import TokenStrategy


class SecureTokenStrategy(TokenStrategy):
    name = "secure"
    label = "Secure CSPRNG Token"
    description = "secrets.token_urlsafe(32) — 256 bits of cryptographic entropy"
    stores_plaintext_sample = False  # Secure tokens only stored as hash
    is_secure = True

    def generate(self, user_id: int, email: str) -> str:
        return secrets.token_urlsafe(32)

    def parse(self, token: str) -> Dict[str, Any]:
        # Validate base64url format
        try:
            # Add padding if needed
            padded = token + "=" * (-len(token) % 4)
            import base64
            raw = base64.urlsafe_b64decode(padded)
            raw_len = len(raw)
        except Exception:
            return {
                "source": "secure",
                "structure": "malformed",
                "known_predictable_components": [],
                "alphabet_size": 64,
                "encoding": "base64url",
                "entropy_bits": 0,
            }

        return {
            "source": "secure",
            "structure": "secrets.token_urlsafe(32) → 256 random bits",
            "raw_bytes": raw_len,
            "bits_of_entropy": raw_len * 8,
            "known_predictable_components": [],  # None!
            "alphabet_size": 64,
            "encoding": "base64url",
            "entropy_bits": 256.0,
        }

    def predictability_label(self) -> str:
        return "Negligible (cryptographically secure)"

    def entropy_estimate(self) -> float:
        return 256.0

    def recommended_usage(self) -> str:
        return "PRODUCTION — use this for real password reset tokens"

    def _alphabet_name(self) -> str:
        return "Base64URL (A-Z, a-z, 0-9, -, _)"

    def _encoding_name(self) -> str:
        return "base64url"

    def _generation_algorithm(self, instructor: bool = False) -> str:
        if instructor:
            return (
                "token = secrets.token_urlsafe(32)\n\n"
                "This uses Python's `secrets` module which wraps `os.urandom()` "
                "(or `getrandom()` syscall on Linux) — a CSPRNG seeded from the "
                "OS entropy pool. Each token contains 256 bits of independent, "
                "unpredictable randomness. No structure, no correlation, no "
                "predictable components. Store ONLY the SHA-256 hash server-side."
            )
        return super()._generation_algorithm(instructor)