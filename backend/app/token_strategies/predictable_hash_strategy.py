"""
Predictable hash token strategy (VULNERABLE).

Generation algorithm:
    nonce = deterministic_nonce(user_id, time)
    token = sha256(f"{email}|{timestamp}|{nonce}").hexdigest()

The token is a 64-character SHA-256 hex string, which LOOKS very secure.
However, the INPUT to the hash is entirely predictable:
- email: known or guessable
- timestamp: correlated with request time
- nonce: derived deterministically (e.g., counter or weak PRNG)

A cryptographic hash does NOT create entropy. It only preserves the entropy
of its input. If the input has N bits of entropy, the output has at most
N bits of entropy (and exactly N if the hash is preimage-resistant).

An attacker who can predict or enumerate the input space can compute the
corresponding hashes and match against observed tokens.

EFFECTIVE ENTROPY: Equal to entropy of input (typically < 40 bits).
"""
import hashlib
import time
from typing import Any, Dict

from . import SECRET_KEY, TokenStrategy


class PredictableHashTokenStrategy(TokenStrategy):
    name = "predictable_hash"
    label = "Long Hash of Predictable Data"
    description = "SHA-256(username|timestamp|predictable_nonce) — 64 hex chars"
    stores_plaintext_sample = True
    is_secure = False

    def _derive_nonce(self, user_id: int) -> int:
        """Derive a predictable nonce from user_id and time."""
        # Use a simple formula: nonce = (user_id * 1000000) + (time % 1000000)
        # This makes the nonce predictable if time is known
        return (user_id * 1000000) + (int(time.time() * 1000) % 1000000)

    def generate(self, user_id: int, email: str) -> str:
        timestamp = int(time.time())
        nonce = self._derive_nonce(user_id)
        data = f"{email}|{timestamp}|{nonce}"
        return hashlib.sha256(data.encode()).hexdigest()

    def parse(self, token: str) -> Dict[str, Any]:
        if len(token) != 64:
            return {
                "source": "predictable_hash",
                "structure": "malformed",
                "known_predictable_components": [],
                "alphabet_size": 16,
                "encoding": "hex",
                "entropy_bits": 0,
            }

        return {
            "source": "predictable_hash",
            "structure": "SHA256(email|timestamp|nonce) → 64 hex chars",
            "input_format": "email|unix_timestamp|nonce",
            "nonce_formula": "nonce = (user_id * 1000000) + (timestamp_ms % 1000000)",
            "known_predictable_components": [
                "email (known or guessable)",
                "timestamp (correlated with request time)",
                "nonce (deterministic from user_id + timestamp)",
            ],
            "alphabet_size": 16,
            "encoding": "hex",
            "entropy_bits": 35,  # ~35 bits if time ±1 min and email known
        }

    def predictability_label(self) -> str:
        return "High (hash of predictable input)"

    def entropy_estimate(self) -> float:
        return 35.0

    def recommended_usage(self) -> str:
        return "NEVER — educational example only"

    def _alphabet_name(self) -> str:
        return "Hexadecimal (0-9, a-f)"

    def _encoding_name(self) -> str:
        return "hex"

    def _generation_algorithm(self, instructor: bool = False) -> str:
        if instructor:
            return (
                "nonce = (user_id * 1000000) + (timestamp_ms % 1000000)\n"
                "data = f'{email}|{timestamp}|{nonce}'\n"
                "token = sha256(data).hexdigest()  # 64 hex chars\n\n"
                "KEY LESSON: A cryptographic hash does NOT create entropy. "
                "It only preserves the entropy of its input. If the input "
                "space has only ~35 bits of entropy (timestamp ±1 min, "
                "known email, deterministic nonce), the 64-char SHA-256 "
                "output still only has ~35 bits of entropy. An attacker "
                "can simply enumerate the input space and hash each candidate."
            )
        return super()._generation_algorithm(instructor)