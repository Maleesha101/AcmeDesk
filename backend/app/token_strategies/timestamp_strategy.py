"""
Timestamp-based token strategy (VULNERABLE).

Generation algorithm:
    token = base64url(version | timestamp_ms | user_id | static_secret)

The token contains:
- version: fixed "v1" (4 chars when encoded)
- timestamp: milliseconds since epoch (13 digits)
- user_id: integer (variable length)
- static_secret: fixed 16-byte secret

The ONLY unpredictable element is the exact millisecond the request arrives.
An attacker who knows the approximate request time (within seconds) faces
a tiny search space. With multiple samples, the temporal correlation is
immediately visible.

EFFECTIVE ENTROPY: ~0-20 bits depending on attacker knowledge.
"""
import base64
import time
from datetime import datetime
from typing import Any, Dict

from . import SECRET_KEY, TokenStrategy


class TimestampTokenStrategy(TokenStrategy):
    name = "timestamp"
    label = "Long Timestamp Token"
    description = "Base64URL-encoded timestamp + user ID + static secret"
    stores_plaintext_sample = True
    is_secure = False

    def generate(self, user_id: int, email: str) -> str:
        version = b"v1"
        timestamp_ms = int(time.time() * 1000)
        # Pack as: version|timestamp|user_id|secret
        data = f"{version.decode()}|{timestamp_ms}|{user_id}|{SECRET_KEY}".encode()
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    def parse(self, token: str) -> Dict[str, Any]:
        # Decode base64url
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded).decode()
        except Exception:
            return {
                "source": "timestamp",
                "structure": "malformed",
                "known_predictable_components": [],
                "alphabet_size": 64,
                "encoding": "base64url",
                "entropy_bits": 0,
            }

        parts = decoded.split("|")
        if len(parts) != 4:
            return {
                "source": "timestamp",
                "structure": "malformed",
                "known_predictable_components": [],
                "alphabet_size": 64,
                "encoding": "base64url",
                "entropy_bits": 0,
            }

        version, timestamp_str, user_id_str, secret = parts
        timestamp_ms = int(timestamp_str)

        return {
            "source": "timestamp",
            "structure": "v1|timestamp_ms|user_id|static_secret",
            "version": version,
            "timestamp_ms": timestamp_ms,
            "timestamp_iso": datetime.fromtimestamp(timestamp_ms / 1000).isoformat(),
            "user_id": int(user_id_str),
            "static_secret": secret,
            "known_predictable_components": [
                "version (fixed)",
                "timestamp (correlated with request time)",
                "user_id (often sequential)",
                "static_secret (constant)",
            ],
            "alphabet_size": 64,
            "encoding": "base64url",
            "entropy_bits": 20,  # ~20 bits if attacker knows time window ±1 minute
        }

    def predictability_label(self) -> str:
        return "Very High (temporal correlation)"

    def entropy_estimate(self) -> float:
        return 20.0

    def recommended_usage(self) -> str:
        return "NEVER — educational example only"

    def _alphabet_name(self) -> str:
        return "Base64URL (A-Z, a-z, 0-9, -, _)"

    def _encoding_name(self) -> str:
        return "base64url"

    def _generation_algorithm(self, instructor: bool = False) -> str:
        if instructor:
            return (
                "token = base64url('v1' + '|' + timestamp_ms + '|' + user_id + '|' + SECRET_KEY)\n"
                "where SECRET_KEY is a fixed string embedded in the source code.\n"
                "The only variable component is timestamp_ms (millisecond precision)."
            )
        return super()._generation_algorithm(instructor)