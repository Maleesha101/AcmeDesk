"""
Structured token strategy (VULNERABLE).

Generation algorithm:
    token = f"v1-{date}-{user_id:06d}-{random_24bit:06x}-{signature_like:16x}"

Where:
- v1: fixed version prefix
- date: YYYYMMDD (e.g., 20260916)
- user_id: 6-digit zero-padded
- random_24bit: 24 bits of actual randomness (6 hex chars)
- signature_like: 16 hex chars that LOOK like a signature but are derived

The signature_like component is computed as:
    signature_like = sha256(f"{date}{user_id}{random_24bit}{SECRET_KEY}")[:16]

This LOOKS like a signed token (JWT-like) but the 'signature' is deterministic
given the other fields. Only 24 bits (6 hex chars) of actual entropy exist.

An attacker who can observe multiple tokens will see:
- Fixed version
- Date changes only daily
- User ID often sequential or known
- Only 6 hex chars change unpredictably
- 'Signature' changes deterministically with the random part

EFFECTIVE ENTROPY: 24 bits (from the random component only).
"""
import hashlib
import secrets
from datetime import datetime
from typing import Any, Dict

from . import SECRET_KEY, TokenStrategy


class StructuredTokenStrategy(TokenStrategy):
    name = "structured"
    label = "Structured Token (Version|Date|UserID|Random|Signature)"
    description = "Partially structured token with only 24 bits of entropy"
    stores_plaintext_sample = True
    is_secure = False

    def generate(self, user_id: int, email: str) -> str:
        date_str = datetime.utcnow().strftime("%Y%m%d")
        random_24bit = secrets.randbits(24)  # Only 24 bits of actual entropy
        random_hex = f"{random_24bit:06x}"

        # Compute deterministic "signature"
        data = f"{date_str}{user_id:06d}{random_hex}{SECRET_KEY}"
        sig = hashlib.sha256(data.encode()).hexdigest()[:16]

        return f"v1-{date_str}-{user_id:06d}-{random_hex}-{sig}"

    def parse(self, token: str) -> Dict[str, Any]:
        parts = token.split("-")
        if len(parts) != 5:
            return {
                "source": "structured",
                "structure": "malformed",
                "known_predictable_components": [],
                "alphabet_size": 16,
                "encoding": "hex",
                "entropy_bits": 0,
            }

        version, date_str, user_id_str, random_hex, sig = parts
        user_id = int(user_id_str)

        return {
            "source": "structured",
            "structure": "v1-YYYYMMDD-user_id(6digits)-random(6hex)-sig(16hex)",
            "version": version,
            "date": date_str,
            "date_iso": datetime.strptime(date_str, "%Y%m%d").date().isoformat(),
            "user_id": user_id,
            "random_hex": random_hex,
            "random_bits": 24,
            "signature_like": sig,
            "known_predictable_components": [
                "version (fixed 'v1')",
                "date (changes daily, known to attacker)",
                "user_id (often known or sequential)",
                "signature (deterministic from other fields)",
            ],
            "alphabet_size": 16,
            "encoding": "hex",
            "entropy_bits": 24,
        }

    def predictability_label(self) -> str:
        return "High (only 24 bits unpredictable)"

    def entropy_estimate(self) -> float:
        return 24.0

    def recommended_usage(self) -> str:
        return "NEVER — educational example only"

    def _alphabet_name(self) -> str:
        return "Hexadecimal (0-9, a-f)"

    def _encoding_name(self) -> str:
        return "hex"

    def _generation_algorithm(self, instructor: bool = False) -> str:
        if instructor:
            return (
                "date = datetime.utcnow().strftime('%Y%m%d')\n"
                "random_24bit = secrets.randbits(24)  # ONLY 24 bits of entropy!\n"
                "random_hex = f'{random_24bit:06x}'\n"
                "data = f'{date}{user_id:06d}{random_hex}{SECRET_KEY}'\n"
                "sig = sha256(data).hexdigest()[:16]\n"
                "token = f'v1-{date}-{user_id:06d}-{random_hex}-{sig}'\n\n"
                "The token LOOKS like a signed JWT (version|payload|signature) "
                "but the 'signature' provides NO additional entropy — it is "
                "deterministically derived from the other fields. Only the "
                "6 hex chars (24 bits) are truly random."
            )
        return super()._generation_algorithm(instructor)