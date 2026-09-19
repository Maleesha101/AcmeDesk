"""
Weak PRNG token strategy (VULNERABLE).

Generation algorithm:
    seed = deterministic_seed(user_id, current_time)
    rng = random.Random(seed)
    token = rng.getrandbits(256).to_bytes(32, 'big').hex()

This uses Python's Mersenne Twister (random.Random), which is NOT a CSPRNG.
It is completely deterministic given the seed. The seed is derived from:
    seed = (user_id << 32) + int(time.time())  # or similar predictable formula

With 624 consecutive 32-bit outputs, the entire MT state can be reconstructed.
Even with fewer samples, statistical tests (e.g., Burp Sequencer) will detect
non-randomness. In a real attack, if an attacker knows the approximate time
and user_id, they can brute-force the seed space.

EFFECTIVE ENTROPY: ~32-64 bits depending on seed predictability.
"""
import random
import time
from typing import Any, Dict

from . import SECRET_KEY, TokenStrategy


class WeakPrngTokenStrategy(TokenStrategy):
    name = "weak_prng"
    label = "Long Weak PRNG Token"
    description = "Python random.Random (Mersenne Twister) with predictable seed"
    stores_plaintext_sample = True
    is_secure = False

    def _derive_seed(self, user_id: int) -> int:
        """Derive a predictable seed from user_id and current time."""
        # Seed = (user_id << 32) + current_unix_timestamp
        # This is completely deterministic and predictable
        return (user_id << 32) + int(time.time())

    def generate(self, user_id: int, email: str) -> str:
        seed = self._derive_seed(user_id)
        rng = random.Random(seed)
        # Generate 256 bits (32 bytes) of output
        bits = rng.getrandbits(256)
        return bits.to_bytes(32, "big").hex()

    def parse(self, token: str) -> Dict[str, Any]:
        if len(token) != 64:
            return {
                "source": "weak_prng",
                "structure": "malformed",
                "known_predictable_components": [],
                "alphabet_size": 16,
                "encoding": "hex",
                "entropy_bits": 0,
            }

        # Try to detect the seed by checking recent timestamps
        # (for educational demonstration)
        detected_seed = None
        detected_time = None
        for offset in range(-10, 11):  # Check ±10 seconds
            test_seed = self._derive_seed(0)  # Would need user_id
            # Can't easily reverse without user_id, but structure is clear

        return {
            "source": "weak_prng",
            "structure": "hex(random.Random(seed).getrandbits(256))",
            "seed_formula": "seed = (user_id << 32) + int(time.time())",
            "known_predictable_components": [
                "seed (deterministic from user_id + timestamp)",
                "Mersenne Twister output (deterministic given seed)",
            ],
            "alphabet_size": 16,
            "encoding": "hex",
            "entropy_bits": 40,  # ~40 bits if attacker knows approximate time ±1 min
        }

    def predictability_label(self) -> str:
        return "High (deterministic PRNG with predictable seed)"

    def entropy_estimate(self) -> float:
        return 40.0

    def recommended_usage(self) -> str:
        return "NEVER — educational example only"

    def _alphabet_name(self) -> str:
        return "Hexadecimal (0-9, a-f)"

    def _encoding_name(self) -> str:
        return "hex"

    def _generation_algorithm(self, instructor: bool = False) -> str:
        if instructor:
            return (
                "seed = (user_id << 32) + int(time.time())\n"
                "rng = random.Random(seed)  # Mersenne Twister — NOT cryptographically secure\n"
                "token = rng.getrandbits(256).to_bytes(32, 'big').hex()\n\n"
                "Python's random.Random uses the Mersenne Twister algorithm. "
                "It is deterministic and predictable. Given 624 consecutive "
                "32-bit outputs, the entire internal state can be reconstructed. "
                "Even without full state recovery, the seed space is small "
                "(≈60 bits if time known to ±1 minute, user_id known)."
            )
        return super()._generation_algorithm(instructor)