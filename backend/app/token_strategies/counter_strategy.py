"""
Counter-based token strategy (VULNERABLE).

Generation algorithm:
    counter = increment_and_get(user_id)
    token = f"RESET-{counter:012d}-{user_id:06d}-{random_hex(8)}"

The token contains:
- Fixed prefix "RESET-"
- 12-digit zero-padded counter (monotonically increasing per user)
- 6-digit zero-padded user_id
- 8 hex characters of pseudo-random filler (32 bits)

The counter is the dominant component and advances by exactly 1 for each
reset request. An attacker observing two tokens can predict the next
counter value with near certainty. The random filler is too small to
meaningfully increase search space.

EFFECTIVE ENTROPY: ~32 bits (from the random filler only, if counter unknown).
But the counter is trivially predictable.
"""
import secrets
from datetime import datetime
from typing import Any, Dict

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from . import SECRET_KEY, TokenStrategy
from ..models import LabCounter


class CounterTokenStrategy(TokenStrategy):
    name = "counter"
    label = "Long Counter Token"
    description = "Sequential counter + user ID + small random suffix"
    stores_plaintext_sample = True
    is_secure = False

    async def _get_next_counter(self, db: AsyncSession, user_id: int) -> int:
        """Atomically increment and return the per-user counter."""
        result = await db.execute(
            select(LabCounter).where(LabCounter.user_id == user_id)
        )
        counter_row = result.scalar_one_or_none()
        if counter_row:
            counter_row.counter += 1
            counter_row.updated_at = datetime.utcnow()
        else:
            counter_row = LabCounter(user_id=user_id, counter=1)
            db.add(counter_row)
        await db.flush()
        return counter_row.counter

    def generate(self, user_id: int, email: str) -> str:
        # This is a fallback for non-DB contexts (shouldn't be used in production flow)
        import time
        counter = int(time.time() * 1000) % 10**12
        random_suffix = secrets.token_hex(8)
        return f"RESET-{counter:012d}-{user_id:06d}-{random_suffix}"

    async def generate_with_db(self, db: AsyncSession, user_id: int, email: str) -> str:
        """Generate token with atomic counter increment from database."""
        counter = await self._get_next_counter(db, user_id)
        random_suffix = secrets.token_hex(8)
        return f"RESET-{counter:012d}-{user_id:06d}-{random_suffix}"

    def parse(self, token: str) -> Dict[str, Any]:
        # Expected format: RESET-{counter:012d}-{user_id:06d}-{random_hex:8}
        parts = token.split("-")
        if len(parts) != 4:
            return {
                "source": "counter",
                "structure": "malformed",
                "known_predictable_components": [],
                "alphabet_size": 16,
                "encoding": "hex",
                "entropy_bits": 0,
            }

        prefix, counter_str, user_id_str, random_suffix = parts
        counter = int(counter_str)
        user_id = int(user_id_str)

        return {
            "source": "counter",
            "structure": "RESET-{counter:012d}-{user_id:06d}-{random_hex:8}",
            "prefix": prefix,
            "counter": counter,
            "user_id": user_id,
            "random_suffix": random_suffix,
            "known_predictable_components": [
                "prefix (fixed 'RESET')",
                "counter (monotonically increasing by 1)",
                "user_id (often sequential across users)",
            ],
            "alphabet_size": 16,
            "encoding": "hex",
            "entropy_bits": 32,  # Only the 8 hex chars (32 bits) are random
        }

    def predictability_label(self) -> str:
        return "Extremely High (sequential counter)"

    def entropy_estimate(self) -> float:
        return 32.0

    def recommended_usage(self) -> str:
        return "NEVER — educational example only"

    def _alphabet_name(self) -> str:
        return "Hexadecimal (0-9, a-f)"

    def _encoding_name(self) -> str:
        return "hex"

    def _generation_algorithm(self, instructor: bool = False) -> str:
        if instructor:
            return (
                "counter = atomic_increment_per_user(user_id)\n"
                "random_suffix = secrets.token_hex(8)  # 32 bits\n"
                "token = f'RESET-{counter:012d}-{user_id:06d}-{random_suffix}'\n\n"
                "The counter is stored in lab_counters table and increments by 1 "
                "for each reset request. Only the 8-char hex suffix is random."
            )
        return super()._generation_algorithm(instructor)