"""
Token strategy registry for AcmeDesk Token Security Lab.

This package implements six password-reset token generation strategies:
five intentionally vulnerable strategies and one cryptographically secure
control. Each strategy implements a common interface so the password-reset
workflow can switch strategies without structural changes to the API.
"""
import importlib
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

SECRET_KEY = "AcmeDesk_Lab_Static_Secret_v1"  # Used in vulnerable strategies


class TokenStrategy:
    """
    Base class for token strategies.

    A TokenStrategy is responsible for:
    1. Generating a raw token string for a given user_id/email.
    2. Extracting metadata from a raw token (for analysis & validation).
    3. Providing an educational summary of how the strategy works.
    """

    # Registry key (matches the DB strategy column)
    name: str = "base"
    # Human-readable label
    label: str = "Base Strategy"
    # Short description for the token laboratory page
    description: str = "Base token strategy"
    # Whether this strategy stores raw tokens in the sample table
    stores_plaintext_sample: bool = False
    # Whether this strategy is cryptographically secure
    is_secure: bool = False

    def generate(self, user_id: int, email: str) -> str:
        """Generate a raw, plaintext token for the given user."""
        raise NotImplementedError

    def parse(self, token: str) -> dict:
        """Parse a raw token and return its components and metadata."""
        raise NotImplementedError

    def get_info(self, token: str, instructor: bool = False) -> dict:
        """Return analytical information about a token."""
        parsed = self.parse(token)
        return {
            "token": token,
            "length": len(token),
            "alphabet_size": parsed.get("alphabet_size", 64),
            "encoding": parsed.get("encoding", "unknown"),
            "structure": parsed.get("structure", ""),
            "source": parsed.get("source", ""),
            "known_predictable_components": parsed.get(
                "known_predictable_components", []
            ),
            "generation_algorithm": self._generation_algorithm(instructor),
            "effective_entropy_bits": parsed.get("entropy_bits"),
            "instructor_only": not instructor,
        }

    def _generation_algorithm(self, instructor: bool = False) -> str:
        """Return the generation description. Only revealed in instructor mode."""
        if instructor:
            return self.__doc__ or "See source code"
        return "Educational strategy — enable INSTRUCTOR_MODE to view details."

    def lab_table_entry(self, token: str) -> dict:
        """Return an entry for the token laboratory comparison table."""
        return {
            "strategy": self.name,
            "token_example": token,
            "length": len(token),
            "alphabet": self._alphabet_name(),
            "alphabet_size": self._alphabet_size(),
            "encoding": self._encoding_name(),
            "generation": self.description,
            "predictability": self.predictability_label(),
            "effective_entropy_bits": self.entropy_estimate(),
            "recommended_usage": self.recommended_usage(),
            "instructor_only": False,
        }

    def _alphabet_name(self) -> str:
        return "mixed"

    def _alphabet_size(self) -> int:
        return 64

    def _encoding_name(self) -> str:
        return "base64url"

    def predictability_label(self) -> str:
        raise NotImplementedError

    def entropy_estimate(self) -> float:
        raise NotImplementedError

    def recommended_usage(self) -> str:
        raise NotImplementedError


# --- Strategy Registry ---
_strategies: dict[str, TokenStrategy] = {}


def register_strategy(strategy: TokenStrategy):
    """Register a strategy in the global registry."""
    _strategies[strategy.name] = strategy
    return strategy


def get_strategy(name: str) -> TokenStrategy:
    """Look up a strategy by name."""
    if name not in _strategies:
        raise ValueError(f"Unknown token strategy: {name}")
    return _strategies[name]


def list_strategies() -> list[str]:
    """Return names of all registered strategies."""
    return list(_strategies.keys())


def get_all_strategies() -> list[TokenStrategy]:
    """Return all registered strategies."""
    return list(_strategies.values())


# Register strategies eagerly so they are available on import
from .timestamp_strategy import TimestampTokenStrategy
from .counter_strategy import CounterTokenStrategy
from .weak_prng_strategy import WeakPrngTokenStrategy
from .structured_strategy import StructuredTokenStrategy
from .predictable_hash_strategy import PredictableHashTokenStrategy
from .secure_strategy import SecureTokenStrategy

register_strategy(TimestampTokenStrategy())
register_strategy(CounterTokenStrategy())
register_strategy(WeakPrngTokenStrategy())
register_strategy(StructuredTokenStrategy())
register_strategy(PredictableHashTokenStrategy())
register_strategy(SecureTokenStrategy())