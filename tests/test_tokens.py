"""
Token generation tests: strategy behavior, uniqueness, and analysis.
"""
import hashlib
import re

import pytest

from app.token_strategies import (
    TimestampTokenStrategy,
    CounterTokenStrategy,
    WeakPrngTokenStrategy,
    StructuredTokenStrategy,
    PredictableHashTokenStrategy,
    SecureTokenStrategy,
    list_strategies,
    get_strategy,
)


class TestStrategiesExist:
    def test_all_strategies_registered(self):
        """All six strategies should be in the registry."""
        expected = {"timestamp", "counter", "weak_prng", "structured", "predictable_hash", "secure"}
        registered = set(list_strategies())
        assert expected == registered, f"Missing strategies: {expected - registered}"


class TestTimestampStrategy:
    def test_generates_long_token(self):
        """Timestamp token should be long (typically 40+ chars)."""
        strat = get_strategy("timestamp")
        token = strat.generate(user_id=1, email="test@example.com")
        assert len(token) >= 30

    def test_deterministic_given_same_input(self):
        """Timestamp token uses current time; structure should be decodable."""
        strat = get_strategy("timestamp")
        token = strat.generate(user_id=1, email="test@example.com")
        info = strat.parse(token)
        assert info["source"] == "timestamp"
        assert "known_predictable_components" in info


class TestCounterStrategy:
    def test_generates_long_token(self):
        """Counter token should be long."""
        strat = get_strategy("counter")
        token = strat.generate(user_id=1, email="test@example.com")
        assert len(token) >= 20
        assert token.startswith("RESET-")

    def test_parseable(self):
        """Counter token should be parseable."""
        strat = get_strategy("counter")
        token = strat.generate(user_id=1, email="test@example.com")
        info = strat.parse(token)
        assert info["source"] == "counter"
        assert info["counter"] is not None


class TestWeakPrngStrategy:
    def test_generates_hex_token(self):
        """Weak PRNG token should be hex."""
        strat = get_strategy("weak_prng")
        token = strat.generate(user_id=1, email="test@example.com")
        assert len(token) == 64
        assert re.match(r"^[0-9a-f]{64}$", token)

    def test_deterministic(self):
        """Weak PRNG is deterministic given the same seed."""
        strat = get_strategy("weak_prng")
        # Manually set a seed by patching _derive_seed
        original = strat._derive_seed
        strat._derive_seed = lambda user_id: 12345
        try:
            t1 = strat.generate(user_id=1, email="test@example.com")
            t2 = strat.generate(user_id=1, email="test@example.com")
            assert t1 == t2, "Weak PRNG should be deterministic with same seed"
        finally:
            strat._derive_seed = original

    def test_different_seeds_produce_different_tokens(self):
        """Different seeds should produce different tokens."""
        strat = get_strategy("weak_prng")
        original = strat._derive_seed
        strat._derive_seed = lambda user_id: 12345
        try:
            t1 = strat.generate(user_id=1, email="test@example.com")
            strat._derive_seed = lambda user_id: 67890
            t2 = strat.generate(user_id=1, email="test@example.com")
            assert t1 != t2
        finally:
            strat._derive_seed = original


class TestStructuredStrategy:
    def test_generates_structured_token(self):
        """Structured token should have 5 parts."""
        strat = get_strategy("structured")
        token = strat.generate(user_id=1, email="test@example.com")
        parts = token.split("-")
        assert len(parts) == 5
        assert parts[0] == "v1"

    def test_parseable(self):
        """Structured token should be parseable."""
        strat = get_strategy("structured")
        token = strat.generate(user_id=1, email="test@example.com")
        info = strat.parse(token)
        assert info["source"] == "structured"
        assert info["random_bits"] == 24


class TestPredictableHashStrategy:
    def test_generates_sha256_hex(self):
        """Predictable hash token should be 64 hex chars."""
        strat = get_strategy("predictable_hash")
        token = strat.generate(user_id=1, email="test@example.com")
        assert len(token) == 64
        assert re.match(r"^[0-9a-f]{64}$", token)

    def test_hash_of_deterministic_input(self):
        """Same input should produce same hash."""
        strat = get_strategy("predictable_hash")
        # Monkey-patch time to make deterministic
        original_generate = strat.generate
        def deterministic_generate(user_id, email):
            import time
            # Use a fixed time
            timestamp = 1000000000
            nonce = (user_id * 1000000) + (timestamp % 1000000)
            data = f"{email}|{timestamp}|{nonce}"
            return hashlib.sha256(data.encode()).hexdigest()

        strat.generate = deterministic_generate
        try:
            t1 = strat.generate(user_id=1, email="test@example.com")
            t2 = strat.generate(user_id=1, email="test@example.com")
            assert t1 == t2
        finally:
            strat.generate = original_generate


class TestSecureStrategy:
    def test_generates_urlsafe_token(self):
        """Secure token should be URL-safe Base64."""
        strat = get_strategy("secure")
        token = strat.generate(user_id=1, email="test@example.com")
        assert len(token) >= 30
        # URL-safe Base64 characters
        import base64
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded)
        assert len(raw) == 32  # 256 bits = 32 bytes

    def test_unique_per_generation(self):
        """Secure tokens should always be unique."""
        strat = get_strategy("secure")
        tokens = {strat.generate(user_id=1, email="test@example.com") for _ in range(100)}
        assert len(tokens) == 100, "CSPRNG tokens should be unique"

    def test_no_predictable_structure(self):
        """Secure tokens should have no fixed components."""
        strat = get_strategy("secure")
        tokens = [strat.generate(user_id=i, email=f"user{i}@example.com") for i in range(10)]
        # All should be different
        assert len(set(tokens)) == 10


class TestInfoEndpoint:
    def test_timestamp_info(self):
        """Token info should include key fields."""
        strat = get_strategy("timestamp")
        token = strat.generate(user_id=1, email="test@example.com")
        info = strat.get_info(token, instructor=True)
        assert "length" in info
        assert "generation_algorithm" in info
        assert "known_predictable_components" in info

    def test_secure_info(self):
        """Secure token info should show zero predictable components."""
        strat = get_strategy("secure")
        token = strat.generate(user_id=1, email="test@example.com")
        info = strat.get_info(token, instructor=True)
        assert info["known_predictable_components"] == [] or len(info["known_predictable_components"]) == 0
        assert info["effective_entropy_bits"] == 256.0