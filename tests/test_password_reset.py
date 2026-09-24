"""
Password reset tests: forgot, mailbox, token validation, reset consumption.
"""
import re
import pytest

BASE_URL = "http://localhost:8080/api"


def extract_token_from_mailbox(mailbox_response):
    """Extract the first token from mailbox HTML/JSON response."""
    text = mailbox_response.text
    match = re.search(r'http://localhost:8080/reset\?token=([^\s<"\']+)', text)
    if match:
        return match.group(1)
    # Try JSON response
    try:
        data = mailbox_response.json()
        if isinstance(data, list) and len(data) > 0:
            entry = data[0]
            if isinstance(entry, dict):
                if "token" in entry:
                    return entry["token"]
                if "body" in entry:
                    token_match = re.search(r'token=([^\s<"\']+)', entry["body"])
                    if token_match:
                        return token_match.group(1)
    except Exception:
        pass
    return None


class TestForgotPassword:
    @pytest.mark.asyncio
    async def test_forgot_password_timestamp(self, async_client):
        """Password reset request accepts a strategy parameter."""
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": "reset1@example.com", "password": "Pass123!"})
        response = await async_client.post(
            f"{BASE_URL}/auth/forgot-password",
            json={"email": "reset1@example.com", "strategy": "timestamp"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
    @pytest.mark.asyncio
    async def test_forgot_password_nonexistent_user(self, async_client):
        """Forgot password for unknown user should still return success (email enumeration protection)."""
        response = await async_client.post(
            f"{BASE_URL}/auth/forgot-password",
            json={"email": "ghost@example.com", "strategy": "secure"},
        )
        assert response.status_code == 200
        assert "If the account exists" in response.json()["message"]


class TestMailbox:
    @pytest.mark.asyncio
    async def test_mailbox_load(self, async_client):
        """Mailbox should show reset links for the user's tokens."""
        email = "mailbox1@example.com"
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": email, "password": "Pass123!"})
        await async_client.post(f"{BASE_URL}/auth/forgot-password", json={"email": email, "strategy": "secure"})
        response = await async_client.get(f"{BASE_URL}/lab/mailbox/{email}")
        assert response.status_code == 200
        token = extract_token_from_mailbox(response)
        assert token is not None


class TestValidateToken:
    @pytest.mark.asyncio
    async def test_validate_valid_token(self, async_client):
        """GET /lab/validate should accept a valid token without consuming it."""
        email = "validate1@example.com"
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": email, "password": "Pass123!"})
        await async_client.post(f"{BASE_URL}/auth/forgot-password", json={"email": email, "strategy": "secure"})
        # Get token from mailbox
        mailbox = await async_client.get(f"{BASE_URL}/lab/mailbox/{email}")
        token = extract_token_from_mailbox(mailbox)
        assert token is not None

        response = await async_client.get(f"{BASE_URL}/auth/validate", params={"token": token})
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
    @pytest.mark.asyncio
    async def test_validate_unknown_token(self, async_client):
        """Non-existent token should return invalid."""
        response = await async_client.get(
            f"{BASE_URL}/auth/validate",
            params={"token": "nonexistent-token-here-12345"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
    @pytest.mark.asyncio
    async def test_validate_token_does_not_consume(self, async_client):
        """Validation (GET) must not mark the token as used."""
        email = "validate2@example.com"
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": email, "password": "Pass123!"})
        await async_client.post(f"{BASE_URL}/auth/forgot-password", json={"email": email, "strategy": "secure"})
        mailbox = await async_client.get(f"{BASE_URL}/lab/mailbox/{email}")
        token = extract_token_from_mailbox(mailbox)

        # Validate twice — both should succeed and not consume
        r1 = await async_client.get(f"{BASE_URL}/auth/validate", params={"token": token})
        assert r1.json()["valid"] is True
        r2 = await async_client.get(f"{BASE_URL}/auth/validate", params={"token": token})
        assert r2.json()["valid"] is True


class TestResetPassword:
    @pytest.mark.asyncio
    async def test_reset_password_valid(self, async_client):
        """POST /lab/reset-password with valid token should succeed."""
        email = "reset_valid@example.com"
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": email, "password": "Pass123!"})
        await async_client.post(f"{BASE_URL}/auth/forgot-password", json={"email": email, "strategy": "secure"})
        mailbox = await async_client.get(f"{BASE_URL}/lab/mailbox/{email}")
        token = extract_token_from_mailbox(mailbox)
        assert token is not None

        response = await async_client.post(
            f"{BASE_URL}/auth/reset-password",
            json={"token": token, "new_password": "NewPass789!"},
        )
        assert response.status_code == 200
        assert "message" in response.json()
    @pytest.mark.asyncio
    async def test_reset_password_unknown_token(self, async_client):
        """Unknown token should be rejected with 400."""
        response = await async_client.post(
            f"{BASE_URL}/auth/reset-password",
            json={"token": "totally-bogus-token", "new_password": "NewPass789!"},
        )
        assert response.status_code == 400
    @pytest.mark.asyncio
    async def test_reset_password_uses_token(self, async_client):
        """Token must be single-use: second reset with same token should fail."""
        email = "reset_twice@example.com"
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": email, "password": "Pass123!"})
        await async_client.post(f"{BASE_URL}/auth/forgot-password", json={"email": email, "strategy": "secure"})
        mailbox = await async_client.get(f"{BASE_URL}/lab/mailbox/{email}")
        token = extract_token_from_mailbox(mailbox)

        # First reset — should succeed
        r1 = await async_client.post(
            f"{BASE_URL}/auth/reset-password",
            json={"token": token, "new_password": "FirstReset789!"},
        )
        assert r1.status_code == 200

        # Second reset with same token — should fail
        r2 = await async_client.post(
            f"{BASE_URL}/auth/reset-password",
            json={"token": token, "new_password": "SecondReset000!"},
        )
        assert r2.status_code == 400
        assert "used" in r2.json()["detail"].lower() or "invalid" in r2.json()["detail"].lower()


class TestStrategySwitching:
    @pytest.mark.asyncio
    async def test_forgot_password_all_strategies(self, async_client):
        """All six strategies should be accepted in forgot-password."""
        for strategy in ["timestamp", "counter", "weak_prng", "structured", "predictable_hash", "secure"]:
            email = f"strat_{strategy}@example.com"
            await async_client.post(f"{BASE_URL}/auth/register", json={"email": email, "password": "Pass123!"})
            response = await async_client.post(
                f"{BASE_URL}/auth/forgot-password",
                json={"email": email, "strategy": strategy},
            )
            assert response.status_code == 200
    @pytest.mark.asyncio
    async def test_invalid_strategy_rejected(self, async_client):
        """Invalid strategy should return 400."""
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": "badstrat@example.com", "password": "Pass123!"})
        response = await async_client.post(
            f"{BASE_URL}/auth/forgot-password",
            json={"email": "badstrat@example.com", "strategy": "nonexistent_strategy"},
        )
        assert response.status_code == 400
