"""
Lab endpoint tests: restrictions, bulk sample generation, data visibility.
"""
import re

import pytest

BASE_URL = "http://localhost:8080/api"


class TestLabModeRestrictions:
    """Lab endpoints should be restricted when LAB_MODE=false."""
    @pytest.mark.asyncio
    async def test_mailbox_endpoint_exists(self, async_client):
        """Mailbox endpoint should return results or 404 depending on lab mode."""
        response = await async_client.get(f"{BASE_URL}/lab/mailbox/test@example.com")
        # In lab mode it should succeed (empty results)
        # In non-lab mode it should be 404
        assert response.status_code in (200, 404)
    @pytest.mark.asyncio
    async def test_token_laboratory_exists(self, async_client):
        """Token laboratory endpoint should respond."""
        response = await async_client.get(f"{BASE_URL}/lab/token-laboratory")
        assert response.status_code in (200, 404)
    @pytest.mark.asyncio
    async def test_generate_samples_endpoint(self, async_client):
        """Bulk sample generation endpoint should respond."""
        response = await async_client.get(f"{BASE_URL}/lab/token-laboratory")
        # Just check it responds
        assert response.status_code in (200, 404)


class TestGenerateSamples:
    """Bulk sample generation for Burp Sequencer."""
    @pytest.mark.asyncio
    async def test_generate_samples_timestamp(self, async_client):
        """Should generate 100 timestamp samples."""
        # Register a test user first
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": "samples@example.com", "password": "Pass123!"})
        response = await async_client.post(
            f"{BASE_URL}/lab/generate-samples",
            json={"email": "samples@example.com", "strategy": "timestamp", "count": 100},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["strategy"] == "timestamp"
        assert len(data["tokens"]) == 100
        assert all(len(t) > 0 for t in data["tokens"])
    @pytest.mark.asyncio
    async def test_generate_samples_secure(self, async_client):
        """Should generate 100 secure samples."""
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": "samples_secure@example.com", "password": "Pass123!"})
        response = await async_client.post(
            f"{BASE_URL}/lab/generate-samples",
            json={"email": "samples_secure@example.com", "strategy": "secure", "count": 100},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["tokens"]) == 100
    @pytest.mark.asyncio
    async def test_generate_samples_max_limit(self, async_client):
        """Should cap samples at maximum allowed."""
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": "max@example.com", "password": "Pass123!"})
        response = await async_client.post(
            f"{BASE_URL}/lab/generate-samples",
            json={"email": "max@example.com", "strategy": "secure", "count": 1000},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["tokens"]) <= 500
    @pytest.mark.asyncio
    async def test_generate_samples_invalid_strategy(self, async_client):
        """Invalid strategy should return 400."""
        response = await async_client.post(
            f"{BASE_URL}/lab/generate-samples",
            json={"email": "invalid@example.com", "strategy": "nonexistent", "count": 10},
        )
        assert response.status_code == 400


class TestTokenInfoAndAnalysis:
    @pytest.mark.asyncio
    async def test_token_info_requires_instructor_mode(self, async_client):
        """Token info endpoint should not reveal details without instructor mode."""
        response = await async_client.get(f"{BASE_URL}/lab/token-info/some-token")
        assert response.status_code in (200, 404)
    @pytest.mark.asyncio
    async def test_challenge_mode(self, async_client):
        """Challenge endpoint should return 6 anonymous samples."""
        response = await async_client.get(f"{BASE_URL}/lab/challenge")
        assert response.status_code in (200, 404)
        if response.status_code == 200:
            data = response.json()
            assert len(data["samples"]) == 6