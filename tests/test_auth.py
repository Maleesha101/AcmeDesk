"""
Authentication tests: registration, login, profile, session management.
"""
import pytest
import httpx

BASE_URL = "http://localhost:8080/api"


class TestRegistration:
    @pytest.mark.asyncio
    async def test_register_new_user(self, async_client):
        """Registration should create a new user and return a session token."""
        payload = {"email": "newuser@example.com", "password": "SecurePass456!"}
        response = await async_client.post(f"{BASE_URL}/auth/register", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["user"]["email"] == "newuser@example.com"
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, async_client):
        """Duplicate email should return 409."""
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": "dup@example.com", "password": "Pass123!"})
        response = await async_client.post(f"{BASE_URL}/auth/register", json={"email": "dup@example.com", "password": "Pass123!"})
        assert response.status_code == 409


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_valid(self, async_client):
        """Valid login should return a session token."""
        await async_client.post(f"{BASE_URL}/auth/register", json={"email": "login@example.com", "password": "Pass123!"})
        response = await async_client.post(f"{BASE_URL}/auth/login", json={"email": "login@example.com", "password": "Pass123!"})
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == "login@example.com"
        assert "access_token" in data
    @pytest.mark.asyncio
    async def test_login_invalid(self, async_client):
        """Invalid credentials should return 401."""
        response = await async_client.post(f"{BASE_URL}/auth/login", json={"email": "nonexistent@example.com", "password": "wrongpassword"})
        assert response.status_code == 401


class TestPasswordChange:
    @pytest.mark.asyncio
    async def test_change_password_authenticated(self, async_client):
        """Change password while authenticated (with valid old password)."""
        response = await async_client.post(
            f"{BASE_URL}/auth/change-password",
            json={"old_password": "Pass123!", "new_password": "NewPass456!"},
        )
        assert response.status_code == 200
    @pytest.mark.asyncio
    async def test_change_password_wrong_old(self, async_client):
        """Change password with wrong old password should fail."""
        response = await async_client.post(
            f"{BASE_URL}/auth/change-password",
            json={"old_password": "wrong", "new_password": "NewPass456!"},
        )
        assert response.status_code == 400


class TestProfile:
    @pytest.mark.asyncio
    async def test_profile_authenticated(self, async_client):
        """Profile endpoint requires authentication."""
        response = await async_client.get(f"{BASE_URL}/me")
        assert response.status_code == 401