import pytest
import httpx
import os

BASE_URL = os.getenv("API_URL", "http://localhost:8000")

@pytest.mark.asyncio
async def test_no_auth_rejected():
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/api/admin/audit")
        assert response.status_code == 403 or response.status_code == 401

@pytest.mark.asyncio
async def test_health_check_public():
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/api/health")
        assert response.status_code == 200
