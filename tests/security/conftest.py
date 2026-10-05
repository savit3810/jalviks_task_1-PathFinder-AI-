import pytest


@pytest.fixture
def api_url():
    """Base URL for the API server."""
    import os
    return os.getenv("API_URL", "http://localhost:8000")
