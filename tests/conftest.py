import pytest
from fastapi.testclient import TestClient

from app.core.policy import get_policy
from app.main import app


@pytest.fixture(scope="session")
def policy():
    return get_policy()


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:  # runs lifespan (policy load)
        yield c


@pytest.fixture
def valid_payload():
    return {
        "prompt": "What is the capital of France?",
        "context_docs": [{"id": "doc-1", "text": "Paris is the capital of France."}],
        "metadata": {"app_id": "test-app", "user_id": "u-1", "request_id": "req-1"},
    }
