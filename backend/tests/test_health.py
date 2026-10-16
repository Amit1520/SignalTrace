from fastapi.testclient import TestClient

from backend.api.main import app


client = TestClient(app)


def test_health_endpoint_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_local_frontend_origin_receives_cors_header() -> None:
    response = client.get("/ai/runtime", headers={"Origin": "http://localhost:5173"})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "*" not in response.headers["access-control-allow-origin"]


def test_loopback_frontend_origin_receives_cors_header() -> None:
    response = client.get("/incidents", headers={"Origin": "http://127.0.0.1:5173"})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"


def test_allowed_origin_passes_preflight() -> None:
    response = client.options(
        "/incidents",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "GET" in response.headers["access-control-allow-methods"]


def test_unlisted_origin_does_not_receive_cors_header() -> None:
    response = client.get("/ai/runtime", headers={"Origin": "http://evil.example"})

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
