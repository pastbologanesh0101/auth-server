"""Integration tests for the Flask app, using the test client + in-memory-ish
temp-file SQLite DB provided by create_app(testing=True)."""

import os
import time

import pytest

from app import create_app, jwt_lib


@pytest.fixture()
def app():
    flask_app = create_app(testing=True)
    yield flask_app
    db_path = flask_app.config["DB_PATH"]
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


def register(client, email="alice@example.com", password="correcthorsebattery"):
    return client.post("/register", json={"email": email, "password": password})


def login(client, email="alice@example.com", password="correcthorsebattery"):
    return client.post("/login", json={"email": email, "password": password})


def test_register_success(client):
    resp = register(client)
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["email"] == "alice@example.com"
    assert "id" in body


def test_register_duplicate_email_rejected(client):
    register(client)
    resp = register(client)
    assert resp.status_code == 409


def test_register_password_not_stored_plaintext(client, app):
    register(client)
    from app import models

    row = models.get_user_by_email(app.config["DB_PATH"], "alice@example.com")
    assert row["password_hash"] != "correcthorsebattery"
    assert row["password_hash"].startswith("pbkdf2:") or ":" in row["password_hash"]


def test_login_success_returns_tokens(client):
    register(client)
    resp = login(client)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "Bearer"


def test_login_wrong_password_fails(client):
    register(client)
    resp = login(client, password="wrong-password")
    assert resp.status_code == 401


def test_login_unknown_user_fails(client):
    resp = login(client, email="nobody@example.com")
    assert resp.status_code == 401


def test_me_requires_bearer_token(client):
    resp = client.get("/me")
    assert resp.status_code == 401


def test_me_rejects_invalid_token(client):
    resp = client.get("/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_me_rejects_expired_token(client, app):
    register(client)
    login(client)
    expired_token = jwt_lib.encode({"sub": 1}, app.config["JWT_SECRET"], expires_in=-5)
    resp = client.get("/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401
    assert "expired" in resp.get_json()["error"]


def test_me_succeeds_with_valid_token(client):
    register(client)
    login_resp = login(client)
    access_token = login_resp.get_json()["access_token"]

    resp = client.get("/me", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["email"] == "alice@example.com"


def test_refresh_issues_new_access_token(client):
    register(client)
    login_resp = login(client)
    refresh_token = login_resp.get_json()["refresh_token"]

    resp = client.post("/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "access_token" in body

    # The new access token itself must work against /me.
    me_resp = client.get("/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me_resp.status_code == 200


def test_refresh_rejects_unknown_token(client):
    resp = client.post("/refresh", json={"refresh_token": "totally-made-up-token"})
    assert resp.status_code == 401


def test_logout_revokes_refresh_token(client):
    register(client)
    login_resp = login(client)
    refresh_token = login_resp.get_json()["refresh_token"]

    logout_resp = client.post("/logout", json={"refresh_token": refresh_token})
    assert logout_resp.status_code == 200

    # Using the same refresh token again must now fail.
    resp = client.post("/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 401


def test_logout_unknown_token_returns_404(client):
    resp = client.post("/logout", json={"refresh_token": "does-not-exist"})
    assert resp.status_code == 404


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
