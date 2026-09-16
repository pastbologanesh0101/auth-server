"""HTTP routes for the authentication server."""

from __future__ import annotations

import secrets

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from . import jwt_lib
from . import models

bp = Blueprint("auth", __name__)

ACCESS_TOKEN_TTL_SECONDS = 15 * 60  # 15 minutes


def _db_path() -> str:
    return current_app.config["DB_PATH"]


def _secret() -> str:
    return current_app.config["JWT_SECRET"]


def _bearer_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[len("Bearer ") :].strip()


@bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    password_hash = generate_password_hash(password)
    user_id = models.create_user(_db_path(), email, password_hash)
    if user_id is None:
        return jsonify({"error": "email already registered"}), 409

    return jsonify({"id": user_id, "email": email}), 201


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = models.get_user_by_email(_db_path(), email)
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid email or password"}), 401

    access_token = jwt_lib.encode(
        {"sub": user["id"], "email": user["email"]},
        _secret(),
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
    )
    refresh_token = secrets.token_urlsafe(32)
    models.store_refresh_token(_db_path(), refresh_token, user["id"])

    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
    ), 200


@bp.post("/refresh")
def refresh():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token") or ""

    row = models.get_refresh_token(_db_path(), refresh_token)
    if row is None or row["revoked"]:
        return jsonify({"error": "invalid or revoked refresh token"}), 401

    user = models.get_user_by_id(_db_path(), row["user_id"])
    if user is None:
        return jsonify({"error": "invalid or revoked refresh token"}), 401

    access_token = jwt_lib.encode(
        {"sub": user["id"], "email": user["email"]},
        _secret(),
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
    )
    return jsonify(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
    ), 200


@bp.post("/logout")
def logout():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token") or ""

    revoked = models.revoke_refresh_token(_db_path(), refresh_token)
    if not revoked:
        return jsonify({"error": "refresh token not found"}), 404

    return jsonify({"message": "logged out"}), 200


@bp.get("/me")
def me():
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing bearer token"}), 401

    try:
        claims = jwt_lib.decode(token, _secret())
    except jwt_lib.ExpiredTokenError:
        return jsonify({"error": "token expired"}), 401
    except jwt_lib.JWTError:
        return jsonify({"error": "invalid token"}), 401

    user = models.get_user_by_id(_db_path(), claims["sub"])
    if user is None:
        return jsonify({"error": "user not found"}), 404

    return jsonify({"id": user["id"], "email": user["email"]}), 200
