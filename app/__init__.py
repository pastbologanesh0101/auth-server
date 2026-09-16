"""Application factory for the Authentication Server."""

from __future__ import annotations

import os
import tempfile

from flask import Flask

from . import models


def create_app(testing: bool = False, db_path: str | None = None) -> Flask:
    """
    Build and configure the Flask application.

    :param testing: if True, use an isolated temp-file SQLite DB and enable
        Flask's TESTING mode (used by the test suite).
    :param db_path: explicit sqlite file path to use; overrides ``testing``'s
        default temp-file behaviour when provided.
    """
    app = Flask(__name__)

    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "dev-secret-change-me")

    if db_path is not None:
        resolved_db_path = db_path
    elif testing:
        fd, resolved_db_path = tempfile.mkstemp(prefix="auth_server_test_", suffix=".db")
        os.close(fd)
    else:
        resolved_db_path = os.environ.get("DB_PATH", "auth_server.db")

    app.config["DB_PATH"] = resolved_db_path
    app.config["TESTING"] = testing

    models.init_db(resolved_db_path)

    from .routes import bp as auth_bp

    app.register_blueprint(auth_bp)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
