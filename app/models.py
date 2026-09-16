"""SQLite persistence layer for the auth server.

Uses the stdlib ``sqlite3`` module directly (no ORM) so the whole project
stays dependency-light. Two tables:

    users           (id, email, password_hash)
    refresh_tokens  (token, user_id, revoked)

Refresh tokens are stored server-side so that ``logout`` can revoke them
(a stateless JWT alone can't be revoked before its natural expiry).
"""

from __future__ import annotations

import sqlite3
from typing import Optional


def get_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str) -> None:
    conn = get_db(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def create_user(db_path: str, email: str, password_hash: str) -> Optional[int]:
    """Insert a new user. Returns the new user id, or None if email exists."""
    conn = get_db(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_email(db_path: str, email: str) -> Optional[sqlite3.Row]:
    conn = get_db(db_path)
    try:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()


def get_user_by_id(db_path: str, user_id: int) -> Optional[sqlite3.Row]:
    conn = get_db(db_path)
    try:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()


def store_refresh_token(db_path: str, token: str, user_id: int) -> None:
    conn = get_db(db_path)
    try:
        conn.execute(
            "INSERT INTO refresh_tokens (token, user_id, revoked) VALUES (?, ?, 0)",
            (token, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_refresh_token(db_path: str, token: str) -> Optional[sqlite3.Row]:
    conn = get_db(db_path)
    try:
        return conn.execute(
            "SELECT * FROM refresh_tokens WHERE token = ?", (token,)
        ).fetchone()
    finally:
        conn.close()


def revoke_refresh_token(db_path: str, token: str) -> bool:
    """Mark a refresh token revoked. Returns True if a row was updated."""
    conn = get_db(db_path)
    try:
        cur = conn.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (token,)
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()
