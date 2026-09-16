# Authentication Server

A small, from-scratch JWT-based authentication server built with Flask and
SQLite. The JWT encoding/decoding (HMAC-SHA256 signing, base64url
`header.payload.signature`) is implemented by hand in [`app/jwt_lib.py`](app/jwt_lib.py)
— no PyJWT or similar library is used — to demonstrate understanding of how
JWTs actually work under the hood.

## Features

- **Register**: create an account with an email + password. Passwords are
  hashed with Werkzeug's `generate_password_hash` (PBKDF2) — never stored in
  plaintext.
- **Login**: verify credentials and issue a short-lived (15 minute) JWT
  access token plus a long-lived, server-side refresh token.
- **Refresh**: exchange a valid, non-revoked refresh token for a new access
  token without re-entering a password.
- **`/me`** (protected): returns the current user's profile, requires a
  valid `Authorization: Bearer <access_token>` header.
- **Logout**: revokes a refresh token server-side so it can no longer be
  used to mint new access tokens.

## Project layout

```
auth-server/
├── app/
│   ├── __init__.py     # create_app() application factory
│   ├── jwt_lib.py       # hand-rolled JWT encode/decode (HS256)
│   ├── models.py        # SQLite persistence (users, refresh_tokens)
│   └── routes.py        # Flask routes / blueprint
├── tests/
│   ├── test_jwt_lib.py  # unit tests for the JWT library
│   └── test_app.py      # Flask test-client integration tests
├── run.py               # dev server entrypoint
├── requirements.txt
└── .github/workflows/tests.yml
```

## Running locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python run.py
# Server runs at http://127.0.0.1:5000
```

## Running the tests

```bash
pip install -r requirements.txt
pytest -v
```

## Example curl flow

```bash
BASE=http://127.0.0.1:5000

# 1. Register
curl -s -X POST $BASE/register \
  -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com", "password": "correcthorsebattery"}'

# 2. Login -> get access_token + refresh_token
LOGIN=$(curl -s -X POST $BASE/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com", "password": "correcthorsebattery"}')
echo $LOGIN

ACCESS_TOKEN=$(echo $LOGIN | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
REFRESH_TOKEN=$(echo $LOGIN | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")

# 3. Call the protected /me route
curl -s $BASE/me -H "Authorization: Bearer $ACCESS_TOKEN"

# 4. Refresh -> get a new access_token
curl -s -X POST $BASE/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}"

# 5. Logout -> revoke the refresh token
curl -s -X POST $BASE/logout \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}"

# 6. Using the refresh token again now fails (401)
curl -s -X POST $BASE/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}"
```

## How the JWT is built

A token is three base64url segments joined with `.`:

```
base64url({"alg":"HS256","typ":"JWT"}) . base64url({"sub":1,"exp":...}) . base64url(HMAC-SHA256(secret, header + "." + payload))
```

`app/jwt_lib.py` implements `encode()` / `decode()` for this directly using
Python's `hmac`, `hashlib`, `base64`, and `json` stdlib modules, including
constant-time signature comparison (`hmac.compare_digest`) and expiry
checking.

## License

MIT — see [LICENSE](LICENSE).
