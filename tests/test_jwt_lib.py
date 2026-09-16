"""Unit tests for the hand-rolled JWT library (app/jwt_lib.py)."""

import time

import pytest

from app import jwt_lib

SECRET = "unit-test-secret"


def test_encode_decode_round_trip():
    token = jwt_lib.encode({"sub": 42, "email": "a@example.com"}, SECRET)
    claims = jwt_lib.decode(token, SECRET)
    assert claims["sub"] == 42
    assert claims["email"] == "a@example.com"
    assert "iat" in claims


def test_token_has_three_dot_separated_parts():
    token = jwt_lib.encode({"sub": 1}, SECRET)
    assert len(token.split(".")) == 3


def test_tampered_payload_is_rejected():
    token = jwt_lib.encode({"sub": 1, "role": "user"}, SECRET)
    header_b64, payload_b64, sig_b64 = token.split(".")

    # Flip a character in the payload segment to simulate tampering.
    tampered_char = "A" if payload_b64[0] != "A" else "B"
    tampered_payload = tampered_char + payload_b64[1:]
    tampered_token = f"{header_b64}.{tampered_payload}.{sig_b64}"

    with pytest.raises(jwt_lib.InvalidSignatureError):
        jwt_lib.decode(tampered_token, SECRET)


def test_tampered_signature_is_rejected():
    token = jwt_lib.encode({"sub": 1}, SECRET)
    header_b64, payload_b64, sig_b64 = token.split(".")
    bad_sig = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
    tampered_token = f"{header_b64}.{payload_b64}.{bad_sig}"

    with pytest.raises(jwt_lib.InvalidSignatureError):
        jwt_lib.decode(tampered_token, SECRET)


def test_wrong_secret_is_rejected():
    token = jwt_lib.encode({"sub": 1}, SECRET)
    with pytest.raises(jwt_lib.InvalidSignatureError):
        jwt_lib.decode(token, "a-different-secret")


def test_expired_token_is_rejected():
    token = jwt_lib.encode({"sub": 1}, SECRET, expires_in=-1)
    with pytest.raises(jwt_lib.ExpiredTokenError):
        jwt_lib.decode(token, SECRET)


def test_expired_token_accepted_when_verify_exp_false():
    token = jwt_lib.encode({"sub": 1}, SECRET, expires_in=-1)
    claims = jwt_lib.decode(token, SECRET, verify_exp=False)
    assert claims["sub"] == 1


def test_malformed_token_rejected():
    with pytest.raises(jwt_lib.MalformedTokenError):
        jwt_lib.decode("not-a-valid-jwt", SECRET)


def test_non_expiring_token_has_no_exp_claim():
    token = jwt_lib.encode({"sub": 1}, SECRET)
    claims = jwt_lib.decode(token, SECRET)
    assert "exp" not in claims


def test_expires_in_sets_exp_in_future():
    before = int(time.time())
    token = jwt_lib.encode({"sub": 1}, SECRET, expires_in=60)
    claims = jwt_lib.decode(token, SECRET)
    assert claims["exp"] >= before + 59
