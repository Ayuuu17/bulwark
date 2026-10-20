"""Accounts: password hashing, login sessions, and the dependency that finds the logged-in user."""

import base64
import hashlib
import hmac
import re
import secrets
import time

from fastapi import HTTPException, Request, Response

from . import db

SESSION_COOKIE = "session"
SESSION_TTL = 30 * 86400
MIN_PASSWORD_LENGTH = 10
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    b64 = lambda raw: base64.b64encode(raw).decode()
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


_DUMMY_HASH = hash_password(secrets.token_hex(16))


def check_login(email: str, password: str) -> dict | None:
    user = db.get_user_by_email(email)
    if user is None:
        verify_password(password, _DUMMY_HASH)  # take the same time whether or not the email exists
        return None
    return user if verify_password(password, user["password_hash"]) else None


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_email(email: str) -> None:
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise HTTPException(400, "Enter a valid email address.")


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"Use at least {MIN_PASSWORD_LENGTH} characters for your password.")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _secure_cookie(request: Request) -> bool:
    # Browsers drop Secure cookies on plain http, except on localhost. Always Secure in production.
    return request.url.scheme == "https" or request.url.hostname not in ("localhost", "127.0.0.1")


def start_session(request: Request, response: Response, user_id: int) -> None:
    token = secrets.token_urlsafe(32)
    db.create_session(_token_hash(token), user_id, time.time() + SESSION_TTL)
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, path="/",
                        httponly=True, samesite="lax", secure=_secure_cookie(request))


def end_session(request: Request, response: Response) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db.delete_session(_token_hash(token))
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax", secure=_secure_cookie(request))


def optional_user(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    return db.session_user(_token_hash(token)) if token else None


def current_user(request: Request) -> dict:
    user = optional_user(request)
    if user is None:
        raise HTTPException(401, "Please log in.")
    return user
