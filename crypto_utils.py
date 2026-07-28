"""
Server-side auth utilities.

This file does NOT handle message encryption — that happens entirely on the
client (Android app). The server only ever needs:
  - password hashing (so we don't store plaintext passwords)
  - JWT creation/verification (so we know who's who over HTTP/WS)
"""

import os
import time
import bcrypt
from jose import jwt, JWTError

# In production, load this from an environment variable / secrets file,
# never hardcode. Generated fresh on first run and persisted to disk below.
_SECRET_FILE = os.path.join(os.path.dirname(__file__), ".jwt_secret")


def _load_or_create_secret() -> str:
    if os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE, "r") as f:
            return f.read().strip()
    secret = os.urandom(32).hex()
    with open(_SECRET_FILE, "w") as f:
        f.write(secret)
    return secret


JWT_SECRET = _load_or_create_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECONDS = 60 * 60 * 24 * 7  # 7 days


def hash_password(password: str) -> str:
    # bcrypt has a hard 72-byte input limit; truncate defensively (registration
    # already enforces max_length=256 chars at the API layer, but this keeps
    # hash_password safe to call from anywhere).
    password_bytes = password.encode("utf-8")[:72]
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    password_bytes = password.encode("utf-8")[:72]
    return bcrypt.checkpw(password_bytes, password_hash.encode("utf-8"))


def create_access_token(user_id: int, username: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": time.time() + JWT_EXPIRE_SECONDS,
        "iat": time.time(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None
