"""
Database layer. Plain sqlite3, no ORM, kept intentionally simple.

IMPORTANT SECURITY NOTE:
This server NEVER stores plaintext messages and NEVER stores private keys.
It only ever sees:
  - usernames
  - bcrypt password hashes
  - public keys (safe to expose by definition)
  - ciphertext + nonce blobs (unreadable without the recipient's private key)
If someone dumps this DB, they get zero message content.
"""

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "discord_clone.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_cursor():
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                sender_ephemeral_pub TEXT,
                created_at REAL NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender_id, recipient_id)")

        # ---------- Stage 2: servers/channels ----------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS server_members (
                server_id INTEGER NOT NULL REFERENCES servers(id),
                user_id INTEGER NOT NULL REFERENCES users(id),
                joined_at REAL NOT NULL,
                PRIMARY KEY (server_id, user_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL REFERENCES servers(id),
                name TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS invites (
                code TEXT PRIMARY KEY,
                server_id INTEGER NOT NULL REFERENCES servers(id),
                created_by INTEGER NOT NULL REFERENCES users(id),
                max_uses INTEGER,
                uses_count INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS channel_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL REFERENCES channels(id),
                sender_id INTEGER NOT NULL REFERENCES users(id),
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_channel_msg ON channel_messages(channel_id)")

        # A "key grant" is one existing member handing a NEW member the
        # channel's symmetric key, encrypted to the new member's public key
        # (same ECDH+AES-GCM scheme as DMs). The server relays this blob but
        # can never read the key inside it.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS key_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL REFERENCES channels(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                granter_id INTEGER NOT NULL REFERENCES users(id),
                encrypted_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_key_grant_recipient ON key_grants(recipient_id, delivered)")


# ---------- Users ----------

def create_user(username: str, password_hash: str, public_key: str):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, public_key, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, public_key, time.time()),
        )
        return cur.lastrowid


def update_user_public_key(user_id: int, public_key: str):
    with db_cursor() as cur:
        cur.execute("UPDATE users SET public_key = ? WHERE id = ?", (public_key, user_id))


def get_user_by_username(username: str):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def list_users(exclude_username: str = None):
    with db_cursor() as cur:
        if exclude_username:
            cur.execute("SELECT id, username, created_at FROM users WHERE username != ?", (exclude_username,))
        else:
            cur.execute("SELECT id, username, created_at FROM users")
        return [dict(r) for r in cur.fetchall()]


# ---------- Messages ----------

def save_message(sender_id: int, recipient_id: int, ciphertext: str, nonce: str, sender_ephemeral_pub: str = None):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO messages
               (sender_id, recipient_id, ciphertext, nonce, sender_ephemeral_pub, created_at, delivered)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (sender_id, recipient_id, ciphertext, nonce, sender_ephemeral_pub, time.time()),
        )
        return cur.lastrowid


def mark_delivered(message_id: int):
    with db_cursor() as cur:
        cur.execute("UPDATE messages SET delivered = 1 WHERE id = ?", (message_id,))


def get_conversation(user_a_id: int, user_b_id: int, limit: int = 200):
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM messages
               WHERE (sender_id = ? AND recipient_id = ?)
                  OR (sender_id = ? AND recipient_id = ?)
               ORDER BY created_at ASC LIMIT ?""",
            (user_a_id, user_b_id, user_b_id, user_a_id, limit),
        )
        return [dict(r) for r in cur.fetchall()]


def get_undelivered_for_user(user_id: int):
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM messages WHERE recipient_id = ? AND delivered = 0 ORDER BY created_at ASC",
            (user_id,),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------- Servers ----------

def create_server(name: str, owner_id: int):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO servers (name, owner_id, created_at) VALUES (?, ?, ?)",
            (name, owner_id, time.time()),
        )
        server_id = cur.lastrowid
        cur.execute(
            "INSERT INTO server_members (server_id, user_id, joined_at) VALUES (?, ?, ?)",
            (server_id, owner_id, time.time()),
        )
        return server_id


def get_server(server_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM servers WHERE id = ?", (server_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def list_servers_for_user(user_id: int):
    with db_cursor() as cur:
        cur.execute("""
            SELECT s.* FROM servers s
            JOIN server_members sm ON sm.server_id = s.id
            WHERE sm.user_id = ?
            ORDER BY s.created_at ASC
        """, (user_id,))
        return [dict(r) for r in cur.fetchall()]


def is_server_member(server_id: int, user_id: int) -> bool:
    with db_cursor() as cur:
        cur.execute(
            "SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?",
            (server_id, user_id),
        )
        return cur.fetchone() is not None


def add_server_member(server_id: int, user_id: int):
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR IGNORE INTO server_members (server_id, user_id, joined_at) VALUES (?, ?, ?)",
            (server_id, user_id, time.time()),
        )


def get_online_capable_member(server_id: int, exclude_user_id: int, online_user_ids: set):
    """Pick an existing member of this server who is currently connected,
    to act as the key-granter for a newly joined member. Prefers the owner
    if they're online, otherwise any online member."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT sm.user_id, s.owner_id FROM server_members sm
            JOIN servers s ON s.id = sm.server_id
            WHERE sm.server_id = ? AND sm.user_id != ?
        """, (server_id, exclude_user_id))
        rows = [dict(r) for r in cur.fetchall()]
    online_members = [r["user_id"] for r in rows if r["user_id"] in online_user_ids]
    if not online_members:
        return None
    owner_id = rows[0]["owner_id"] if rows else None
    return owner_id if owner_id in online_members else online_members[0]


def list_server_members(server_id: int):
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.id, u.username FROM users u
            JOIN server_members sm ON sm.user_id = u.id
            WHERE sm.server_id = ?
        """, (server_id,))
        return [dict(r) for r in cur.fetchall()]


# ---------- Channels ----------

def create_channel(server_id: int, name: str):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO channels (server_id, name, created_at) VALUES (?, ?, ?)",
            (server_id, name, time.time()),
        )
        return cur.lastrowid


def list_channels(server_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM channels WHERE server_id = ? ORDER BY created_at ASC", (server_id,))
        return [dict(r) for r in cur.fetchall()]


def get_channel(channel_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM channels WHERE id = ?", (channel_id,))
        row = cur.fetchone()
        return dict(row) if row else None


# ---------- Invites ----------

def create_invite(code: str, server_id: int, created_by: int, max_uses: int = None):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO invites (code, server_id, created_by, max_uses, uses_count, revoked, created_at)
               VALUES (?, ?, ?, ?, 0, 0, ?)""",
            (code, server_id, created_by, max_uses, time.time()),
        )


def get_invite(code: str):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM invites WHERE code = ?", (code,))
        row = cur.fetchone()
        return dict(row) if row else None


def increment_invite_uses(code: str):
    with db_cursor() as cur:
        cur.execute("UPDATE invites SET uses_count = uses_count + 1 WHERE code = ?", (code,))


# ---------- Channel messages ----------

def save_channel_message(channel_id: int, sender_id: int, ciphertext: str, nonce: str):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO channel_messages (channel_id, sender_id, ciphertext, nonce, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (channel_id, sender_id, ciphertext, nonce, time.time()),
        )
        return cur.lastrowid


def get_channel_messages(channel_id: int, limit: int = 200):
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM channel_messages WHERE channel_id = ? ORDER BY created_at ASC LIMIT ?",
            (channel_id, limit),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------- Key grants ----------

def create_key_grant(channel_id: int, recipient_id: int, granter_id: int, encrypted_key: str, nonce: str):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO key_grants
               (channel_id, recipient_id, granter_id, encrypted_key, nonce, delivered, created_at)
               VALUES (?, ?, ?, ?, ?, 0, ?)""",
            (channel_id, recipient_id, granter_id, encrypted_key, nonce, time.time()),
        )
        return cur.lastrowid


def mark_key_grant_delivered(grant_id: int):
    with db_cursor() as cur:
        cur.execute("UPDATE key_grants SET delivered = 1 WHERE id = ?", (grant_id,))


def get_undelivered_key_grants(recipient_id: int):
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM key_grants WHERE recipient_id = ? AND delivered = 0 ORDER BY created_at ASC",
            (recipient_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def has_pending_or_delivered_key_grant(channel_id: int, recipient_id: int) -> bool:
    """Used to avoid asking multiple online members to grant the same key
    redundantly."""
    with db_cursor() as cur:
        cur.execute(
            "SELECT 1 FROM key_grants WHERE channel_id = ? AND recipient_id = ?",
            (channel_id, recipient_id),
        )
        return cur.fetchone() is not None
