"""
Encrypted-DM server (v1 scope: 1:1 direct messages only — groups/voice come later).

Architecture:
  - Client generates an X25519 keypair on the device. Private key NEVER leaves
    the device. Public key is uploaded here so other users can look it up.
  - To send a message, the client does X25519(my_priv, their_pub) -> shared
    secret -> HKDF -> AES-256-GCM key, encrypts locally, and sends us only:
        { to: "username", ciphertext: "...", nonce: "..." }
  - We store and relay that blob. We cannot decrypt it. We don't have the keys.
  - This server IS trusted for: who-talked-to-whom-and-when (metadata),
    availability/relay, and identity (impersonation is possible if we're
    malicious/compromised, same as any centralized key-directory system
    without out-of-band key verification — this is a known limitation of
    v1; TOFU-style key pinning on the client is a good v2 addition).
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Header, UploadFile, File
from pydantic import BaseModel, Field
from typing import Optional
import asyncio
import secrets
import time
import os
import uuid
from fastapi.staticfiles import StaticFiles

import models
import crypto_utils
from websocket_manager import manager

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(
    title="Encrypted DM Server",
    docs_url=None,      # Disable Swagger UI
    redoc_url=None,     # Disable ReDoc
    openapi_url=None    # Disable OpenAPI JSON
)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

models.init_db()


# ---------- Request/response schemas ----------

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=8, max_length=256)
    public_key: str  # base64-encoded X25519 public key
    server_password: str # Required to prevent random people from registering


class LoginRequest(BaseModel):
    username: str
    password: str
    server_password: str # Required for login too for extra safety


class AuthResponse(BaseModel):
    token: str
    user_id: int
    username: str
    public_key: str


class PublicKeyResponse(BaseModel):
    username: str
    public_key: str


class UpdatePublicKeyRequest(BaseModel):
    public_key: str


class UserSummary(BaseModel):
    id: int
    username: str


class SendMessageRequest(BaseModel):
    to: str
    ciphertext: str
    nonce: str
    sender_ephemeral_pub: Optional[str] = None


class CreateServerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class ServerSummary(BaseModel):
    id: int
    name: str
    owner_id: int


class CreateChannelRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class ChannelSummary(BaseModel):
    id: int
    server_id: int
    name: str


class CreateInviteRequest(BaseModel):
    max_uses: Optional[int] = None


class InviteResponse(BaseModel):
    code: str
    server_id: int
    max_uses: Optional[int]


class RedeemInviteResponse(BaseModel):
    server: ServerSummary
    channels: list[ChannelSummary]
    key_grant_requested: bool  # true if we found an online member to ask for keys


class SendChannelMessageRequest(BaseModel):
    ciphertext: str
    nonce: str


class GrantKeyRequest(BaseModel):
    recipient_username: str
    channel_id: int
    encrypted_key: str
    nonce: str


# ---------- Auth dependency ----------

def verify_cloudflare_access(
    cf_access_client_id: Optional[str] = Header(None, alias="CF-Access-Client-Id"),
    cf_access_client_secret: Optional[str] = Header(None, alias="CF-Access-Client-Secret")
):
    """
    Optional: Strict Cloudflare Access verification.
    If you set CF_CLIENT_ID and CF_CLIENT_SECRET environment variables,
    the server will require these headers on every request.
    """
    required_id = os.getenv("CF_CLIENT_ID")
    required_secret = os.getenv("CF_CLIENT_SECRET")

    if required_id and required_secret:
        if cf_access_client_id != required_id or cf_access_client_secret != required_secret:
            raise HTTPException(403, "Invalid Cloudflare Access credentials")


def get_current_user(
    authorization: str = Header(...),
    _ = Depends(verify_cloudflare_access) # Ensure CF Access headers are valid if configured
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    payload = crypto_utils.decode_access_token(token)
    if payload is None:
        raise HTTPException(401, "Invalid or expired token")
    user = models.get_user_by_id(int(payload["sub"]))
    if user is None:
        raise HTTPException(401, "User no longer exists")
    return user


# ---------- Auth routes ----------

@app.post("/register", response_model=AuthResponse)
def register(req: RegisterRequest, _ = Depends(verify_cloudflare_access)):
    # SAFETY: Check global server password
    # You can change this password here:
    if req.server_password != "rick123":
        raise HTTPException(403, "Invalid server password")

    if models.get_user_by_username(req.username):
        raise HTTPException(400, "Username already taken")
    pw_hash = crypto_utils.hash_password(req.password)
    user_id = models.create_user(req.username, pw_hash, req.public_key)
    token = crypto_utils.create_access_token(user_id, req.username)
    return AuthResponse(token=token, user_id=user_id, username=req.username, public_key=req.public_key)


@app.post("/login", response_model=AuthResponse)
def login(req: LoginRequest, _ = Depends(verify_cloudflare_access)):
    # SAFETY: Check global server password
    if req.server_password != "rick123":
        raise HTTPException(403, "Invalid server password")

    user = models.get_user_by_username(req.username)
    if user is None or not crypto_utils.verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    token = crypto_utils.create_access_token(user["id"], user["username"])
    return AuthResponse(token=token, user_id=user["id"], username=user["username"], public_key=user["public_key"])


# ---------- User / key discovery ----------

@app.get("/users", response_model=list[UserSummary])
def list_users(current_user=Depends(get_current_user)):
    # SAFETY: Discovery is disabled to prevent user enumeration.
    # You must know the exact username to start a chat.
    return []


@app.get("/users/{username}/public_key", response_model=PublicKeyResponse)
def get_public_key(username: str, current_user=Depends(get_current_user)):
    user = models.get_user_by_username(username)
    if user is None:
        raise HTTPException(404, "User not found")
    return PublicKeyResponse(username=user["username"], public_key=user["public_key"])


@app.put("/users/me/public_key")
def update_public_key(req: UpdatePublicKeyRequest, current_user=Depends(get_current_user)):
    models.update_user_public_key(current_user["id"], req.public_key)
    return {"status": "ok"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    file_extension = os.path.splitext(file.filename)[1] if file.filename else ".enc"
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)
    
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
        
    return {"filename": unique_filename}


# ---------- Message history (for offline backlog / scrollback) ----------

@app.get("/messages/{username}")
def get_conversation(username: str, current_user=Depends(get_current_user)):
    other = models.get_user_by_username(username)
    if other is None:
        raise HTTPException(404, "User not found")
    msgs = models.get_conversation(current_user["id"], other["id"])
    return [
        {
            "id": m["id"],
            "from": current_user["username"] if m["sender_id"] == current_user["id"] else username,
            "to": username if m["sender_id"] == current_user["id"] else current_user["username"],
            "ciphertext": m["ciphertext"],
            "nonce": m["nonce"],
            "sender_ephemeral_pub": m["sender_ephemeral_pub"],
            "created_at": m["created_at"],
        }
        for m in msgs
    ]


# ---------- Stage 2: Servers & Channels ----------
#
# Each CHANNEL (not server) has its own randomly-generated AES-256 key,
# created locally on whichever device makes the channel. That key never
# touches this server in raw form. When someone new joins via invite, we
# can't give them the key ourselves — instead we ask an already-online
# member's app to encrypt the key to the new member's public key (the same
# X25519 ECDH scheme as DMs) and relay that blob to us. We just pass it
# along; we can't read it.

@app.post("/servers", response_model=ServerSummary)
def create_server(req: CreateServerRequest, current_user=Depends(get_current_user)):
    server_id = models.create_server(req.name, current_user["id"])
    # Every server starts with a default "general" channel. The CLIENT is
    # responsible for generating that channel's key locally right after
    # this call returns and storing it (see CryptoHelper.generateChannelKey
    # on the Android side) — the server only tracks that the channel exists.
    models.create_channel(server_id, "general")
    return ServerSummary(id=server_id, name=req.name, owner_id=current_user["id"])


@app.get("/servers", response_model=list[ServerSummary])
def list_my_servers(current_user=Depends(get_current_user)):
    servers = models.list_servers_for_user(current_user["id"])
    return [ServerSummary(id=s["id"], name=s["name"], owner_id=s["owner_id"]) for s in servers]


@app.get("/servers/{server_id}/channels", response_model=list[ChannelSummary])
def list_channels(server_id: int, current_user=Depends(get_current_user)):
    if not models.is_server_member(server_id, current_user["id"]):
        raise HTTPException(403, "Not a member of this server")
    channels = models.list_channels(server_id)
    return [ChannelSummary(id=c["id"], server_id=c["server_id"], name=c["name"]) for c in channels]


@app.post("/servers/{server_id}/channels", response_model=ChannelSummary)
def create_channel(server_id: int, req: CreateChannelRequest, current_user=Depends(get_current_user)):
    if not models.is_server_member(server_id, current_user["id"]):
        raise HTTPException(403, "Not a member of this server")
    channel_id = models.create_channel(server_id, req.name)
    # NOTE: like the default "general" channel, the CREATOR's client must
    # generate this channel's AES key locally right after this call. Other
    # existing members won't have it until the creator (or someone who has
    # it) grants it to them via POST /channels/{id}/key_grant — same
    # mechanism as new-member key distribution.
    return ChannelSummary(id=channel_id, server_id=server_id, name=req.name)


@app.get("/servers/{server_id}/members")
def list_server_members(server_id: int, current_user=Depends(get_current_user)):
    if not models.is_server_member(server_id, current_user["id"]):
        raise HTTPException(403, "Not a member of this server")
    return models.list_server_members(server_id)


@app.post("/servers/{server_id}/invites", response_model=InviteResponse)
def create_invite(server_id: int, req: CreateInviteRequest, current_user=Depends(get_current_user)):
    if not models.is_server_member(server_id, current_user["id"]):
        raise HTTPException(403, "Not a member of this server")
    code = secrets.token_urlsafe(6)  # short, URL-safe invite code
    models.create_invite(code, server_id, current_user["id"], req.max_uses)
    return InviteResponse(code=code, server_id=server_id, max_uses=req.max_uses)


@app.post("/invites/{code}/redeem", response_model=RedeemInviteResponse)
async def redeem_invite(code: str, current_user=Depends(get_current_user)):
    invite = models.get_invite(code)
    if invite is None or invite["revoked"]:
        raise HTTPException(404, "Invalid or revoked invite")
    if invite["max_uses"] is not None and invite["uses_count"] >= invite["max_uses"]:
        raise HTTPException(410, "Invite has reached its use limit")

    server = models.get_server(invite["server_id"])
    if server is None:
        raise HTTPException(404, "Server no longer exists")

    already_member = models.is_server_member(server["id"], current_user["id"])
    if not already_member:
        models.add_server_member(server["id"], current_user["id"])
        models.increment_invite_uses(code)

    channels = models.list_channels(server["id"])

    # Ask an online existing member to grant this new member the key(s) for
    # each channel they don't already have a grant for. We notify at most
    # one online member per channel (they'll each do one ECDH+encrypt on
    # their device and POST /channels/{id}/key_grant back to us).
    key_grant_requested = False
    if not already_member:
        for channel in channels:
            if models.has_pending_or_delivered_key_grant(channel["id"], current_user["id"]):
                continue
            granter_id = models.get_online_capable_member(
                server["id"], exclude_user_id=current_user["id"], online_user_ids=set(manager.active.keys())
            )
            if granter_id is not None:
                delivered = await manager.send_to_user(granter_id, {
                    "type": "key_request",
                    "channel_id": channel["id"],
                    "channel_name": channel["name"],
                    "new_member_username": current_user["username"],
                    "new_member_public_key": current_user["public_key"],
                })
                if delivered:
                    key_grant_requested = True

    return RedeemInviteResponse(
        server=ServerSummary(id=server["id"], name=server["name"], owner_id=server["owner_id"]),
        channels=[ChannelSummary(id=c["id"], server_id=c["server_id"], name=c["name"]) for c in channels],
        key_grant_requested=key_grant_requested,
    )


@app.get("/channels/{channel_id}/messages")
def get_channel_messages(channel_id: int, current_user=Depends(get_current_user)):
    channel = models.get_channel(channel_id)
    if channel is None:
        raise HTTPException(404, "Channel not found")
    if not models.is_server_member(channel["server_id"], current_user["id"]):
        raise HTTPException(403, "Not a member of this server")
    msgs = models.get_channel_messages(channel_id)
    return [
        {
            "id": m["id"],
            "channel_id": m["channel_id"],
            "from": models.get_user_by_id(m["sender_id"])["username"],
            "ciphertext": m["ciphertext"],
            "nonce": m["nonce"],
            "created_at": m["created_at"],
        }
        for m in msgs
    ]


@app.post("/channels/{channel_id}/key_grant")
async def grant_channel_key(channel_id: int, req: GrantKeyRequest, current_user=Depends(get_current_user)):
    """Called by an existing member's device after it encrypts the channel
    key to a new member's public key. We store + relay the encrypted blob —
    we never see the raw key."""
    channel = models.get_channel(channel_id)
    if channel is None:
        raise HTTPException(404, "Channel not found")
    if not models.is_server_member(channel["server_id"], current_user["id"]):
        raise HTTPException(403, "Not a member of this server")

    recipient = models.get_user_by_username(req.recipient_username)
    if recipient is None:
        raise HTTPException(404, "Recipient not found")

    grant_id = models.create_key_grant(
        channel_id=channel_id,
        recipient_id=recipient["id"],
        granter_id=current_user["id"],
        encrypted_key=req.encrypted_key,
        nonce=req.nonce,
    )

    delivered = await manager.send_to_user(recipient["id"], {
        "type": "key_grant_delivery",
        "channel_id": channel_id,
        "granter": current_user["username"],
        "encrypted_key": req.encrypted_key,
        "nonce": req.nonce,
    })
    if delivered:
        models.mark_key_grant_delivered(grant_id)

    return {"status": "ok", "delivered_live": delivered}


# ---------- WebSocket: live delivery ----------

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str,
    cf_access_client_id: Optional[str] = Header(None, alias="CF-Access-Client-Id"),
    cf_access_client_secret: Optional[str] = Header(None, alias="CF-Access-Client-Secret")
):
    # Verify Cloudflare Access headers if configured
    required_id = os.getenv("CF_CLIENT_ID")
    required_secret = os.getenv("CF_CLIENT_SECRET")
    if required_id and required_secret:
        if cf_access_client_id != required_id or cf_access_client_secret != required_secret:
            await websocket.close(code=4403) # Forbidden
            return

    payload = crypto_utils.decode_access_token(token)
    if payload is None:
        await websocket.close(code=4401)
        return

    user = models.get_user_by_id(int(payload["sub"]))
    if user is None:
        await websocket.close(code=4401)
        return

    user_id = user["id"]
    await manager.connect(user_id, websocket)

    # Flush any DMs that arrived while this user was offline.
    backlog = models.get_undelivered_for_user(user_id)
    for m in backlog:
        sender = models.get_user_by_id(m["sender_id"])
        await websocket.send_json({
            "type": "message",
            "from": sender["username"] if sender else "unknown",
            "ciphertext": m["ciphertext"],
            "nonce": m["nonce"],
            "sender_ephemeral_pub": m["sender_ephemeral_pub"],
            "created_at": m["created_at"],
        })
        models.mark_delivered(m["id"])

    # Flush any channel-key grants that arrived while this user was offline
    # (e.g. someone joined a server, requested keys, and the only online
    # member at the time granted it before this user reconnected).
    pending_grants = models.get_undelivered_key_grants(user_id)
    for g in pending_grants:
        granter = models.get_user_by_id(g["granter_id"])
        await websocket.send_json({
            "type": "key_grant_delivery",
            "channel_id": g["channel_id"],
            "granter": granter["username"] if granter else "unknown",
            "encrypted_key": g["encrypted_key"],
            "nonce": g["nonce"],
        })
        models.mark_key_grant_delivered(g["id"])

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            if msg_type == "channel_message":
                channel_id = data.get("channel_id")
                ciphertext = data.get("ciphertext")
                nonce = data.get("nonce")

                if not channel_id or not ciphertext or not nonce:
                    await websocket.send_json({"type": "error", "detail": "malformed channel message"})
                    continue

                channel = models.get_channel(channel_id)
                if channel is None or not models.is_server_member(channel["server_id"], user_id):
                    await websocket.send_json({"type": "error", "detail": "not a member of this channel's server"})
                    continue

                msg_id = models.save_channel_message(channel_id, user_id, ciphertext, nonce)

                # Broadcast to every OTHER online member of the server (v1
                # has no per-channel subscription tracking, so this relies
                # on every member being able to decrypt only the channels
                # they hold keys for — messages for channels they can't
                # decrypt are simply undecryptable noise to them).
                members = models.list_server_members(channel["server_id"])
                for member in members:
                    if member["id"] == user_id:
                        continue
                    await manager.send_to_user(member["id"], {
                        "type": "channel_message",
                        "channel_id": channel_id,
                        "from": user["username"],
                        "ciphertext": ciphertext,
                        "nonce": nonce,
                        "created_at": time.time(),
                    })

                await websocket.send_json({"type": "ack", "message_id": msg_id})
                continue

            if msg_type == "message":
                # Expect: { type: "message", to: "username", ciphertext, nonce, sender_ephemeral_pub }
                to_username = data.get("to")
                ciphertext = data.get("ciphertext")
                nonce = data.get("nonce")
                sender_ephemeral_pub = data.get("sender_ephemeral_pub")

                if not to_username or not ciphertext or not nonce:
                    await websocket.send_json({"type": "error", "detail": "malformed message"})
                    continue

                recipient = models.get_user_by_username(to_username)
                if recipient is None:
                    await websocket.send_json({"type": "error", "detail": "unknown recipient"})
                    continue

                msg_id = models.save_message(
                    sender_id=user_id,
                    recipient_id=recipient["id"],
                    ciphertext=ciphertext,
                    nonce=nonce,
                    sender_ephemeral_pub=sender_ephemeral_pub,
                )

                delivered_live = await manager.send_to_user(recipient["id"], {
                    "type": "message",
                    "from": user["username"],
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "sender_ephemeral_pub": sender_ephemeral_pub,
                    "created_at": time.time(),
                })
                if delivered_live:
                    models.mark_delivered(msg_id)

                # ack back to sender so the UI can show "sent"
                await websocket.send_json({"type": "ack", "message_id": msg_id})
                continue

            if msg_type == "call_signaling":
                to_username = data.get("to")
                payload = data.get("payload")

                if not to_username or not payload:
                    await websocket.send_json({"type": "error", "detail": "malformed call_signaling message"})
                    continue

                recipient = models.get_user_by_username(to_username)
                if recipient is None:
                    await websocket.send_json({"type": "error", "detail": "unknown call recipient"})
                    continue

                await manager.send_to_user(recipient["id"], {
                    "type": "call_signaling",
                    "from": user["username"],
                    "payload": payload
                })
                continue

            await websocket.send_json({"type": "error", "detail": f"unknown message type: {msg_type}"})

    except WebSocketDisconnect:
        manager.disconnect(user_id)


@app.get("/")
def get_root_blank():
    # SAFETY: Return a completely blank response to any browser visit.
    # No JSON, no text, no metadata.
    from fastapi.responses import Response
    return Response(content=None, status_code=200, media_type="text/plain")


@app.get("/health")
def health():
    # Minimal health check - no JSON
    from fastapi.responses import Response
    return Response(content="ok", status_code=200, media_type="text/plain")

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(path_name: str):
    # SAFETY: Return blank for any unknown URL.
    # This prevents an attacker from guessing API endpoints via 404/200 differences.
    from fastapi.responses import Response
    return Response(content=None, status_code=200, media_type="text/plain")
