import secrets
import time

IDLE_TIMEOUT = 10 * 60      # 10 min
MAX_LIFETIME = 8 * 60 * 60  # 8 h

# token -> session info, only kept in memory
sessions = {}


def create_session(user, key):
    token = secrets.token_urlsafe(32)  # 256 bits
    now = time.time()
    sessions[token] = {
        "user_id": user.id,
        "username": user.username,
        "key": key,
        "created": now,
        "last_seen": now,
    }
    return token


def get_session(token):
    session = sessions.get(token)
    if session is None:
        return None

    now = time.time()
    if now - session["last_seen"] > IDLE_TIMEOUT or now - session["created"] > MAX_LIFETIME:
        del sessions[token]
        return None

    session["last_seen"] = now
    return session


def delete_session(token):
    sessions.pop(token, None)
