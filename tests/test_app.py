# run with: python -m pytest -v

import os
import time

os.environ["DATABASE_URL"] = "sqlite:///test.db"  # don't touch the real vault.db

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import Base, Entry, SessionLocal, User, engine
from app.main import COOKIE_NAME, CSRF_COOKIE_NAME, app
from app.sessions import sessions

PASSWORD = "correct horse battery staple"


@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    sessions.clear()
    # https, otherwise the Secure cookie isn't sent back
    return TestClient(app, base_url="https://testserver")


def register(client, username="alice"):
    client.get("/register")
    return client.post("/register", data={
        "username": username, "password": PASSWORD, "password2": PASSWORD,
        **csrf_data(client),
    }, follow_redirects=False)


def csrf_data(client):
    return {"csrf_token": client.cookies.get(CSRF_COOKIE_NAME, "")}


def add_entry(client, **fields):
    data = {"title": "GitHub", "username": "alice", "password": "S3cret!", "url": "", "notes": ""}
    data.update(fields)
    client.post("/vault/new", data={**data, **csrf_data(client)}, follow_redirects=False)
    with SessionLocal() as db:
        return db.scalars(select(Entry)).all()[-1].id


def test_cookie_flags(client):
    cookie = register(client).headers["set-cookie"]
    assert cookie.startswith(COOKIE_NAME)
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie
    assert client.cookies.get(CSRF_COOKIE_NAME)


def test_password_is_hashed_with_argon2id(client):
    register(client)
    with SessionLocal() as db:
        user = db.scalar(select(User))
    assert user.password_hash.startswith("$argon2id$")


def test_wrong_password(client):
    register(client)
    client.cookies.clear()
    client.get("/login")
    response = client.post(
        "/login",
        data={"username": "alice", "password": "wrong", **csrf_data(client)},
    )
    assert "Wrong username or password." in response.text


def test_sql_injection_in_login(client):
    register(client)
    client.cookies.clear()
    client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": "' OR '1'='1",
            "password": "' OR '1'='1",
            **csrf_data(client),
        },
    )
    assert "Wrong username or password." in response.text


def test_new_session_token_on_login(client):
    old_token = register(client).cookies[COOKIE_NAME]
    client.get("/login")
    response = client.post(
        "/login",
        data={"username": "alice", "password": PASSWORD, **csrf_data(client)},
        follow_redirects=False,
    )
    assert response.cookies[COOKIE_NAME] != old_token
    assert old_token not in sessions


def test_session_expires_when_idle(client):
    token = register(client).cookies[COOKIE_NAME]
    sessions[token]["last_seen"] = time.time() - 11 * 60
    assert client.get("/vault", follow_redirects=False).headers["location"] == "/login"


def test_entries_are_encrypted_in_database(client):
    register(client)
    add_entry(client, password="S3cret!")
    with SessionLocal() as db:
        entry = db.scalar(select(Entry))
    assert b"S3cret!" not in entry.ciphertext
    assert b"GitHub" not in entry.ciphertext


def test_add_view_edit_delete(client):
    register(client)
    entry_id = add_entry(client)
    assert "S3cret!" in client.get(f"/vault/{entry_id}").text

    client.post(
        f"/vault/{entry_id}/edit",
        data={"title": "GitLab", "password": "New1", **csrf_data(client)},
    )
    assert "GitLab" in client.get(f"/vault/{entry_id}").text

    client.post(f"/vault/{entry_id}/delete", data=csrf_data(client))
    assert client.get(f"/vault/{entry_id}").status_code == 404


def test_cannot_open_other_users_entry(client):
    register(client, "alice")
    entry_id = add_entry(client)
    client.cookies.clear()
    register(client, "mallory")
    assert client.get(f"/vault/{entry_id}").status_code == 404


def test_html_is_escaped(client):
    register(client)
    entry_id = add_entry(client, title="<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in client.get(f"/vault/{entry_id}").text


def test_javascript_url_rejected(client):
    register(client)
    response = client.post(
        "/vault/new",
        data={"title": "x", "url": "javascript:alert(1)", **csrf_data(client)},
    )
    assert "URL must start with" in response.text


def test_csrf_rejects_missing_tokens_for_state_changes(client):
    assert client.post(
        "/register",
        data={"username": "alice", "password": PASSWORD, "password2": PASSWORD},
    ).status_code == 403
    assert client.post("/login", data={"username": "alice", "password": PASSWORD}).status_code == 403

    register(client)
    entry_id = add_entry(client)
    assert client.post("/vault/new", data={"title": "forged"}).status_code == 403
    assert client.post(f"/vault/{entry_id}/edit", data={"title": "forged"}).status_code == 403
    assert client.post(f"/vault/{entry_id}/delete").status_code == 403
    assert client.post("/logout").status_code == 403

    with SessionLocal() as db:
        assert db.get(Entry, entry_id) is not None
        assert len(db.scalars(select(Entry)).all()) == 1


def test_csrf_token_is_in_forms_and_must_match_cookie(client):
    response = client.get("/register")
    csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token
    assert f'name="csrf_token" value="{csrf_token}"' in response.text

    response = client.post(
        "/register",
        data={
            "username": "alice",
            "password": PASSWORD,
            "password2": PASSWORD,
            "csrf_token": "forged-token",
        },
    )
    assert response.status_code == 403


def test_security_headers(client):
    headers = client.get("/login").headers
    assert "default-src 'self'" in headers["content-security-policy"]
    assert "strict-transport-security" in headers
