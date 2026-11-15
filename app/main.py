import json
import logging
import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import crypto
from app.database import Base, Entry, SessionLocal, User, engine
from app.sessions import create_session, delete_session, get_session

Base.metadata.create_all(engine)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# __Host- prefix: browser only accepts the cookie over https
COOKIE_NAME = "__Host-session"
CSRF_COOKIE_NAME = "__Host-csrf"
ENTRY_FIELD_LIMITS = {
    "title": 200,
    "username": 256,
    "password": 4096,
    "url": 2048,
    "notes": 10000,
}


class StructuredFormatter(logging.Formatter):
    def format(self, record):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
        }
        for field in ("method", "path", "status_code", "error_type", "user_id", "entry_id"):
            value = getattr(record, field, None)
            if value is not None:
                event[field] = value
        return json.dumps(event)


security_logger = logging.getLogger("app.security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False
if not security_logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    security_logger.addHandler(handler)


def log_security_event(event, request, **fields):
    security_logger.warning(
        event,
        extra={
            "event": event,
            "method": request.method,
            "path": request.url.path,
            **fields,
        },
    )


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def show(request, template, **values):
    csrf_token = request.cookies.get(CSRF_COOKIE_NAME) or secrets.token_urlsafe(32)
    values["csrf_token"] = csrf_token
    response = templates.TemplateResponse(request, template, values)
    if request.cookies.get(CSRF_COOKIE_NAME) != csrf_token:
        response.set_cookie(
            CSRF_COOKIE_NAME,
            csrf_token,
            httponly=True,
            secure=True,
            samesite="strict",
        )
    return response


def redirect(url):
    return RedirectResponse(url, status_code=303)


def current_session(request):
    return get_session(request.cookies.get(COOKIE_NAME))


def require_csrf(request, csrf_token):
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not cookie_token or not csrf_token or not secrets.compare_digest(cookie_token, csrf_token):
        log_security_event("csrf_rejected", request)
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token.")


def log_in(request, user, password):
    # remove the old session and make a new token (session fixation)
    delete_session(request.cookies.get(COOKIE_NAME))
    key = crypto.derive_key(password, user.kdf_salt)
    token = create_session(user, key)

    response = redirect("/vault")
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=True, samesite="strict")
    response.set_cookie(
        CSRF_COOKIE_NAME,
        secrets.token_urlsafe(32),
        httponly=True,
        secure=True,
        samesite="strict",
    )
    return response


def check_registration(username, password, password2):
    if not (3 <= len(username) <= 32 and username.isascii() and username.isalnum()):
        return "Username must be 3-32 letters or digits."
    if len(password) < 12:
        return "Master password must be at least 12 characters."
    if password != password2:
        return "Passwords do not match."
    return None


def check_entry(data):
    if not data["title"].strip():
        return "Title is required."
    for field, limit in ENTRY_FIELD_LIMITS.items():
        if len(data[field]) > limit:
            return f"{field.capitalize()} must be {limit} characters or fewer."
    if any("\x00" in value for value in data.values()):
        return "Fields must not contain null characters."
    if data["url"]:
        try:
            parsed_url = urlsplit(data["url"])
            port = parsed_url.port
            valid_url = (
                parsed_url.scheme.lower() in {"http", "https"}
                and bool(parsed_url.hostname)
                and parsed_url.username is None
                and parsed_url.password is None
                and (port is None or 1 <= port <= 65535)
                and not any(char.isspace() for char in data["url"])
                and not any(ord(char) < 32 or ord(char) == 127 for char in data["url"])
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            return "URL must be a valid http:// or https:// URL without embedded credentials."
    return None


def find_entry(db, entry_id, session):
    # only finds the entry if it belongs to the logged in user (IDOR)
    entry = db.scalar(
        select(Entry).where(Entry.id == entry_id, Entry.user_id == session["user_id"])
    )
    if entry is None:
        security_logger.warning(
            "entry_access_denied",
            extra={
                "event": "entry_access_denied",
                "user_id": session["user_id"],
                "entry_id": entry_id,
            },
        )
        raise HTTPException(status_code=404)
    return entry


@app.get("/")
def home():
    return redirect("/vault")


@app.get("/register")
def register_page(request: Request):
    return show(request, "register.html")


@app.post("/register")
def register(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    password2: str = Form(""),
    csrf_token: str = Form(""),
):
    require_csrf(request, csrf_token)
    username = username.strip().lower()
    error = check_registration(username, password, password2)
    if error:
        return show(request, "register.html", error=error, username=username)

    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            return show(request, "register.html", error="That username is taken.")

        user = User(
            username=username,
            password_hash=crypto.hash_password(password),
            kdf_salt=os.urandom(16),
        )
        db.add(user)
        db.commit()
        return log_in(request, user, password)


@app.get("/login")
def login_page(request: Request):
    return show(request, "login.html")


@app.post("/login")
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    require_csrf(request, csrf_token)
    username = username.strip().lower()
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))

    # same message for both cases so you can't tell which usernames exist
    if user is None or not crypto.check_password(user.password_hash, password):
        log_security_event("login_rejected", request)
        return show(request, "login.html", error="Wrong username or password.", username=username)
    return log_in(request, user, password)


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    require_csrf(request, csrf_token)
    delete_session(request.cookies.get(COOKIE_NAME))
    response = redirect("/login")
    response.delete_cookie(COOKIE_NAME, httponly=True, secure=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE_NAME, httponly=True, secure=True, samesite="strict")
    return response


@app.get("/vault")
def vault(request: Request):
    session = current_session(request)
    if session is None:
        return redirect("/login")

    with SessionLocal() as db:
        rows = db.scalars(select(Entry).where(Entry.user_id == session["user_id"])).all()

    entries = []
    for row in rows:
        data = crypto.decrypt(session["key"], row.nonce, row.ciphertext)
        entries.append({"id": row.id, "title": data["title"], "username": data["username"]})
    return show(request, "vault.html", session=session, entries=entries)


@app.get("/vault/new")
def new_entry_page(request: Request):
    session = current_session(request)
    if session is None:
        return redirect("/login")
    return show(request, "entry_form.html", session=session, entry={})


@app.post("/vault/new")
def new_entry(
    request: Request,
    title: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    url: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(""),
):
    require_csrf(request, csrf_token)
    session = current_session(request)
    if session is None:
        return redirect("/login")

    data = {"title": title.strip(), "username": username, "password": password,
            "url": url.strip(), "notes": notes}
    error = check_entry(data)
    if error:
        return show(request, "entry_form.html", session=session, entry=data, error=error)

    nonce, ciphertext = crypto.encrypt(session["key"], data)
    with SessionLocal() as db:
        db.add(Entry(user_id=session["user_id"], nonce=nonce, ciphertext=ciphertext))
        db.commit()
    return redirect("/vault")


@app.get("/vault/{entry_id}")
def view_entry(request: Request, entry_id: int):
    session = current_session(request)
    if session is None:
        return redirect("/login")

    with SessionLocal() as db:
        entry = find_entry(db, entry_id, session)
    data = crypto.decrypt(session["key"], entry.nonce, entry.ciphertext)
    return show(request, "entry.html", session=session, entry_id=entry_id, entry=data)


@app.get("/vault/{entry_id}/edit")
def edit_entry_page(request: Request, entry_id: int):
    session = current_session(request)
    if session is None:
        return redirect("/login")

    with SessionLocal() as db:
        entry = find_entry(db, entry_id, session)
    data = crypto.decrypt(session["key"], entry.nonce, entry.ciphertext)
    return show(request, "entry_form.html", session=session, entry_id=entry_id, entry=data)


@app.post("/vault/{entry_id}/edit")
def edit_entry(
    request: Request,
    entry_id: int,
    title: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    url: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(""),
):
    require_csrf(request, csrf_token)
    session = current_session(request)
    if session is None:
        return redirect("/login")

    data = {"title": title.strip(), "username": username, "password": password,
            "url": url.strip(), "notes": notes}
    error = check_entry(data)
    if error:
        return show(request, "entry_form.html", session=session, entry_id=entry_id,
                    entry=data, error=error)

    with SessionLocal() as db:
        entry = find_entry(db, entry_id, session)
        # encrypt again with a new nonce
        entry.nonce, entry.ciphertext = crypto.encrypt(session["key"], data)
        db.commit()
    return redirect(f"/vault/{entry_id}")


@app.post("/vault/{entry_id}/delete")
def delete_entry(request: Request, entry_id: int, csrf_token: str = Form("")):
    require_csrf(request, csrf_token)
    session = current_session(request)
    if session is None:
        return redirect("/login")

    with SessionLocal() as db:
        db.delete(find_entry(db, entry_id, session))
        db.commit()
    return redirect("/vault")


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception):
    security_logger.error(
        "request_failed",
        extra={
            "event": "request_failed",
            "method": request.method,
            "path": request.url.path,
            "status_code": 500,
            "error_type": type(exc).__name__,
        },
    )
    return HTMLResponse("An internal error occurred.", status_code=500)
