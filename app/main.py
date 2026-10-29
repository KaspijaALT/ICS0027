import os

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import crypto
from app.database import Base, SessionLocal, User, engine
from app.sessions import create_session, delete_session, get_session

Base.metadata.create_all(engine)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# __Host- prefix: browser only accepts the cookie over https
COOKIE_NAME = "__Host-session"


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def show(request, template, **values):
    return templates.TemplateResponse(request, template, values)


def redirect(url):
    return RedirectResponse(url, status_code=303)


def current_session(request):
    return get_session(request.cookies.get(COOKIE_NAME))


def log_in(request, user, password):
    # remove the old session and make a new token (session fixation)
    delete_session(request.cookies.get(COOKIE_NAME))
    key = crypto.derive_key(password, user.kdf_salt)
    token = create_session(user, key)

    response = redirect("/vault")
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=True, samesite="strict")
    return response


def check_registration(username, password, password2):
    if not (3 <= len(username) <= 32 and username.isascii() and username.isalnum()):
        return "Username must be 3-32 letters or digits."
    if len(password) < 12:
        return "Master password must be at least 12 characters."
    if password != password2:
        return "Passwords do not match."
    return None


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
):
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
def login(request: Request, username: str = Form(""), password: str = Form("")):
    username = username.strip().lower()
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))

    # same message for both cases so you can't tell which usernames exist
    if user is None or not crypto.check_password(user.password_hash, password):
        return show(request, "login.html", error="Wrong username or password.", username=username)
    return log_in(request, user, password)


@app.post("/logout")
def logout(request: Request):
    delete_session(request.cookies.get(COOKIE_NAME))
    response = redirect("/login")
    response.delete_cookie(COOKIE_NAME, httponly=True, secure=True, samesite="strict")
    return response


@app.get("/vault")
def vault(request: Request):
    session = current_session(request)
    if session is None:
        return redirect("/login")
    return show(request, "vault.html", session=session)
