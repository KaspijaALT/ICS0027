# Secure password manager - Checkpoint 2 progress note

https://github.com/KaspijaALT/ICS0027

## 1. Current state

The application is now running as a FastAPI web application on Uvicorn and is served over HTTPS also in the development setup. Core flows are implemented: user can register, log in, log out, see the list of entries in the vault, add a new entry, view, edit and delete it. Instructions for running the project on a clean machine are in the README file.

## 2. Encryption and password hashing

During registration, master password is hashed with Argon2id using the argon2-cffi library and only the hash is stored in the database. Application also generates a unique 16-byte salt (kdf_salt) for every user which is stored alongside the user record. When the user logs in, the password is first checked against the Argon2id hash. If it is correct, Argon2id processes the master password once more together with kdf_salt to derive a 256-bit encryption key. Since the login hash and the encryption key use different salts, the stored hash does not reveal the key.

Vault entries (title, username, password, URL and notes) are formatted as a JSON payload and encrypted server-side with AES-256-GCM before saving to the database. Every encryption generates a new random 12-byte nonce (IV). The database stores the nonce and the ciphertext, where the 16-byte authentication tag is kept at the end of the ciphertext. If the stored ciphertext is changed, tag verification fails and the entry cannot be decrypted. Derived key is never written to the database, it only exists in the server-side session while the user is logged in.

## 3. Authentication and session management

After successful login, the server generates a random 256-bit session token and gives it to the browser in a cookie named __Host-session. The cookie uses HttpOnly attribute so it can not be read by JavaScript, Secure attribute so it is only sent over HTTPS, and SameSite=Strict so it is not sent with requests coming from other websites, which also protects against CSRF. The __Host- prefix makes the browser accept the cookie only over HTTPS for the whole site.

Session data, including the encryption key, is kept in server memory. Session expires after 10 minutes of inactivity and in any case after 8 hours. To prevent session fixation, every login destroys the old session token and generates a fresh one. Wrong username and wrong password return the same error message, so it is not possible to find out which usernames exist.

## 4. Threat model status

| Threat Category | Attack Vector | Status | Implementation |
|---|---|---|---|
| A01: Broken Access Control | IDOR | Done | Every entry query checks both entry id and user id of the logged in user, other user's entry returns 404. |
| A02: Cryptographic Failures | Weak KDF / insecure storage | Done | Argon2id with unique 16-byte salts, AES-256-GCM encryption of entries. |
| A03: Injection | SQL Injection | Done | All database calls use SQLAlchemy ORM with parameterized queries. |
| A03: Injection | XSS | Partly done | Jinja2 encodes all output, Content Security Policy only allows files from own server, javascript: URLs are rejected. Pydantic validation is not added yet. |
| A07: Authentication Failures | Session Fixation | Done | Old session destroyed and new token generated on login. |
| A07: Authentication Failures | Brute force | Partly done | High Argon2id memory and time cost (64 MB, 3 iterations). Rate limiting is not added yet. |

## 5. Changes from Checkpoint 1 design

SQLite is used as the default database instead of PostgreSQL, so the project can be run on a clean machine without installing a database server. PostgreSQL still works by setting the DATABASE_URL variable and a docker-compose file is included for it. Because SQLAlchemy is used, the code is the same for both databases.

In Checkpoint 1 it was stated that argon2-cffi will be used for all cryptographic operations. Argon2-cffi only provides Argon2, therefore AES-256-GCM encryption is done with the cryptography library, which uses OpenSSL.

Development certificate is created with a small Python script (scripts/make_cert.py) instead of mkcert, so no extra tool is needed. Uvicorn uses Python's default TLS settings, browsers connect with TLS 1.3, however TLS 1.2 is not yet disabled on the server.

Input validation is currently done with simple checks in the code instead of Pydantic schemas. The authentication tag is stored together with the ciphertext and not in a separate column, as the cryptography library returns them together. Sessions are stored in memory, which means restarting the server logs out all users. Wiping the key and plaintext from memory is not implemented, since Python does not give reliable control over memory.

## 6. Testing

Tests are written with pytest and can be run with python -m pytest -v. There are 12 tests which check cookie flags, Argon2id password hashing, wrong password, SQL injection in the login form, new session token on login, idle session timeout, that entries are encrypted in the database, adding, viewing, editing and deleting entries, that a user can not open another user's entry, HTML escaping, rejecting javascript: URLs and security headers.

## 7. Next steps

For the final version it is planned to add rate limiting on the login route by IP and user account, asking for the master password again before showing or editing a password, Pydantic schemas for input validation and TLS 1.3 as the minimum version. Optional TOTP two-factor authentication with pyotp, changing the master password and client-side encryption described in Checkpoint 1 are also planned.
