# Secure password manager

https://github.com/KaspijaALT/ICS0027

## Threat model

| Threat Category | Attack Vector (Weeks 1–4) | Technical Threat Scenario | Intended Mitigation Strategy |
|---|---|---|---|
| A01: Broken Access Control | Client-Side Control Bypass / IDOR | An authenticated user changes entry IDs in API requests (e.g., GET /api/vault/42) to view or edit another user's encrypted vault record. | Check ownership on every database query by enforcing WHERE entry_id = :id AND user_id = :current_user. |
| A02: Cryptographic Failures | Insecure Vault Storage / Weak KDF | Leaked or intercepted database backups get brute-forced offline to crack stored vault records. | Derive 256-bit keys using Argon2id with unique 16-byte user salts, and encrypt payloads server-side with AES-256-GCM. |
| A03: Injection | Input Tampering & SQL Injection | An attacker enters malicious SQL strings into login or search fields to bypass auth or dump database tables. | Use SQLAlchemy ORM with parameterized queries across all database calls to isolate user input from executable SQL. |
| A03: Injection | HTML & JavaScript Injection (XSS) | Malicious scripts saved in vault fields (labels, usernames, URLs) run in the browser when loaded and steal session data. | Validate inputs using Pydantic schemas, encode output HTML entities, and enforce a strict Content Security Policy (script-src 'self'). |
| A07: Authentication Failures | Session Fixation | An attacker sets a known session ID on a target before they log in, hijacking the session once authentication succeeds. | Destroy pre-login session cookies upon login and issue a fresh, cryptographically secure session ID. |
| A07: Authentication Failures | Brute-Force Master Password Attacks | Automated scripts run dictionary attacks against /api/auth/login to guess user master passwords. | Apply rate limiting by IP and user account on auth routes, and set high Argon2id memory and time costs to slow down attempts. |

## Cryptographic design

This project will rely on the Argon2id for encryption key generation and Master password management. During registration process, application generates a unique 16-byte salt (kdf_salt) bounded by cryptography and stored alongside user record. When Authentication takes place, Argon2id processes the user's master password with its salt to derive a symmetric 256-bit data encryption key. Argon2id is well known for protecting services against GPU / ASIC hardware brute forcing and side channel timing attacks.

Server-side credentials like usernames, site passwords, URLs, and notes are formatted in JSON payloads and encrypted in RAM using AES-256-GCM before saving it to the database. Given protocol provides solid encryption, guaranteeing confidentiality and integrity of data. Every single operation generates a distinct 12-byte initialization vector (IV) and produces a 128-bit authentication tag. Any unauthorized tampering with the stored ciphertext will cause authentication tag verification to fail during encryption, therefore blocking corrupted data retrieval.

Storage for database acts as a ciphertext store for credential data. Each record has primary user identifier (ID), Argon2id master password hash used for login validation, 16-byte kdf salt, AES-256-GCM master passwords, 12 byte IV, 16-byte authentication tag. Unencrypted master passwords, derived encryption keys and plaintext is wiped form memory after use and never to be recorded.

As a planned enhancement, client-side encryption will be introduced so that data sent from the client to the server is never transmitted in plaintext. The client will encrypt sensitive fields locally before the request leaves the browser, and the server will hold the corresponding decryption capability to verify and process the data server-side. This differs from a pure zero-knowledge model, where the server would never be able to decrypt stored data at all; here, the server retains decrypt access but the wire transmission itself is never plaintext, protecting credentials in transit even over a compromised network segment or logging layer, in addition to the existing TLS channel.

## Technology stack & TLS plan

Protocol TLS is used across HTTPS, including in the development and testing environments. Local developments runs on Uvicorn ASGI server, known for TLS bounded developments on localhost generated via mkcert. Having TLS 1.3 insures all HTTP session cookies marked with Secure flags are transported properly and protects against local eavesdropping and interception (MITM).

Project will have Cryptographic based libraries from Python – Argon2-cfii for all cryptographic operations. This library wraps standard C/OpenSSL implementations, delivering verified primitives for AES-256-GCM authenticated encryption and Argon2id key derivation. In result of using Argon2-cfii, it will prevent improper handling of nonces, tags, and memory operations.

Database layer PostgreSQL connected via SQL Alchemy Object Relational Mapper (ORM) concludes the database layer. SQLAlchemy insists that all database interactions to run as parameterized queries, keeping user inputs completely separate from SQL runnable statements. Using tools mentioned above, the risk for SQL injection decreases.

FastAPI is used for core web application framework. It provides rapid fast performance, strict type checking, and automatic request validation through Pydantic schemas. Automatic schema will enforce first line of defense by stripping unexpected payload fields and sanitizing inputs before they reach server-side logic. FastAPI simplifies security middleware integration for custom HTTP security headers and CORS policies

## Authentication & Session security

Session identifiers are given to authenticated clients using secure HTTP response cookies rather then storing them locally which is prone to script based extractions. Cookies insist using HttpOnly attribute, making them inaccessible to JavaScript running in the Dom and reducing token theft via XSS. The Secureflag attribute forces cookies to transport data if its under TLS 1.3 channel. Following these principles Cross site request forgery (CRSF) security flaw can be minimized.

To limit exposure, sessions use both an idle timeout and a maximum lifespan. If a user is inactive for 10 minutes, the session auto-expires and requires logging back in with the master password. There is also an absolute 8-hour limit that ends the session regardless of user activity. For extra safety, sensitive actions like viewing decrypted passwords or editing vault entries require entering the master password again, protecting against unauthorized access if a screen is left unattended.

The application protects against session fixation attacks by resetting session tokens when moving across authentication states. Any temporary or guest session token created before logging in is destroyed in memory as soon as the master password gets verified. The server then generates a fresh, cryptographically secure 256-bit session token, preventing an attacker from pre-setting a known session ID to hijack a user session.

An optional second layer of security uses Time-based One-Time Passwords (TOTP) following RFC 6238 via the pyotplibrary. When enabled, getting the master password right puts the user into a temporary pending state instead of giving full vault access right away. The user must provide a valid 6-digit TOTP code from their authenticator app within 30 seconds before the final session cookie is issued.
