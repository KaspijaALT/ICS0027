import json
import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

hasher = PasswordHasher()  # argon2id by default


def hash_password(password):
    return hasher.hash(password)


def check_password(password_hash, password):
    try:
        return hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


# master password + salt -> 32 byte key for AES-256
def derive_key(password, salt):
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MB
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )


def encrypt(key, data):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), None)
    return nonce, ciphertext


# fails if the ciphertext was changed (GCM tag check)
def decrypt(key, nonce, ciphertext):
    return json.loads(AESGCM(key).decrypt(nonce, ciphertext, None))
