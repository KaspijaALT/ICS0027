"""Database connection and tables."""

import os

from sqlalchemy import ForeignKey, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

# SQLite file by default. Set DATABASE_URL to use PostgreSQL instead.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///vault.db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str]  # Argon2id hash, used to check the login
    kdf_salt: Mapped[bytes]     # random salt, used to derive the encryption key


class Entry(Base):
    __tablename__ = "entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    nonce: Mapped[bytes]        # 12 random bytes, new every time we encrypt
    ciphertext: Mapped[bytes]   # the encrypted entry, with the 16-byte GCM tag at the end
