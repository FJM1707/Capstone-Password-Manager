"""Vault encryption primitives: Argon2id key derivation + AES-256-GCM AEAD.

Argon2id is used because it is the PHC-winning, OWASP-recommended choice for
password-based key derivation - resistant to both GPU and side-channel attacks,
unlike PBKDF2. AES-256-GCM is used because it is authenticated encryption: a
tampered or corrupted ciphertext fails to decrypt instead of silently
returning garbage, and it needs no separate MAC step to get right.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN_BYTES = 32  # AES-256
SALT_LEN_BYTES = 16
NONCE_LEN_BYTES = 12  # standard AES-GCM nonce size

# Argon2id cost parameters. These follow OWASP's current minimum
# recommendation for interactive logins (memory-hard, ~0.5-1s on typical
# hardware) rather than the library defaults, which are tuned lower for
# server-side request latency, not a single local unlock.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536  # 64 MiB
ARGON2_PARALLELISM = 4


@dataclass(frozen=True)
class KdfParams:
    salt: bytes
    time_cost: int = ARGON2_TIME_COST
    memory_cost_kib: int = ARGON2_MEMORY_COST_KIB
    parallelism: int = ARGON2_PARALLELISM

    @staticmethod
    def generate() -> "KdfParams":
        return KdfParams(salt=os.urandom(SALT_LEN_BYTES))

    def to_dict(self) -> dict:
        return {
            "salt": self.salt.hex(),
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
        }

    @staticmethod
    def from_dict(data: dict) -> "KdfParams":
        return KdfParams(
            salt=bytes.fromhex(data["salt"]),
            time_cost=data["time_cost"],
            memory_cost_kib=data["memory_cost_kib"],
            parallelism=data["parallelism"],
        )


class DecryptionError(Exception):
    """Raised when the master password is wrong or the vault is corrupted/tampered."""


def derive_key(master_password: str, params: KdfParams) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN_BYTES,
        type=Type.ID,
    )


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext). A fresh random nonce is generated per call -
    required because AES-GCM security collapses if a (key, nonce) pair repeats."""
    nonce = os.urandom(NONCE_LEN_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise DecryptionError("Incorrect master password or corrupted vault file") from exc
