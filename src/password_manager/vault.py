"""Encrypted vault: on-disk format and CRUD operations over vault entries.

On-disk file is JSON holding only public data (KDF parameters, nonce,
ciphertext) - never anything that reveals vault contents. Everything under
"entries" only exists in memory once unlocked.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .crypto import KdfParams

FORMAT_VERSION = 1


@dataclass
class VaultEntry:
    username: str
    password: str
    notes: str = ""
    created: str = ""
    modified: str = ""

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
            "created": self.created,
            "modified": self.modified,
        }

    @staticmethod
    def from_dict(data: dict) -> "VaultEntry":
        return VaultEntry(
            username=data["username"],
            password=data["password"],
            notes=data.get("notes", ""),
            created=data.get("created", ""),
            modified=data.get("modified", ""),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VaultError(Exception):
    pass


@dataclass
class Vault:
    path: Path
    _key: bytes
    _kdf_params: KdfParams
    entries: dict[str, VaultEntry] = field(default_factory=dict)

    @staticmethod
    def exists(path: Path) -> bool:
        return Path(path).exists()

    @classmethod
    def create(cls, path: Path, master_password: str) -> "Vault":
        path = Path(path)
        if path.exists():
            raise VaultError(f"Vault already exists at {path}")
        params = KdfParams.generate()
        key = crypto.derive_key(master_password, params)
        vault = cls(path=path, _key=key, _kdf_params=params, entries={})
        vault.save()
        return vault

    @classmethod
    def unlock(cls, path: Path, master_password: str) -> "Vault":
        path = Path(path)
        if not path.exists():
            raise VaultError(f"No vault found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if data.get("version") != FORMAT_VERSION:
            raise VaultError(f"Unsupported vault format version: {data.get('version')}")

        params = KdfParams.from_dict(data["kdf"])
        key = crypto.derive_key(master_password, params)
        nonce = bytes.fromhex(data["nonce"])
        ciphertext = bytes.fromhex(data["ciphertext"])

        plaintext = crypto.decrypt(nonce, ciphertext, key)  # raises DecryptionError on wrong password
        payload = json.loads(plaintext.decode("utf-8"))
        entries = {
            service: VaultEntry.from_dict(entry_data)
            for service, entry_data in payload.get("entries", {}).items()
        }
        return cls(path=path, _key=key, _kdf_params=params, entries=entries)

    def save(self) -> None:
        payload = {
            "entries": {service: entry.to_dict() for service, entry in self.entries.items()},
        }
        plaintext = json.dumps(payload).encode("utf-8")
        nonce, ciphertext = crypto.encrypt(plaintext, self._key)

        on_disk = {
            "version": FORMAT_VERSION,
            "kdf": self._kdf_params.to_dict(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }

        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(on_disk, f)
        os.replace(tmp_path, self.path)  # atomic on both POSIX and Windows

    def change_master_password(self, new_master_password: str) -> None:
        self._kdf_params = KdfParams.generate()
        self._key = crypto.derive_key(new_master_password, self._kdf_params)
        self.save()

    def add_entry(self, service: str, username: str, password: str, notes: str = "") -> None:
        if service in self.entries:
            raise VaultError(f"An entry for '{service}' already exists")
        now = _now()
        self.entries[service] = VaultEntry(username=username, password=password, notes=notes, created=now, modified=now)
        self.save()

    def get_entry(self, service: str) -> VaultEntry | None:
        return self.entries.get(service)

    def update_entry(
        self,
        service: str,
        username: str | None = None,
        password: str | None = None,
        notes: str | None = None,
    ) -> None:
        entry = self.entries.get(service)
        if entry is None:
            raise VaultError(f"No entry for '{service}'")
        if username is not None:
            entry.username = username
        if password is not None:
            entry.password = password
        if notes is not None:
            entry.notes = notes
        entry.modified = _now()
        self.save()

    def delete_entry(self, service: str) -> None:
        if service in self.entries:
            del self.entries[service]
            self.save()

    def list_services(self) -> list[str]:
        return sorted(self.entries.keys())
