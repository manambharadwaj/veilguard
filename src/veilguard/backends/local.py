"""Local AES-256-GCM encrypted JSON secret store (VeilGuard native format)."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from veilguard.backends.types import BackendHealth

STORE_FILE = "secrets.enc"
META_FILE = "secrets.meta.json"
SALT_FILE = ".salt"
LOCK_FILE = ".lock"
NONCE_LEN = 12

_DEFAULT_KEY_WARNING_SHOWN = False


def _load_or_create_salt(store_dir: Path) -> bytes:
    salt_path = store_dir / SALT_FILE
    try:
        existing = salt_path.read_bytes()
        if len(existing) == 16:
            return existing
    except OSError:
        pass
    store_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    salt = secrets.token_bytes(16)
    salt_path.write_bytes(salt)
    os.chmod(salt_path, 0o600)
    return salt


def _derive_key(key_material: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        key_material.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )


def _time_ms() -> int:
    return int(time.time() * 1000)


class LocalBackend:
    """AES-256-GCM encrypted local file backend for secret storage.

    Secrets are kept in a single encrypted JSON blob at
    ``~/.veilguard/store/secrets.enc``.  Key material is derived via scrypt
    from a user-supplied passphrase or a default derived from ``$HOME`` and
    ``$USER``.

    All writes use advisory file locking (``fcntl.flock``) and atomic
    tmpfile-rename to ensure crash safety and mutual exclusion.
    """

    name = "local"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        home = Path.home()
        raw_home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or str(home)
        default_dir = home / ".veilguard" / "store"
        self._store_dir = Path(cfg.get("storeDir", default_dir))
        user = os.environ.get("USER", os.environ.get("USERNAME", "default"))
        explicit_key = cfg.get("key")
        if not explicit_key:
            self._key_material = f"{raw_home}-veilguard-{user}"
            self._using_default_key = True
        else:
            self._key_material = explicit_key
            self._using_default_key = False
        salt = _load_or_create_salt(self._store_dir)
        self._encryption_key = _derive_key(self._key_material, salt)

    def _warn_default_key(self) -> None:
        global _DEFAULT_KEY_WARNING_SHOWN
        if self._using_default_key and not _DEFAULT_KEY_WARNING_SHOWN:
            store_path = self._store_dir / STORE_FILE
            if not store_path.is_file():
                print(
                    "Warning: Using default key material derived from HOME and USER. "
                    "For stronger security, set a custom key via "
                    'LocalBackend({"key": "your-secret"}) or the VEILGUARD_KEY env var.',
                    file=sys.stderr,
                )
                _DEFAULT_KEY_WARNING_SHOWN = True

    def destroy(self) -> None:
        self._encryption_key = b"\x00" * len(self._encryption_key)

    def _encrypt(self, plaintext: str) -> bytes:
        nonce = secrets.token_bytes(NONCE_LEN)
        aes = AESGCM(self._encryption_key)
        ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce + ct

    def _decrypt(self, data: bytes) -> str:
        nonce, ct = data[:NONCE_LEN], data[NONCE_LEN:]
        aes = AESGCM(self._encryption_key)
        return aes.decrypt(nonce, ct, None).decode("utf-8")

    def _lock(self) -> int:
        self._store_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        lock_path = self._store_dir / LOCK_FILE
        fd = os.open(lock_path, os.O_CREAT | os.O_WRONLY, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _unlock(self, fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def resolve(self, secret_path: str) -> dict[str, str]:
        store_path = self._store_dir / STORE_FILE
        if not store_path.is_file():
            return {}
        try:
            store: dict[str, str] = json.loads(self._decrypt(store_path.read_bytes()))
        except Exception as exc:
            print(f"Warning: could not decrypt store: {exc}", file=sys.stderr)
            return {}
        out: dict[str, str] = {}
        for key, value in store.items():
            if not secret_path or key == secret_path or key.startswith(secret_path + "/"):
                out[key] = value
        return out

    def health_check(self) -> BackendHealth:
        start = _time_ms()
        store_path = self._store_dir / STORE_FILE
        exists = store_path.is_file()
        return BackendHealth(
            healthy=exists,
            latency_ms=_time_ms() - start,
            message="Local store available" if exists else "No local store found (will be created on first write)",
        )

    def store(self, key: str, value: str) -> None:
        self._warn_default_key()
        fd = self._lock()
        try:
            self._store_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            store_path = self._store_dir / STORE_FILE
            store: dict[str, str] = {}
            if store_path.is_file():
                try:
                    store = json.loads(self._decrypt(store_path.read_bytes()))
                except Exception as exc:
                    print(f"Warning: could not decrypt existing store, starting fresh: {exc}", file=sys.stderr)
                    store = {}
            store[key] = value
            blob = self._encrypt(json.dumps(store))
            tmp = store_path.with_suffix(store_path.suffix + ".tmp")
            tmp.write_bytes(blob)
            os.chmod(tmp, 0o600)
            tmp.replace(store_path)

            meta_path = self._store_dir / META_FILE
            meta: dict[str, Any] = {"version": "1", "entries": {}}
            if meta_path.is_file():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
            meta.setdefault("entries", {})[key] = {
                "createdAt": datetime.now(tz=timezone.utc).isoformat(),
            }
            mtmp = meta_path.with_suffix(meta_path.suffix + ".tmp")
            mtmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            os.chmod(mtmp, 0o600)
            mtmp.replace(meta_path)
        finally:
            self._unlock(fd)

    def delete(self, key: str) -> bool:
        fd = self._lock()
        try:
            store_path = self._store_dir / STORE_FILE
            if not store_path.is_file():
                return False
            try:
                store = json.loads(self._decrypt(store_path.read_bytes()))
            except Exception as exc:
                print(f"Warning: could not decrypt store for deletion: {exc}", file=sys.stderr)
                return False
            if key not in store:
                return False
            del store[key]
            blob = self._encrypt(json.dumps(store))
            tmp = store_path.with_suffix(store_path.suffix + ".tmp")
            tmp.write_bytes(blob)
            os.chmod(tmp, 0o600)
            tmp.replace(store_path)
            meta_path = self._store_dir / META_FILE
            if meta_path.is_file():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    meta.get("entries", {}).pop(key, None)
                    mtmp = meta_path.with_suffix(meta_path.suffix + ".tmp")
                    mtmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
                    os.chmod(mtmp, 0o600)
                    mtmp.replace(meta_path)
                except Exception:
                    pass
            return True
        finally:
            self._unlock(fd)
