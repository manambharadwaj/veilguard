"""User-managed secrets under the `secret/` key prefix."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from veilguard.backends.config import resolve_backend_type
from veilguard.backends.factory import create_backend

if TYPE_CHECKING:
    from veilguard.backends.types import WritableSecretBackend

SECRET_PREFIX = "secret"
_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")


class SecretStore:
    def __init__(
        self,
        *,
        backend_type: str | None = None,
        backend: WritableSecretBackend | None = None,
    ) -> None:
        if backend is not None:
            self._backend = backend
        else:
            self._backend = create_backend(resolve_backend_type(backend_type))

    def set_secret(self, name: str, value: str) -> None:
        _validate_secret_name(name)
        self._backend.store(f"{SECRET_PREFIX}/{name}", value)

    def get_secret(self, name: str) -> str | None:
        _validate_secret_name(name)
        key = f"{SECRET_PREFIX}/{name}"
        result = self._backend.resolve(key)
        return result.get(key)

    def list_secrets(self) -> list[str]:
        all_k = self._backend.resolve(SECRET_PREFIX)
        names: list[str] = []
        prefix = f"{SECRET_PREFIX}/"
        for full_key in all_k:
            if full_key.startswith(prefix):
                n = full_key[len(prefix) :]
                if n:
                    names.append(n)
        return sorted(names)

    def remove_secret(self, name: str) -> bool:
        _validate_secret_name(name)
        return self._backend.delete(f"{SECRET_PREFIX}/{name}")

    def load_secrets(self, only: list[str] | None = None) -> dict[str, str]:
        all_k = self._backend.resolve(SECRET_PREFIX)
        result: dict[str, str] = {}
        prefix = f"{SECRET_PREFIX}/"
        normalized = {x.upper() for x in only} if only else None
        for full_key, value in all_k.items():
            if not full_key.startswith(prefix):
                continue
            n = full_key[len(prefix) :]
            if not n:
                continue
            if normalized and n.upper() not in normalized:
                continue
            result[n] = value
        return result


def _validate_secret_name(name: str) -> None:
    if not _SAFE_NAME.match(name):
        raise ValueError(
            f'Invalid secret name: "{name}". Only alphanumeric, dash, and underscore allowed.',
        )
