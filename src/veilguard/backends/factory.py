"""Construct secret backends."""

from __future__ import annotations

from typing import Any

from veilguard.backends.config import resolve_backend_type
from veilguard.backends.local import LocalBackend
from veilguard.backends.types import WritableSecretBackend


def create_backend(
    backend_type: str | None = None,
    config: dict[str, Any] | None = None,
) -> WritableSecretBackend:
    """Construct and return a secret backend of the given type.

    Raises ``ValueError`` if *backend_type* is not supported.
    """
    resolved = resolve_backend_type(backend_type)
    if resolved == "local":
        return LocalBackend(config)
    raise ValueError(
        f"Unsupported backend type: {resolved!r}. "
        "VeilGuard currently ships the 'local' backend only; "
        "keychain, vault, and cloud backends are on the roadmap.",
    )
