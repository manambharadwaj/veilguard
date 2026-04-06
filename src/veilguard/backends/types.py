"""Backend protocol types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class BackendHealth:
    """Health-check result returned by a secret backend.

    Attributes:
        healthy: Whether the backend is operational.
        latency_ms: Milliseconds taken by the health probe.
        message: Human-readable status description.
    """

    healthy: bool
    latency_ms: int
    message: str


@runtime_checkable
class WritableSecretBackend(Protocol):
    """Protocol that all secret backends must implement.

    Methods follow a key-value model where keys use ``"secret/<name>"``
    path syntax.  ``resolve`` returns matching entries, ``store``/``delete``
    mutate the backend, and ``destroy`` wipes sensitive material from memory.
    """

    name: str

    def resolve(self, secret_path: str) -> dict[str, str]: ...

    def store(self, key: str, value: str) -> None: ...

    def delete(self, key: str) -> bool: ...

    def health_check(self) -> BackendHealth: ...

    def destroy(self) -> None: ...
