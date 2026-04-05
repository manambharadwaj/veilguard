"""Backend protocol types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class BackendHealth:
    healthy: bool
    latency_ms: int
    message: str


@runtime_checkable
class WritableSecretBackend(Protocol):
    name: str

    def resolve(self, secret_path: str) -> dict[str, str]: ...

    def store(self, key: str, value: str) -> None: ...

    def delete(self, key: str) -> bool: ...

    def health_check(self) -> BackendHealth: ...

    def destroy(self) -> None: ...
