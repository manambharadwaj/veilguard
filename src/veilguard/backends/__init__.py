"""Pluggable secret storage backends."""

from veilguard.backends.config import read_backend_config, resolve_backend_type, write_backend_config
from veilguard.backends.factory import create_backend
from veilguard.backends.local import LocalBackend
from veilguard.backends.types import BackendHealth, WritableSecretBackend

__all__ = [
    "BackendHealth",
    "LocalBackend",
    "WritableSecretBackend",
    "create_backend",
    "read_backend_config",
    "resolve_backend_type",
    "write_backend_config",
]
