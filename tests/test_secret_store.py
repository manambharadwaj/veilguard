"""Tests for SecretStore orchestration through the backend."""

import tempfile

import pytest

from veilguard.backends.factory import create_backend
from veilguard.backends.local import LocalBackend
from veilguard.secret_store import SecretStore, _validate_secret_name


def _make_store(td: str) -> SecretStore:
    backend = LocalBackend({"storeDir": td, "key": "test-key"})
    return SecretStore(backend=backend)


def test_set_get_remove_cycle():
    with tempfile.TemporaryDirectory() as td:
        store = _make_store(td)
        store.set_secret("my_key", "my_value")
        assert store.get_secret("my_key") == "my_value"
        assert store.remove_secret("my_key") is True
        assert store.get_secret("my_key") is None


def test_list_secrets():
    with tempfile.TemporaryDirectory() as td:
        store = _make_store(td)
        store.set_secret("alpha", "1")
        store.set_secret("beta", "2")
        names = store.list_secrets()
        assert names == ["alpha", "beta"]


def test_load_secrets_all():
    with tempfile.TemporaryDirectory() as td:
        store = _make_store(td)
        store.set_secret("x", "1")
        store.set_secret("y", "2")
        loaded = store.load_secrets()
        assert loaded == {"x": "1", "y": "2"}


def test_load_secrets_filtered():
    with tempfile.TemporaryDirectory() as td:
        store = _make_store(td)
        store.set_secret("API_KEY", "val1")
        store.set_secret("OTHER", "val2")
        loaded = store.load_secrets(only=["api_key"])
        assert "API_KEY" in loaded
        assert "OTHER" not in loaded


def test_remove_nonexistent():
    with tempfile.TemporaryDirectory() as td:
        store = _make_store(td)
        assert store.remove_secret("nope") is False


def test_validate_secret_name_valid():
    _validate_secret_name("my-key_123")


def test_validate_secret_name_invalid():
    with pytest.raises(ValueError, match="Invalid secret name"):
        _validate_secret_name("bad name!")


def test_context_manager():
    with tempfile.TemporaryDirectory() as td:
        backend = LocalBackend({"storeDir": td, "key": "test-key"})
        with SecretStore(backend=backend) as store:
            store.set_secret("cm_test", "value")
            assert store.get_secret("cm_test") == "value"


def test_create_backend_local():
    with tempfile.TemporaryDirectory() as td:
        backend = create_backend("local", {"storeDir": td, "key": "test"})
        assert backend.name == "local"


def test_create_backend_invalid():
    with pytest.raises(ValueError, match="Unsupported backend"):
        create_backend("vault")
