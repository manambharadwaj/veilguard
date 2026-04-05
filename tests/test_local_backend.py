import tempfile

from veilguard.backends.local import LocalBackend


def test_local_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        b = LocalBackend({"storeDir": td, "key": "test-key-material"})
        try:
            b.store("secret/x", "hello")
            assert b.resolve("secret/x") == {"secret/x": "hello"}
            assert b.delete("secret/x") is True
            assert b.resolve("secret/x") == {}
        finally:
            b.destroy()
