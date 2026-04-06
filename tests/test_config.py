"""Tests for the backends/config module."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

from veilguard.backends.config import read_backend_config, resolve_backend_type, write_backend_config


def test_read_backend_config_missing():
    with tempfile.TemporaryDirectory() as td:
        with mock.patch("veilguard.backends.config.Path.home", return_value=Path(td)):
            result = read_backend_config()
            assert result == {}


def test_write_and_read_backend_config():
    with tempfile.TemporaryDirectory() as td:
        with mock.patch("veilguard.backends.config.Path.home", return_value=Path(td)):
            write_backend_config({"type": "local"})
            result = read_backend_config()
            assert result["type"] == "local"

            path = Path(td) / ".veilguard" / "backend.json"
            assert path.is_file()
            assert (path.stat().st_mode & 0o777) == 0o600


def test_read_backend_config_invalid_json(capsys):
    with tempfile.TemporaryDirectory() as td:
        vg = Path(td) / ".veilguard"
        vg.mkdir()
        (vg / "backend.json").write_text("not json")
        with mock.patch("veilguard.backends.config.Path.home", return_value=Path(td)):
            result = read_backend_config()
            assert result == {}
            assert "Warning" in capsys.readouterr().err


def test_resolve_backend_type_override():
    assert resolve_backend_type("local") == "local"


def test_resolve_backend_type_env():
    with mock.patch.dict("os.environ", {"VEILGUARD_BACKEND": "Local "}):
        assert resolve_backend_type() == "local"


def test_resolve_backend_type_default():
    with mock.patch.dict("os.environ", {}, clear=True):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("veilguard.backends.config.Path.home", return_value=Path(td)):
                assert resolve_backend_type() == "local"
