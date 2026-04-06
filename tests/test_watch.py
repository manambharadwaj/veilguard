"""Tests for the transcript watcher module."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from veilguard.watch import is_watch_running


def test_is_watch_running_no_pid_file():
    with mock.patch.object(Path, "is_file", return_value=False):
        assert is_watch_running() is False


def test_is_watch_running_dead_process():
    with tempfile.TemporaryDirectory() as td:
        pid_file = Path(td) / "watch.pid"
        pid_file.write_text(json.dumps({"pid": 999999999}))
        with mock.patch("veilguard.watch.PID_FILE", pid_file):
            assert is_watch_running() is False


def test_is_watch_running_alive_process():
    with tempfile.TemporaryDirectory() as td:
        pid_file = Path(td) / "watch.pid"
        pid_file.write_text(json.dumps({"pid": os.getpid()}))
        with mock.patch("veilguard.watch.PID_FILE", pid_file):
            assert is_watch_running() is True


def test_is_watch_running_invalid_json():
    with tempfile.TemporaryDirectory() as td:
        pid_file = Path(td) / "watch.pid"
        pid_file.write_text("not json")
        with mock.patch("veilguard.watch.PID_FILE", pid_file):
            assert is_watch_running() is False


def test_is_watch_running_missing_pid():
    with tempfile.TemporaryDirectory() as td:
        pid_file = Path(td) / "watch.pid"
        pid_file.write_text(json.dumps({}))
        with mock.patch("veilguard.watch.PID_FILE", pid_file):
            assert is_watch_running() is False
