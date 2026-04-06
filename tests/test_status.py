"""Tests for the status module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from veilguard.status import status


def test_status_unprotected():
    with tempfile.TemporaryDirectory() as td:
        s = status(td)
        assert s["is_protected"] is False
        assert s["configured_tools"] == []
        assert s["hook_installed"] is False
        assert s["deny_rule_count"] == 0


def test_status_with_hook():
    with tempfile.TemporaryDirectory() as td:
        hook_path = Path(td) / ".claude" / "hooks" / "veilguard-guard.sh"
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("#!/bin/bash\nexit 0\n")
        s = status(td)
        assert s["hook_installed"] is True
        assert s["is_protected"] is True


def test_status_with_deny_rules():
    with tempfile.TemporaryDirectory() as td:
        settings = {
            "permissions": {"deny": ["Read(.env*)", "Read(*.key)"]},
            "hooks": {"Stop": []},
        }
        settings_path = Path(td) / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps(settings))
        s = status(td)
        assert s["deny_rule_count"] == 2


def test_status_with_stop_hook():
    with tempfile.TemporaryDirectory() as td:
        settings = {
            "permissions": {"deny": []},
            "hooks": {
                "Stop": [
                    {
                        "matcher": "",
                        "hooks": [{"type": "command", "command": "python3 -m veilguard clean"}],
                    }
                ]
            },
        }
        settings_path = Path(td) / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps(settings))
        s = status(td)
        assert s["transcript_protection"]["stop_hook_installed"] is True


def test_status_secrets_found():
    with tempfile.TemporaryDirectory() as td:
        config = Path(td) / "config.json"
        config.write_text('{"token": "ghp_' + "a" * 36 + '"}')
        s = status(td)
        assert s["secrets_found"] >= 1
