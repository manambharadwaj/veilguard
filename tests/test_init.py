"""Tests for project initialization."""

import tempfile
from pathlib import Path

from veilguard.initialize import VEIL_MARKER, init_project, quick_scan


def test_init_project_creates_claude_code_defaults():
    with tempfile.TemporaryDirectory() as td:
        result = init_project(td)
        assert "claude-code" in result["tools_configured"]
        assert result["secrets_found"] == 0

        hook_path = Path(td) / ".claude" / "hooks" / "veilguard-guard.sh"
        assert hook_path.is_file()

        claude_md = Path(td) / "CLAUDE.md"
        assert claude_md.is_file()
        assert VEIL_MARKER in claude_md.read_text()


def test_init_project_detects_cursor():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".cursorrules").touch()
        result = init_project(td)
        assert "cursor" in result["tools_detected"]
        rules = Path(td) / ".cursorrules"
        assert rules.is_file()
        assert VEIL_MARKER in rules.read_text()


def test_init_project_idempotent():
    with tempfile.TemporaryDirectory() as td:
        init_project(td)
        r2 = init_project(td)
        assert r2["files_created"] == []
        assert r2["files_modified"] == []

        claude_md = Path(td) / "CLAUDE.md"
        text = claude_md.read_text()
        assert text.count(VEIL_MARKER) == 1


def test_quick_scan_finds_credential():
    with tempfile.TemporaryDirectory() as td:
        config = Path(td) / "config.json"
        config.write_text('{"token": "ghp_' + "a" * 36 + '"}')
        count = quick_scan(Path(td))
        assert count >= 1


def test_quick_scan_empty_project():
    with tempfile.TemporaryDirectory() as td:
        count = quick_scan(Path(td))
        assert count == 0


def test_init_project_aider():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".aiderignore").touch()
        result = init_project(td)
        assert "aider" in result["tools_detected"]
        ignore = Path(td) / ".aiderignore"
        content = ignore.read_text()
        assert "# VeilGuard" in content
        assert ".env" in content
