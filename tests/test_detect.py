"""Tests for AI tool detection."""

import tempfile
from pathlib import Path

from veilguard.detect import detect_ai_tools, tool_display_name


def test_detect_claude_code():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".claude").mkdir()
        results = detect_ai_tools(td)
        assert len(results) == 1
        assert results[0].tool == "claude-code"
        assert results[0].hooks_supported is True


def test_detect_cursor():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".cursorrules").touch()
        results = detect_ai_tools(td)
        assert len(results) == 1
        assert results[0].tool == "cursor"
        assert results[0].hooks_supported is False


def test_detect_multiple_tools():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".claude").mkdir()
        (Path(td) / ".cursorrules").touch()
        results = detect_ai_tools(td)
        assert len(results) == 2
        assert results[0].tool == "claude-code"
        assert results[1].tool == "cursor"


def test_detect_no_tools():
    with tempfile.TemporaryDirectory() as td:
        results = detect_ai_tools(td)
        assert results == []


def test_hooks_supported_first():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".cursorrules").touch()
        (Path(td) / ".claude").mkdir()
        results = detect_ai_tools(td)
        assert results[0].hooks_supported is True


def test_tool_display_name():
    assert tool_display_name("claude-code") == "Claude Code"
    assert tool_display_name("cursor") == "Cursor"
    assert tool_display_name("copilot") == "GitHub Copilot"
    assert tool_display_name("unknown") == "unknown"


def test_detect_copilot():
    with tempfile.TemporaryDirectory() as td:
        gh = Path(td) / ".github"
        gh.mkdir()
        (gh / "copilot-instructions.md").touch()
        results = detect_ai_tools(td)
        assert len(results) == 1
        assert results[0].tool == "copilot"


def test_detect_aider():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / ".aiderignore").touch()
        results = detect_ai_tools(td)
        assert len(results) == 1
        assert results[0].tool == "aider"
