"""Detect which AI coding tools are present in a project."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

AITool = str  # literal union optional in 3.12+


@dataclass(frozen=True)
class DetectionResult:
    """Describes an AI coding tool detected in a project directory.

    Attributes:
        tool: Canonical short name (e.g. ``"claude-code"``, ``"cursor"``).
        config_dir: Relative path to the tool's configuration directory.
        settings_file: Relative path to the primary settings/instruction file.
        hooks_supported: Whether the tool supports executable hooks.
    """

    tool: AITool
    config_dir: str
    settings_file: str
    hooks_supported: bool


_DETECTORS: list[dict] = [
    {
        "tool": "claude-code",
        "markers": [".claude", "CLAUDE.md", ".claude/settings.json"],
        "config_dir": ".claude",
        "settings_file": ".claude/settings.json",
        "hooks_supported": True,
    },
    {
        "tool": "cursor",
        "markers": [".cursor", ".cursorrules", ".cursor/rules"],
        "config_dir": ".cursor",
        "settings_file": ".cursor/settings.json",
        "hooks_supported": False,
    },
    {
        "tool": "copilot",
        "markers": [".github/copilot-instructions.md", ".copilot"],
        "config_dir": ".github",
        "settings_file": ".github/copilot-instructions.md",
        "hooks_supported": False,
    },
    {
        "tool": "windsurf",
        "markers": [".windsurfrules", ".windsurf"],
        "config_dir": ".windsurf",
        "settings_file": ".windsurfrules",
        "hooks_supported": False,
    },
    {
        "tool": "cline",
        "markers": [".clinerules", ".cline"],
        "config_dir": ".cline",
        "settings_file": ".clinerules",
        "hooks_supported": False,
    },
    {
        "tool": "aider",
        "markers": [".aider.conf.yml", ".aiderignore"],
        "config_dir": ".",
        "settings_file": ".aider.conf.yml",
        "hooks_supported": False,
    },
]


def detect_ai_tools(project_dir: str | os.PathLike[str]) -> list[DetectionResult]:
    """Detect AI coding tools present in *project_dir* by filesystem markers.

    Returns results sorted with hook-supporting tools first.
    """
    root = Path(project_dir).resolve()
    results: list[DetectionResult] = []
    for d in _DETECTORS:
        found = any((root / marker).exists() for marker in d["markers"])
        if found:
            results.append(
                DetectionResult(
                    tool=d["tool"],
                    config_dir=d["config_dir"],
                    settings_file=d["settings_file"],
                    hooks_supported=d["hooks_supported"],
                )
            )
    hooks_first = [r for r in results if r.hooks_supported]
    rest = [r for r in results if not r.hooks_supported]
    return hooks_first + rest


def tool_display_name(tool: AITool) -> str:
    """Return a human-friendly display name for a tool identifier."""
    return {
        "claude-code": "Claude Code",
        "cursor": "Cursor",
        "copilot": "GitHub Copilot",
        "windsurf": "Windsurf",
        "cline": "Cline",
        "aider": "Aider",
    }.get(tool, tool)
