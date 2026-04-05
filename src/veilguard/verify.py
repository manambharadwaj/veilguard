"""Verify env-based secrets are not exposed in AI context files."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from veilguard.patterns import CREDENTIAL_PATTERNS
from veilguard.transcript import discover_transcripts, scan_transcript_file


@dataclass
class VerifyResult:
    env_vars: dict[str, bool] = field(default_factory=dict)
    exposed_in_context: list[dict] = field(default_factory=list)
    exposed_in_transcripts: list[dict] = field(default_factory=list)
    passed: bool = False


def _ai_context_files() -> list[tuple[Path, str]]:
    home = Path.home()
    return [
        (home / ".claude" / "CLAUDE.md", "~/.claude/CLAUDE.md"),
        (home / ".claude" / "settings.json", "~/.claude/settings.json"),
    ]


PROJECT_CONTEXT_FILES = [
    "CLAUDE.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
    ".claude/settings.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "mcp.json",
    ".env",
    ".env.local",
    "config.json",
]


def verify(project_dir: str | os.PathLike[str]) -> VerifyResult:
    env_vars: dict[str, bool] = {}
    exposed_in_context: list[dict] = []
    exposed_in_transcripts: list[dict] = []

    unique_env = {p.env_prefix for p in CREDENTIAL_PATTERNS}
    for ev in unique_env:
        v = os.environ.get(ev, "")
        env_vars[ev] = bool(v)

    root = Path(project_dir).resolve()
    files_to_check: list[tuple[Path, str]] = []
    for abs_path, label in _ai_context_files():
        files_to_check.append((abs_path, label))
    for rel in PROJECT_CONTEXT_FILES:
        files_to_check.append((root / rel, rel))

    for abs_path, label in files_to_check:
        if not abs_path.is_file():
            continue
        try:
            st = abs_path.stat()
            if not st.is_file() or st.st_size > 10 * 1024 * 1024:
                continue
            content = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(content.splitlines(), start=1):
            if len(line) > 4096:
                continue
            for pattern in CREDENTIAL_PATTERNS:
                if pattern.regex.search(line):
                    exposed_in_context.append(
                        {
                            "env_var": pattern.env_prefix,
                            "pattern_name": pattern.name,
                            "file": label,
                            "line": i,
                        }
                    )
                    break

    try:
        transcripts = discover_transcripts()
        recent = [f for f in transcripts if f.endswith(".jsonl")][:5]
        for fp in recent:
            findings, _ = scan_transcript_file(fp, True)
            for f in findings:
                exposed_in_transcripts.append(
                    {
                        "file": f.file,
                        "line": f.line,
                        "json_path": f.json_path,
                        "pattern_name": f.pattern_name,
                    }
                )
    except Exception:
        pass

    any_env = any(env_vars.values())
    passed = bool(
        any_env and len(exposed_in_context) == 0 and len(exposed_in_transcripts) == 0
    )
    return VerifyResult(
        env_vars=env_vars,
        exposed_in_context=exposed_in_context,
        exposed_in_transcripts=exposed_in_transcripts,
        passed=passed,
    )
