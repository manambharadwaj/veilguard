"""Report whether VeilGuard protections appear active."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from veilguard.detect import detect_ai_tools
from veilguard.scan import scan
from veilguard.transcript import discover_transcripts, scan_transcript_file
from veilguard.watch import is_watch_running


def status(project_dir: str) -> dict[str, Any]:
    root = Path(project_dir).resolve()
    hook_path = root / ".claude" / "hooks" / "veilguard-guard.sh"
    hook_installed = hook_path.is_file()

    deny_rule_count = 0
    stop_hook_installed = False
    settings_path = root / ".claude" / "settings.json"
    if settings_path.is_file():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            deny_rule_count = len(settings.get("permissions", {}).get("deny", []))
            stop_hooks = settings.get("hooks", {}).get("Stop", [])
            stop_hook_installed = any(
                any(
                    "veilguard" in str(hh.get("command", ""))
                    for hh in h.get("hooks", [])
                )
                for h in stop_hooks
            )
        except Exception as exc:
            print(f"Warning: could not read Claude settings: {exc}", file=sys.stderr)

    configured_tools: list[str] = []
    marker = "veilguard:managed"
    for tool in detect_ai_tools(root):
        fp = root / tool.settings_file
        if fp.is_file():
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
                if marker in text or "VeilGuard" in text:
                    configured_tools.append(tool.tool)
            except OSError:
                pass

    claude_md = root / "CLAUDE.md"
    if claude_md.is_file() and "claude-code" not in configured_tools:
        try:
            if marker in claude_md.read_text(encoding="utf-8", errors="replace"):
                configured_tools.append("claude-code")
        except OSError:
            pass

    findings = scan(str(root), scan_global=False)
    secrets_found = len(findings)

    transcript_files = 0
    transcript_secrets = 0
    try:
        transcripts = discover_transcripts()
        jsonl = [f for f in transcripts if f.endswith(".jsonl")]
        transcript_files = len(jsonl)
        for fp in jsonl[:3]:
            fings, _ = scan_transcript_file(fp, True)
            transcript_secrets += len(fings)
    except Exception as exc:
        print(f"Warning: could not scan transcripts: {exc}", file=sys.stderr)

    is_protected = hook_installed or len(configured_tools) > 0

    return {
        "is_protected": is_protected,
        "configured_tools": configured_tools,
        "hook_installed": hook_installed,
        "deny_rule_count": deny_rule_count,
        "secrets_found": secrets_found,
        "transcript_protection": {
            "stop_hook_installed": stop_hook_installed,
            "watcher_running": is_watch_running(),
            "transcript_files": transcript_files,
            "transcript_secrets_found": transcript_secrets,
        },
    }
