"""Initialize VeilGuard: hooks, deny rules, and AI tool instructions."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from veilguard.detect import DetectionResult, detect_ai_tools
from veilguard.patterns import CONFIG_FILES, CREDENTIAL_PATTERNS

VEIL_MARKER = "<!-- veilguard:managed -->"

SERVICE_HINTS: dict[str, tuple[str, str]] = {
    "ANTHROPIC_API_KEY": ("Anthropic Messages API", "x-api-key: $ANTHROPIC_API_KEY"),
    "OPENAI_API_KEY": ("OpenAI API", "Authorization: Bearer $OPENAI_API_KEY"),
    "AWS_ACCESS_KEY_ID": ("AWS", "(use AWS SDK or aws configure)"),
    "GITHUB_TOKEN": ("GitHub API", "Authorization: Bearer $GITHUB_TOKEN"),
    "STRIPE_SECRET_KEY": ("Stripe API", "Authorization: Bearer $STRIPE_SECRET_KEY"),
    "SLACK_TOKEN": ("Slack API", "Authorization: Bearer $SLACK_TOKEN"),
    "GOOGLE_API_KEY": ("Google API", "key=$GOOGLE_API_KEY (query param)"),
    "DATABASE_URL": ("Database", "(connection string)"),
    "MONGODB_URI": ("MongoDB", "(connection string)"),
}

FILE_PATTERNS_HOOK = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".crt",
    "credentials",
    ".aws/credentials",
    ".ssh/",
    ".docker/config.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".tfstate",
    ".tfvars",
    "secrets/",
    ".veilguard/",
]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        import sys

        print(f"Warning: could not read {path}: {exc}", file=sys.stderr)
        return {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _build_instructions() -> str:
    available = [k for k in SERVICE_HINTS if os.environ.get(k)]
    key_table = ""
    if available:
        key_table = (
            "\n**Available API keys** (set as env vars — use `$VAR_NAME` in commands, "
            "never ask for values):\n\n"
            "| Env Var | Service | Auth Header |\n"
            "|---------|---------|-------------|\n"
        )
        for ev in available:
            svc, hdr = SERVICE_HINTS[ev]
            key_table += f"| `${ev}` | {svc} | `{hdr}` |\n"

    return f"""
{VEIL_MARKER}
## VeilGuard

This project uses VeilGuard to protect credentials from AI context.
{key_table}
**Blocked file patterns** (never read, write, or reference):
- `.env`, `.env.*` — environment variable files
- `*.key`, `*.pem`, `*.p12`, `*.pfx` — private key files
- `.aws/credentials`, `.ssh/*` — cloud/SSH credentials
- `*.tfstate`, `*.tfvars` — Terraform state with secrets
- `secrets/`, `credentials/` — secret directories

**If you need a credential:**
1. Reference it via `$VAR_NAME` in shell commands or `os.environ["VAR_NAME"]` in Python
2. Never hardcode credentials in source files
3. Never print or echo key values — only reference them as variables

**If you find a hardcoded credential:**
1. Replace it with an environment variable reference
2. Add the variable name to `.env.example`
3. Warn the user to rotate the exposed credential

Verify setup: `veilguard verify`

## Transcript protection
- NEVER ask users to paste API keys, tokens, or passwords into the conversation
- If a user pastes a credential, warn them and suggest environment variables
"""


def _hook_bash_blocks() -> str:
    lines: list[str] = []
    for p in FILE_PATTERNS_HOOK:
        esc = p.replace("'", "'\\''")
        if p.startswith(".") and "/" not in p:
            if "*" in p:
                pat = p.replace("*", ".*")
                lines.append(f'# Match {p}\nif echo "$BASENAME" | grep -qE \'{pat}$\'; then BLOCKED=1; REASON="{p}"; fi')
            else:
                lines.append(
                    f'# Match {p}\nif [ "$BASENAME" = "{p}" ] || echo "$BASENAME" | grep -qE \'^{p}\'; '
                    f'then BLOCKED=1; REASON="{p}"; fi'
                )
        else:
            lines.append(
                f'# Match {p}\nif echo "$LOWER_PATH" | grep -qi \'{esc}\'; then BLOCKED=1; REASON="{p}"; fi'
            )
    return "\n".join(lines)


def _generate_hook_script() -> str:
    blocks = _hook_bash_blocks()
    # Note: use f-string only for injecting {blocks}; JSON echoes use literal braces.
    return f"""#!/bin/bash
# VeilGuard — PreToolUse hook for Claude Code
# Blocks file access to secrets before they enter AI context.

set -euo pipefail

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | grep -o '"tool_name":"[^"]*"' | head -1 | cut -d'"' -f4)

FILE_PATH=$(echo "$INPUT" | grep -o '"file_path":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$FILE_PATH" ]; then
  FILE_PATH=$(echo "$INPUT" | grep -o '"path":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

if [ "$TOOL_NAME" = "Bash" ]; then
  COMMAND=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4)
  if echo "$COMMAND" | grep -qiE '(cat|head|tail|less|more|type|grep|awk|sed|strings|xxd)\\\\s+.*\\\\.(env|key|pem|p12|pfx)'; then
    echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked command that reads secret files"}}}}'
    exit 0
  fi
  if echo "$COMMAND" | grep -qiE '(python3?|node)\\\\s+-(c|e).*\\\\.(env|key|pem|p12|pfx)'; then
    echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked script that reads secret files"}}}}'
    exit 0
  fi
  if echo "$COMMAND" | grep -qiE '(python3?|node)\\\\s+-(c|e).*(os\\\\\\\\.environ|process\\\\\\\\.env).*(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY|VAULT|CREDENTIAL)'; then
    echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked env dump from script"}}}}'
    exit 0
  fi
  if echo "$COMMAND" | grep -qiE '(echo|printenv)\\\\s+.*\\\\$(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY|VAULT|CREDENTIAL)'; then
    echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked exposure of secret env vars"}}}}'
    exit 0
  fi
  if echo "$COMMAND" | grep -qiE 'veilguard\\\\s+secret\\\\s+get.*--force'; then
    echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked forced secret extraction"}}}}'
    exit 0
  fi
  if echo "$COMMAND" | grep -qiE 'veilguard\\\\s+run.*--\\\\s*(env|printenv)'; then
    echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked env dump via veilguard run"}}}}'
    exit 0
  fi
  if echo "$COMMAND" | grep -qiE '(cat|head|grep|ls)\\\\s+.*\\\\.veilguard'; then
    echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked access to VeilGuard data directory"}}}}'
    exit 0
  fi
  exit 0
fi

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

BASENAME=$(basename "$FILE_PATH")
LOWER_PATH=$(echo "$FILE_PATH" | tr '[:upper:]' '[:lower:]')

{blocks}

if [ "${{BLOCKED:-0}}" = "1" ]; then
  echo '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"VeilGuard: blocked access to secret file matching pattern '"'"'$REASON'"'"'"}}}}'
  exit 0
fi

exit 0
"""


_DENY_RULES = [
    "Read(.env*)",
    "Read(*.key)",
    "Read(*.pem)",
    "Read(*.p12)",
    "Read(*.pfx)",
    "Read(*.tfstate)",
    "Read(*.tfvars)",
    "Read(.aws/credentials)",
    "Read(.ssh/*)",
    "Read(~/.veilguard/*)",
    "Grep(*.env*)",
    "Grep(*.key)",
    "Grep(*.pem)",
    "Grep(credentials*)",
    "Bash(cat .env*)",
    "Bash(cat *.key)",
    "Bash(echo $*API_KEY*)",
    "Bash(*veilguard secret get*--force*)",
    "Bash(*veilguard run*-- env*)",
    "Bash(cat *\\.veilguard*)",
]


def _configure_claude_code(root: Path, created: list[str], modified: list[str]) -> None:
    claude = root / ".claude"
    hooks = claude / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook_path = hooks / "veilguard-guard.sh"
    if not hook_path.exists():
        hook_path.write_text(_generate_hook_script(), encoding="utf-8")
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        created.append(str(hook_path.relative_to(root)))

    settings_path = claude / "settings.json"
    settings = _read_json(settings_path)
    settings.setdefault("hooks", {})
    settings["hooks"].setdefault("PreToolUse", [])
    hook_exists = any(
        any(
            "veilguard-guard" in str(hh.get("command", ""))
            for hh in h.get("hooks", [])
        )
        for h in settings["hooks"]["PreToolUse"]
    )
    if not hook_exists:
        settings["hooks"]["PreToolUse"].append(
            {
                "matcher": "Read|Grep|Glob|Bash|Write|Edit",
                "hooks": [
                    {
                        "type": "command",
                        "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/veilguard-guard.sh',
                    }
                ],
            }
        )
        modified.append(str(settings_path.relative_to(root)))

    settings["hooks"].setdefault("Stop", [])
    has_stop = any(
        any("veilguard" in str(hh.get("command", "")) for hh in h.get("hooks", []))
        for h in settings["hooks"]["Stop"]
    )
    if not has_stop:
        settings["hooks"]["Stop"].append(
            {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 -m veilguard clean --last 2>/dev/null || true",
                    }
                ],
            }
        )
        if str(settings_path.relative_to(root)) not in modified:
            modified.append(str(settings_path.relative_to(root)))

    settings.setdefault("permissions", {})
    settings["permissions"].setdefault("deny", [])
    for rule in _DENY_RULES:
        if rule not in settings["permissions"]["deny"]:
            settings["permissions"]["deny"].append(rule)
    _write_json(settings_path, settings)

    claude_md = root / "CLAUDE.md"
    _append_instructions(claude_md, created, modified, root)


def _append_instructions(path: Path, created: list[str], modified: list[str], root: Path) -> None:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if VEIL_MARKER in existing:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    new_content = existing + _build_instructions()
    path.write_text(new_content, encoding="utf-8")
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)
    (modified if existing else created).append(rel)


def _configure_cursor(root: Path, created: list[str], modified: list[str]) -> None:
    _append_instructions(root / ".cursorrules", created, modified, root)


def _configure_copilot(root: Path, created: list[str], modified: list[str]) -> None:
    gh = root / ".github"
    gh.mkdir(parents=True, exist_ok=True)
    _append_instructions(gh / "copilot-instructions.md", created, modified, root)


def _configure_windsurf(root: Path, created: list[str], modified: list[str]) -> None:
    _append_instructions(root / ".windsurfrules", created, modified, root)


def _configure_cline(root: Path, created: list[str], modified: list[str]) -> None:
    _append_instructions(root / ".clinerules", created, modified, root)


def _configure_aider(root: Path, created: list[str], modified: list[str]) -> None:
    p = root / ".aiderignore"
    block = "\n# VeilGuard: keep secrets out of AI context\n.env\n.env.*\n*.key\n*.pem\n*.p12\n*.pfx\n*.tfstate\n*.tfvars\n.aws/\n.ssh/\nsecrets/\ncredentials/\n"
    existing = p.read_text(encoding="utf-8") if p.exists() else ""
    if "# VeilGuard" in existing:
        return
    p.write_text(existing + block, encoding="utf-8")
    rel = ".aiderignore"
    (modified if existing else created).append(rel)


def quick_scan(project_dir: Path) -> int:
    count = 0
    for rel in CONFIG_FILES:
        fp = project_dir / rel
        if not fp.is_file():
            continue
        try:
            if fp.stat().st_size > 10 * 1024 * 1024:
                continue
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if len(line) > 4096:
                continue
            for pattern in CREDENTIAL_PATTERNS:
                if pattern.regex.search(line):
                    count += 1
                    break
    return count


def init_project(project_dir: str) -> dict[str, Any]:
    root = Path(project_dir).resolve()
    created: list[str] = []
    modified: list[str] = []
    detected = list(detect_ai_tools(root))
    tools_detected = [d.tool for d in detected]
    if not detected:
        detected = [
            DetectionResult(
                tool="claude-code",
                config_dir=".claude",
                settings_file=".claude/settings.json",
                hooks_supported=True,
            )
        ]

    secrets_found = quick_scan(root)

    for d in detected:
        t = d.tool
        if t == "claude-code":
            _configure_claude_code(root, created, modified)
        elif t == "cursor":
            _configure_cursor(root, created, modified)
        elif t == "copilot":
            _configure_copilot(root, created, modified)
        elif t == "windsurf":
            _configure_windsurf(root, created, modified)
        elif t == "cline":
            _configure_cline(root, created, modified)
        elif t == "aider":
            _configure_aider(root, created, modified)

    return {
        "tools_detected": tools_detected,
        "tools_configured": [d.tool for d in detected],
        "files_created": created,
        "files_modified": modified,
        "secrets_found": secrets_found,
    }
