"""JSONL transcript discovery, scan, and redaction."""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from veilguard.patterns import CREDENTIAL_PATTERNS, CredentialPattern


@dataclass
class TranscriptFinding:
    file: str
    line: int
    json_path: str
    pattern_id: str
    pattern_name: str
    preview: str


@dataclass
class CleanResult:
    files_scanned: int
    files_with_secrets: int
    total_findings: int
    total_redacted: int
    findings: list[TranscriptFinding]


SKIP_KEYS: frozenset[str] = frozenset(
    {
        "uuid",
        "sessionId",
        "parentUuid",
        "timestamp",
        "signature",
        "cacheKey",
        "hash",
        "requestId",
        "traceId",
        "spanId",
        "correlationId",
        "messageId",
        "conversationId",
        "cacheCreatedAt",
    }
)

MAX_LINE_SIZE = 50 * 1024


def discover_transcripts(target_path: str | os.PathLike[str] | None = None) -> list[str]:
    files: list[tuple[str, float]] = []
    home = Path.home()

    if target_path is not None:
        tp = Path(target_path).expanduser().resolve()
        try:
            if tp.is_file() and (tp.suffix == ".jsonl" or tp.suffix == ".md"):
                return [str(tp)]
            if tp.is_dir():
                _walk_dir(tp, files)
                files.sort(key=lambda x: x[1], reverse=True)
                return [f[0] for f in files]
        except OSError:
            return []
        return []

    transcript_dir = home / ".claude" / "projects"
    if not transcript_dir.is_dir():
        return []
    _walk_dir(transcript_dir, files)
    files.sort(key=lambda x: x[1], reverse=True)
    return [f[0] for f in files]


def _walk_dir(dir_path: Path, out: list[tuple[str, float]]) -> None:
    try:
        entries = list(dir_path.iterdir())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name == "tool-results":
                    continue
                _walk_dir(entry, out)
            elif entry.is_file():
                if entry.name.endswith(".jsonl") or (
                    entry.name == "summary.md" and entry.parent.name == "session-memory"
                ):
                    try:
                        mtime = entry.stat().st_mtime
                        out.append((str(entry.resolve()), mtime))
                    except OSError:
                        pass
        except OSError:
            continue


def _scan_string(
    value: str,
    json_path: str,
    findings: list[TranscriptFinding],
    file_info: tuple[str, int],
) -> str:
    if len(value) > MAX_LINE_SIZE:
        return value
    result = value
    fpath, fline = file_info
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.regex.search(result):
            global_rx = re_compile_global(pattern)
            preview = global_rx.sub(f"[REDACTED:{pattern.id}]", result)[:80]
            findings.append(
                TranscriptFinding(
                    file=fpath,
                    line=fline,
                    json_path=json_path,
                    pattern_id=pattern.id,
                    pattern_name=pattern.name,
                    preview=preview,
                )
            )
            result = global_rx.sub(f"[REDACTED:{pattern.id}]", result)
    return result


def re_compile_global(pattern: CredentialPattern) -> re.Pattern[str]:
    return re.compile(pattern.regex.pattern, pattern.regex.flags)


def deep_scan(
    value: Any,
    json_path: str,
    findings: list[TranscriptFinding],
    file_info: tuple[str, int],
) -> Any:
    if value is None:
        return value
    if isinstance(value, str):
        return _scan_string(value, json_path, findings, file_info)
    if isinstance(value, list):
        return [
            deep_scan(item, f"{json_path}[{i}]", findings, file_info)
            for i, item in enumerate(value)
        ]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, val in value.items():
            if key in SKIP_KEYS:
                out[key] = val
            else:
                path = f"{json_path}.{key}" if json_path else key
                out[key] = deep_scan(val, path, findings, file_info)
        return out
    return value


def scan_transcript_file(
    file_path: str | os.PathLike[str],
    dry_run: bool,
) -> tuple[list[TranscriptFinding], list[str] | None]:
    findings: list[TranscriptFinding] = []
    redacted_lines: list[str] = []
    path = Path(file_path)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings, None

    home = str(Path.home())
    display_path = str(path).replace(home, "~")
    has_changes = False
    lines = content.split("\n")

    for i, line in enumerate(lines, start=1):
        if not line.strip():
            if not dry_run:
                redacted_lines.append(line)
            continue
        if len(line) > MAX_LINE_SIZE:
            if not dry_run:
                redacted_lines.append(line)
            continue

        if str(path).endswith(".md"):
            scanned = _scan_string(line, "content", findings, (display_path, i))
            if scanned != line:
                has_changes = True
            if not dry_run:
                redacted_lines.append(scanned)
            continue

        try:
            parsed: Any = json.loads(line)
        except json.JSONDecodeError:
            if not dry_run:
                redacted_lines.append(line)
            continue

        before_ct = len(findings)
        redacted = deep_scan(parsed, "", findings, (display_path, i))
        if len(findings) > before_ct:
            has_changes = True
            if not dry_run:
                redacted_lines.append(json.dumps(redacted, ensure_ascii=False))
        else:
            if not dry_run:
                redacted_lines.append(line)

    rl: list[str] | None = None
    if not dry_run and has_changes:
        rl = redacted_lines
    return findings, rl


def atomic_write(file_path: str | os.PathLike[str], lines: list[str]) -> None:
    path = Path(file_path)
    suffix = secrets.token_hex(8)
    tmp = path.parent / f"{path.name}.tmp.{os.getpid()}.{suffix}"
    try:
        tmp.write_text("\n".join(lines), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def clean_transcripts(
    *,
    dry_run: bool = False,
    target_path: str | os.PathLike[str] | None = None,
    last_session: bool = False,
) -> CleanResult:
    result = CleanResult(0, 0, 0, 0, [])
    files = discover_transcripts(target_path)

    if last_session:
        newest: dict[str, str] = {}
        for f in files:
            if not f.endswith(".jsonl"):
                continue
            parent = str(Path(f).parent)
            if parent not in newest:
                newest[parent] = f
        files = list(newest.values())

    for fp in files:
        result.files_scanned += 1
        fings, redacted = scan_transcript_file(fp, dry_run)
        if fings:
            result.files_with_secrets += 1
            result.total_findings += len(fings)
            result.findings.extend(fings)
            if not dry_run and redacted is not None:
                atomic_write(fp, redacted)
                result.total_redacted += len(fings)

    return result
