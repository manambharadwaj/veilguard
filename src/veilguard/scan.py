"""Scan project files for hardcoded credentials."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from veilguard.patterns import (
    CONFIG_FILES,
    CREDENTIAL_PATTERNS,
    CREDENTIAL_PREFIX_QUICK_CHECK,
    KNOWN_EXAMPLE_KEYS,
    PLACEHOLDER_INDICATORS,
    SOURCE_FILE_EXTENSIONS,
    SOURCE_SKIP_DIRS,
    CredentialPattern,
)


@dataclass
class ScanFinding:
    file: str
    line: int
    pattern_id: str
    pattern_name: str
    severity: str
    preview: str
    fix: str | None = None


FIX_GUIDANCE: dict[str, str] = {
    "anthropic": "Move to env var ANTHROPIC_API_KEY. Rotate at console.anthropic.com > API Keys.",
    "openai-proj": "Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.",
    "openai-legacy": "Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.",
    "aws-access": "Move to env var AWS_ACCESS_KEY_ID. Rotate in AWS IAM console.",
    "aws-sts": "STS tokens are temporary but should not be committed. Use AWS SDK credential chain.",
    "github-pat": "Move to env var GITHUB_TOKEN. Rotate at github.com > Settings > Developer Settings > PATs.",
    "github-fine": "Move to env var GITHUB_TOKEN. Rotate at github.com > Settings > Developer Settings > Fine-grained PATs.",
    "stripe": "Move to env var STRIPE_SECRET_KEY. Rotate at dashboard.stripe.com > Developers > API Keys.",
    "stripe-test": "Move to env var STRIPE_SECRET_KEY. Even test keys should not be committed.",
    "slack": "Move to env var SLACK_TOKEN. Rotate at api.slack.com > Your Apps.",
    "postgres": "Move to env var DATABASE_URL. Rotate the database password.",
    "mongodb": "Move to env var MONGODB_URI. Rotate the database password.",
    "pem-private-key": "Never commit private keys. Use `veilguard secret set` or a secrets manager.",
    "google": "Move to env var GOOGLE_API_KEY. Restrict and rotate at console.cloud.google.com.",
    "supabase": "Move to env var SUPABASE_SERVICE_ROLE_KEY. Rotate in Supabase dashboard > Settings > API.",
}

_ENV_REF = re.compile(r"\$\{[A-Z_]+\}")
_PROCESS_ENV = re.compile(r"process\.env\.[A-Z_]+")
_OS_ENVIRON = re.compile(r"os\.environ")

TEST_DIRS: frozenset[str] = frozenset(
    {"__tests__", "__mocks__", "test", "tests", "fixtures", "__fixtures__"}
)


def _is_test_file(name: str) -> bool:
    return bool(
        re.search(r"\.(test|spec|e2e)\.[^.]+$", name)
        or name.startswith("test_")
        or name.endswith("_test.go")
    )


def _walk_source_files(project_dir: Path, max_files: int, include_tests: bool) -> list[Path]:
    results: list[Path] = []
    queue: list[Path] = [project_dir]
    while queue and len(results) < max_files:
        current = queue.pop(0)
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in sorted(entries, key=lambda p: p.name):
            if len(results) >= max_files:
                break
            try:
                if entry.is_dir():
                    if entry.name in SOURCE_SKIP_DIRS or entry.name.startswith("."):
                        continue
                    if not include_tests and entry.name in TEST_DIRS:
                        continue
                    queue.append(entry)
                elif entry.is_file():
                    if entry.suffix not in SOURCE_FILE_EXTENSIONS:
                        continue
                    if not include_tests and _is_test_file(entry.name):
                        continue
                    results.append(entry)
            except OSError:
                continue
    return results


def _is_known_example(line: str, match: re.Match[str]) -> bool:
    value = match.group(0)
    if value in KNOWN_EXAMPLE_KEYS:
        return True
    lower = value.lower()
    if any(p in lower for p in PLACEHOLDER_INDICATORS):
        return True
    line_lc = line.lower()
    if ("//" in line or "#" in line_lc) and any(
        x in line_lc for x in ("example", "placeholder", "fake")
    ):
        return True
    return False


def _mask_line(line: str, pattern: CredentialPattern) -> str:
    global_rx = re.compile(pattern.regex.pattern, pattern.regex.flags | re.MULTILINE)
    return global_rx.sub(f"[{pattern.name} REDACTED]", line)


def scan(
    project_dir: str | os.PathLike[str],
    *,
    scan_global: bool = True,
    scan_source: bool = True,
    include_tests: bool = False,
    max_source_files: int = 5000,
) -> list[ScanFinding]:
    root = Path(project_dir).resolve()
    findings: list[ScanFinding] = []
    config_set = set(CONFIG_FILES)

    home = Path.home()

    global_configs: list[tuple[Path, str]] = []
    if scan_global:
        global_configs = [
            (home / ".claude" / "CLAUDE.md", "~/.claude/CLAUDE.md"),
            (home / ".claude" / "settings.json", "~/.claude/settings.json"),
        ]

    def scan_file_lines(abs_path: Path, label: str, severity: str) -> None:
        try:
            stat = abs_path.stat()
        except OSError:
            return
        if not abs_path.is_file() or stat.st_size > 10 * 1024 * 1024:
            return
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        for i, line in enumerate(text.splitlines(), start=1):
            if len(line) > 4096:
                continue
            if _ENV_REF.search(line) and not CREDENTIAL_PREFIX_QUICK_CHECK.search(line):
                continue
            for pattern in CREDENTIAL_PATTERNS:
                m = pattern.regex.search(line)
                if m:
                    if _is_known_example(line, m):
                        break
                    masked = _mask_line(line, pattern).strip()[:80]
                    findings.append(
                        ScanFinding(
                            file=label,
                            line=i,
                            pattern_id=pattern.id,
                            pattern_name=pattern.name,
                            severity=severity,
                            preview=masked,
                            fix=FIX_GUIDANCE.get(pattern.id),
                        )
                    )
                    break

    for gp, glabel in global_configs:
        scan_file_lines(gp, glabel, "critical")

    for rel in CONFIG_FILES:
        scan_file_lines(root / rel, rel, "critical")

    if scan_source:
        for file_path in _walk_source_files(root, max_source_files, include_tests):
            rel = str(file_path.relative_to(root))
            if rel in config_set:
                continue
            try:
                st = file_path.stat()
            except OSError:
                continue
            if st.st_size > 1024 * 1024 or not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(content.splitlines(), start=1):
                if len(line) > 4096:
                    continue
                t = line.strip()
                if t.startswith("//") and "regex" in t:
                    continue
                if _ENV_REF.search(line) and not CREDENTIAL_PREFIX_QUICK_CHECK.search(line):
                    continue
                if _PROCESS_ENV.search(line) and not CREDENTIAL_PREFIX_QUICK_CHECK.search(line):
                    continue
                if _OS_ENVIRON.search(line) and not CREDENTIAL_PREFIX_QUICK_CHECK.search(line):
                    continue
                for pattern in CREDENTIAL_PATTERNS:
                    m = pattern.regex.search(line)
                    if m:
                        if _is_known_example(line, m):
                            break
                        masked = _mask_line(line, pattern).strip()[:80]
                        findings.append(
                            ScanFinding(
                                file=rel,
                                line=i,
                                pattern_id=pattern.id,
                                pattern_name=pattern.name,
                                severity="high",
                                preview=masked,
                                fix=FIX_GUIDANCE.get(pattern.id),
                            )
                        )
                        break

    findings.sort(
        key=lambda f: (0 if f.severity == "critical" else 1, f.file, f.line),
    )
    return findings
