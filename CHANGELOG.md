# Changelog

All notable changes to VeilGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-05

### Added

- CLI with subcommands: `init`, `scan`, `status`, `verify`, `clean`, `watch`,
  `secret`, `backend`
- 55 credential patterns across 8 categories (AI/ML, cloud, communication,
  developer, payment, database, auth, monitoring)
- AI tool detection for Claude Code, Cursor, GitHub Copilot, Windsurf, Cline,
  and Aider
- Claude Code PreToolUse hook with Bash command interception
- Claude Code Stop hook for automatic transcript redaction
- Deny rules and instruction file generation for all supported tools
- JSONL transcript deep-scan and in-place redaction
- Foreground transcript watcher with PID-file-based single-instance guard
- Encrypted local secret store (AES-256-GCM, scrypt key derivation)
- `--json` output flag for `init`, `scan`, `status`, `verify`
- `--fix` flag for `scan` with per-pattern remediation guidance
- Non-zero exit codes for `scan` (findings), `verify` (exposures), `secret
  remove` (not found)
- File locking (`fcntl.flock`) on secret store writes
- False-positive filtering via known example keys, placeholder detection, and
  comment heuristics
- Formal threat model document
- Benchmark evaluation framework with ground-truth corpus
- Tool comparison script (detect-secrets, gitleaks, trufflehog)
- CI with Ruff linting, mypy type checking, pytest + coverage on Python
  3.11/3.12/3.13
- 140 tests covering all source modules

[0.1.0]: https://github.com/manambharadwaj/veilguard/releases/tag/v0.1.0
