# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **manambharadwaj@users.noreply.github.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive an acknowledgment within 48 hours. We aim to provide a
patch or mitigation within 7 days for critical issues.

## Security Design Principles

VeilGuard is built around these core security properties:

1. **No network communication** — VeilGuard never phones home, sends
   telemetry, or contacts any external service. All operations are local.

2. **Defense in depth** — Multiple overlapping mechanisms (hooks, deny rules,
   instruction files, scanning, transcript redaction) so that failure of one
   layer does not expose credentials.

3. **Fail-safe defaults** — When in doubt, VeilGuard blocks access rather
   than allowing it. Pattern matching prefers false positives over missed
   credentials.

4. **Minimal privilege** — Secret files are stored with `0600` permissions,
   directories with `0700`. File locking prevents concurrent write races.

5. **Cryptographic hygiene** — AES-256-GCM for authenticated encryption,
   scrypt for key derivation, 12-byte random nonces, atomic file writes.

## Known Limitations

- Default key material is derived from `$HOME` and `$USER`, which any
  same-user process can read. For stronger protection, set a custom key.
- Regex-based detection has inherent false-negative risk for novel or
  obfuscated credential formats.
- AI tool instruction files are advisory; only Claude Code's PreToolUse
  hook provides hard enforcement.
- Transcript redaction currently targets Claude Code JSONL format only.
- File locking uses POSIX `fcntl.flock` and does not support Windows.

For the full threat model, see [`docs/threat-model.md`](docs/threat-model.md).
