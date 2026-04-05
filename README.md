# VeilGuard

Python CLI that helps keep API keys and secrets out of AI coding assistant context (Cursor, Claude Code, Copilot, Windsurf, Cline, Aider).

## Install

```bash
cd /path/to/veilguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```bash
veilguard init
veilguard scan
veilguard status
veilguard verify
```

Encrypted local store (default): `~/.veilguard/store/`.

## Commands

| Command | Purpose |
|--------|---------|
| `init` | Detect AI tools, install hooks / rules / instructions |
| `scan` | Find hardcoded credentials in config and source |
| `status` | Show whether protections look active |
| `verify` | Check env vars vs exposure in context files and transcripts |
| `secret` | `set`, `get`, `list`, `remove` in configured backend |
| `clean` | Redact credentials in Claude Code JSONL transcripts |
| `watch` | Poll transcripts and redact (foreground; basic) |

Extended areas (MCP hardening, cloud broker, multi-cloud scope) are scaffolded under `veilguard/` for incremental implementation.

## Security notes

- Line and file size caps limit regex work against huge inputs.
- Local store uses scrypt + AES-256-GCM (`cryptography`).
- No optional vendor-specific AI analysis packages are required.

## License

MIT — see [LICENSE](LICENSE).
