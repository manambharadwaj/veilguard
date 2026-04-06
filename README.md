# VeilGuard

**Keep API keys and secrets out of AI coding assistant context.**

VeilGuard is a Python CLI that scans your codebase for hardcoded credentials, installs protective hooks and deny rules for AI tools, manages secrets in an encrypted local store, and monitors AI transcripts for accidental secret exposure.

Supports **Cursor**, **Claude Code**, **GitHub Copilot**, **Windsurf**, **Cline**, and **Aider**.

[![CI](https://github.com/manambharadwaj/veilguard/actions/workflows/ci.yml/badge.svg)](https://github.com/manambharadwaj/veilguard/actions/workflows/ci.yml)

---

## Why VeilGuard?

AI coding assistants read your project files, config, and sometimes transcripts. If a secret is in any of those, it enters the AI context — and potentially the cloud. VeilGuard prevents that:

- **Scans** source and config files for 45+ credential patterns (AWS, OpenAI, Stripe, GitHub, Slack, database URIs, PEM keys, and more)
- **Blocks** AI tools from reading secret files (`.env`, `*.pem`, `*.key`, `.aws/credentials`, etc.)
- **Redacts** secrets that leak into Claude Code JSONL transcripts
- **Stores** secrets locally with AES-256-GCM encryption so you never need to hardcode them

---

## Install

```bash
git clone https://github.com/manambharadwaj/veilguard.git
cd veilguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Quick Start

```bash
# Detect AI tools in your project and install protections
veilguard init

# Scan for hardcoded credentials
veilguard scan

# Check if protections are active
veilguard status

# Verify env vars aren't exposed in AI context
veilguard verify
```

---

## Commands

| Command | Description |
|---------|-------------|
| `veilguard init [dir]` | Detect AI tools, install hooks, deny rules, and instruction files |
| `veilguard scan [dir]` | Scan config and source files for hardcoded credentials |
| `veilguard status [dir]` | Show whether protections are active |
| `veilguard verify [dir]` | Check that env vars aren't exposed in context files or transcripts |
| `veilguard clean` | Redact credentials found in Claude Code JSONL transcripts |
| `veilguard watch` | Continuously poll transcripts and redact in real time |
| `veilguard secret set <name> <value>` | Store a secret in the encrypted local store |
| `veilguard secret get <name>` | Retrieve a secret |
| `veilguard secret list` | List stored secret names |
| `veilguard secret remove <name>` | Delete a secret |
| `veilguard backend show\|set` | View or change the storage backend |

---

## How It Works

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Developer Machine                     │
│                                                          │
│   ┌──────────┐     ┌────────────┐     ┌──────────────┐  │
│   │ AI Tool  │◄────│  VeilGuard │────►│  Encrypted   │  │
│   │ (Cursor, │     │    CLI     │     │  Local Store │  │
│   │  Claude, │     └──────┬─────┘     │  (AES-256)   │  │
│   │  etc.)   │            │           └──────────────┘  │
│   └────┬─────┘     ┌──────▼──────┐                      │
│        │           │  Hooks /     │                      │
│        │           │  Deny Rules /│                      │
│        │           │  Instructions│                      │
│        ▼           └─────────────┘                      │
│   ┌───────────┐                                          │
│   │Transcripts│◄── watch / clean ── VeilGuard            │
│   │ (.jsonl)  │                                          │
│   └───────────┘                                          │
└─────────────────────────────────────────────────────────┘
```

### Detection & Initialization

`veilguard init` scans for AI tool markers in your project (`.cursor/`, `.claude/`, `.github/copilot-instructions.md`, etc.) and installs tool-specific protections:

| AI Tool | What Gets Installed |
|---------|-------------------|
| **Claude Code** | PreToolUse bash hook, Stop hook (auto-redact on session end), deny rules in `settings.json`, instructions in `CLAUDE.md` |
| **Cursor** | Instructions appended to `.cursorrules` |
| **GitHub Copilot** | Instructions appended to `.github/copilot-instructions.md` |
| **Windsurf** | Instructions appended to `.windsurfrules` |
| **Cline** | Instructions appended to `.clinerules` |
| **Aider** | Secret file patterns added to `.aiderignore` |

### Credential Scanning

VeilGuard ships 45+ regex patterns organized by category:

| Category | Examples |
|----------|---------|
| AI/ML | Anthropic, OpenAI, Groq, HuggingFace, Perplexity, Replicate |
| Cloud | AWS, GCP, Azure, DigitalOcean, Heroku, Fly.io, Netlify, Supabase |
| Communication | Slack, Discord, Telegram, Twilio, SendGrid |
| Developer | GitHub, GitLab, npm, PyPI, Docker Hub, Bitbucket |
| Payment | Stripe (live/test/restricted/webhook), Square |
| Database | PostgreSQL, MongoDB, MySQL, Redis connection strings |
| Auth | Google API, PEM private keys, Firebase |
| Monitoring | New Relic, Sentry, Grafana, Linear |

Patterns are ordered from most specific to least specific (first match wins). False positives are filtered via known example keys, placeholder detection, and comment heuristics.

### Transcript Protection

Claude Code stores conversation history as JSONL files under `~/.claude/projects/`. VeilGuard can:

- **`clean`**: Scan all transcript files, recursively walk the JSON structure, and replace credentials with `[REDACTED:<pattern_id>]`
- **`watch`**: Run a foreground poller (3-second interval) that automatically redacts new secrets as they appear
- **Stop hook**: Auto-runs `veilguard clean --last` when a Claude Code session ends

### Secret Store

Secrets are encrypted at rest using AES-256-GCM with keys derived via scrypt:

```
Key:   scrypt(key_material, salt, n=16384, r=8, p=1) → 256-bit
Store: nonce (12 bytes) || AES-256-GCM(plaintext JSON)
Path:  ~/.veilguard/store/secrets.enc
```

All file writes use atomic tmp-file + `chmod 600` + rename to prevent partial writes or permission leaks.

---

## Supported Credential Patterns

<details>
<summary>Full list of 45+ detected patterns (click to expand)</summary>

| Pattern | Prefix/Signature |
|---------|-----------------|
| Anthropic API Key | `sk-ant-api03-...` |
| OpenAI Project Key | `sk-proj-...` |
| OpenRouter API Key | `sk-or-v1-...` |
| OpenAI Legacy Key | `sk-...` (48+ chars) |
| Groq API Key | `gsk_...` |
| Replicate API Token | `r8_...` |
| HuggingFace Token | `hf_...` |
| Perplexity API Key | `pplx-...` |
| Fireworks AI Key | `fw_...` |
| AWS Access Key | `AKIA...` |
| AWS STS Token | `ASIA...` |
| GCP Service Account | `"type": "service_account"` |
| DigitalOcean PAT | `dop_v1_...` |
| Heroku API Key | `HRKU-...` |
| Fly.io Token | `fo1_...` |
| Netlify PAT | `nfp_...` |
| Azure Key | `AccountKey=...` / `SharedAccessKey=...` |
| Supabase Service Key | JWT with `eyJhbGci...` prefix |
| Slack Token | `xox[baprs]-...` |
| Slack Webhook | `hooks.slack.com/services/...` |
| Slack App Token | `xapp-...` |
| Telegram Bot Token | `123456789:ABC-...` |
| Discord Bot Token | `M/N...` (JWT-like) |
| Discord Webhook | `discord.com/api/webhooks/...` |
| Twilio API Key | `SK...` (32 hex) |
| SendGrid Key | `SG....` |
| GitHub PAT | `ghp_...` |
| GitHub Fine-Grained PAT | `github_pat_...` |
| GitHub OAuth | `gho_...` |
| GitHub App Token | `ghs_...` |
| GitHub Refresh Token | `ghr_...` |
| GitLab PAT | `glpat-...` |
| GitLab Pipeline Trigger | `glptt-...` |
| GitLab Runner Token | `GR1348941...` |
| npm Token | `npm_...` |
| PyPI Token | `pypi-...` |
| Docker Hub PAT | `dckr_pat_...` |
| Bitbucket App Password | `ATBB...` |
| Stripe Live Key | `sk_live_...` |
| Stripe Test Key | `sk_test_...` |
| Stripe Restricted Key | `rk_live_...` |
| Stripe Webhook Secret | `whsec_...` |
| Square API Key | `sq0...-...` |
| MongoDB URI | `mongodb+srv://...` |
| PostgreSQL URI | `postgres://...` |
| MySQL URI | `mysql://...` |
| Redis URI | `redis://...` / `rediss://...` |
| Google API Key | `AIza...` |
| Google OAuth Token | `ya29....` |
| PEM Private Key | `-----BEGIN ... PRIVATE KEY-----` |
| Firebase FCM Key | `AAAA...:...` |
| New Relic API Key | `NRAK-...` |
| Sentry Auth Token | `sntrys_...` |
| Grafana Cloud Key | `glc_...` |
| Linear API Key | `lin_api_...` |

</details>

---

## Project Structure

```
src/veilguard/
├── cli.py              CLI entry point (argparse subcommands)
├── patterns.py         Credential regex catalog + file lists
├── scan.py             Source and config file scanner
├── detect.py           AI tool detection via filesystem markers
├── initialize.py       Hook generation, deny rules, instruction files
├── transcript.py       JSONL transcript discovery + deep redaction
├── watch.py            Foreground transcript poller
├── status.py           Protection health aggregator
├── verify.py           Env var vs context exposure checker
├── secret_store.py     High-level secret management API
├── backends/
│   ├── types.py        WritableSecretBackend protocol
│   ├── config.py       Backend resolution (env → config → default)
│   ├── factory.py      Backend constructor
│   └── local.py        AES-256-GCM encrypted local store
└── (roadmap stubs)
    ├── session/        Touch ID / biometric session flows
    ├── phantom/        secret:// URI resolution
    ├── scope/          Cloud scope discovery + drift checks
    ├── broker/         Credential broker daemon
    └── mcp/            MCP server config protection
```

---

## Security Model

- **Encryption**: AES-256-GCM with scrypt-derived keys (n=16384, r=8, p=1)
- **File permissions**: All secret files written as `0600`, directories as `0700`
- **Atomic writes**: Every file mutation uses tmpfile + chmod + rename
- **Size limits**: Lines >4096 chars and files >10MB are skipped to bound regex work
- **Single instance**: Watch daemon uses exclusive PID file to prevent duplicates
- **No network**: VeilGuard never phones home or sends data anywhere

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint
ruff check src/ tests/
```

## License

MIT — see [LICENSE](LICENSE).
