# VeilGuard Threat Model

## 1. Overview

VeilGuard defends against credential exposure through AI coding assistants.
Unlike traditional secret scanners that target git history or CI artifacts,
VeilGuard operates on the **developer workstation**, addressing the unique
attack surface created when an AI assistant reads project files, follows
instruction files, and persists conversation transcripts to disk.

This document describes the adversary model, trust boundaries, attack
surfaces, mitigations, and known limitations.

---

## 2. Adversary Model

### 2.1 Primary Threat: Inadvertent Credential Leakage to AI Context

The most common threat is **accidental**: a developer's credentials end up in
files the AI assistant reads (source code, config, instruction files, MCP
configs), or in transcripts the assistant writes. Once in the AI context
window, the credential may be:

- Transmitted to a remote model endpoint (cloud-hosted LLM)
- Stored in server-side conversation logs
- Echoed back in generated code or responses
- Persisted in local transcript files readable by other processes

### 2.2 Secondary Threat: Prompt-Injection Credential Extraction

A sophisticated attacker could craft repository content (e.g. a malicious
dependency, README, or issue template) that instructs the AI assistant to:

- Read `.env` files or credential stores
- Print environment variable values
- Exfiltrate secrets through generated code (e.g. `curl` commands)

### 2.3 Out-of-Scope Threats

VeilGuard does **not** defend against:

- **Model-side memorization**: Secrets in LLM training data are outside
  VeilGuard's control.
- **Compromised developer machine**: If the OS or AI tool binary is
  compromised, all bets are off.
- **Network-level interception**: TLS between the assistant and its API
  endpoint is the assistant vendor's responsibility.
- **Physical access**: An attacker with physical access to the machine can
  read the encrypted store's key material from the filesystem.

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Machine (Trusted)               │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐   │
│  │  VeilGuard   │   │  OS Process  │   │   Encrypted    │   │
│  │   CLI        │   │  Isolation   │   │   Local Store  │   │
│  └──────┬───────┘   └──────────────┘   └────────────────┘   │
│         │                                                    │
│  ───────┼──── Trust Boundary ─────────────────────────────   │
│         │                                                    │
│  ┌──────▼───────┐   ┌──────────────┐   ┌────────────────┐   │
│  │  AI Tool     │   │  Transcript  │   │   Cloud LLM    │   │
│  │  (Cursor,    │   │  Files       │   │   Endpoint     │   │
│  │   Claude,…)  │   │  (.jsonl)    │   │   (Untrusted)  │   │
│  └──────────────┘   └──────────────┘   └────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Trusted Components

| Component | Trust Rationale |
|-----------|----------------|
| Local filesystem | VeilGuard relies on POSIX permissions (0600/0700) to protect secret files |
| OS process isolation | `os.kill(pid, 0)` for PID file validation; `fcntl.flock` for write locking |
| Python runtime | VeilGuard runs as a standard Python process |
| cryptography library | AES-256-GCM and scrypt provided by a well-audited library |

### Untrusted Components

| Component | Risk |
|-----------|------|
| AI assistant behavior | May read files outside deny rules; behavior is non-deterministic |
| AI assistant transcripts | Persisted to disk; may contain secrets from prior interactions |
| Remote LLM endpoint | Context window contents are transmitted; server-side logging is opaque |
| Repository content | May contain prompt-injection attacks targeting the AI assistant |

---

## 4. Attack Surfaces

### 4.1 Context Window Injection

**Vector**: Credentials in files the AI reads (source, config, instruction
files).

**Examples**:
- API key hardcoded in `config.json`
- Database connection string in `.env` file read by assistant
- Secret in `CLAUDE.md` or `.cursorrules` instruction file

**VeilGuard mitigation**: `veilguard scan` detects 55 credential patterns
across source and config files. `veilguard init` installs deny rules that
block the AI from reading secret-bearing files (`.env`, `*.pem`, `*.key`,
`.aws/credentials`, etc.).

### 4.2 Transcript Persistence

**Vector**: AI tools write conversation history to local disk. If a secret
was discussed or appeared in tool output, it persists in transcript files.

**Examples**:
- Claude Code JSONL transcript containing an API key from a tool result
- Session summary `.md` file with a connection string

**VeilGuard mitigation**: `veilguard clean` scans transcript files with deep
JSON traversal and replaces credentials with `[REDACTED:<pattern_id>]`.
`veilguard watch` polls transcripts continuously. The Claude Code Stop hook
auto-redacts on session end.

### 4.3 Environment Variable Exposure

**Vector**: AI assistant runs shell commands that print or reference
environment variables containing secrets.

**Examples**:
- `echo $ANTHROPIC_API_KEY` in a tool-use Bash call
- `printenv | grep API` exposing key values
- `python -c "import os; print(os.environ['SECRET'])"` in generated code

**VeilGuard mitigation**: The PreToolUse hook intercepts Bash commands that
reference secret-related environment variables (`SECRET`, `PASSWORD`,
`API_KEY`, `TOKEN`, `PRIVATE_KEY`, `VAULT`, `CREDENTIAL`) and blocks
execution.

### 4.4 Secret Store Extraction

**Vector**: AI assistant attempts to read VeilGuard's own encrypted store or
extract secrets via the CLI.

**Examples**:
- `cat ~/.veilguard/store/secrets.enc`
- `veilguard secret get my-key --force`
- `veilguard run -- env` to dump all injected env vars

**VeilGuard mitigation**: Deny rules and hook patterns block these specific
command patterns. The encrypted store requires the key material (derived from
HOME + USER or a custom key) to decrypt.

### 4.5 MCP Configuration Exposure

**Vector**: MCP (Model Context Protocol) server configurations often contain
API keys or tokens in plain JSON.

**Examples**:
- `mcp.json` with `"api_key": "sk-..."` field
- `.cursor/mcp.json` or `.vscode/mcp.json` with embedded credentials

**VeilGuard mitigation**: `veilguard scan` includes MCP config files in its
scan targets. `veilguard init` deny rules block AI from reading these files
directly.

---

## 5. Mitigation Matrix

| Attack Surface | Detection | Prevention | Remediation |
|---------------|-----------|------------|-------------|
| Hardcoded credentials in source | `scan` (55 patterns) | `init` deny rules | `scan --fix` guidance |
| Credentials in config files | `scan` (config file targets) | `init` deny rules | `scan --fix` guidance |
| Credentials in AI context files | `verify` (context file scan) | `init` instruction files | Manual removal |
| Credentials in transcripts | `clean` / `watch` (deep scan) | Stop hook (auto-redact) | `clean` (redaction) |
| Env var exposure via commands | — | PreToolUse hook (Bash interception) | — |
| Secret store extraction | — | Hook + deny rules block access | — |
| MCP config secrets | `scan` (MCP configs) | `init` deny rules | `scan --fix` guidance |

---

## 6. Cryptographic Design

### 6.1 Key Derivation

```
key = scrypt(key_material, salt, n=16384, r=8, p=1, dklen=32)
```

- **key_material**: Custom passphrase or default `"{HOME}-veilguard-{USER}"`
- **salt**: 16 random bytes, generated once and stored in
  `~/.veilguard/store/.salt`
- **Parameters**: n=16384 (memory cost), r=8, p=1 — intentionally modest for
  CLI responsiveness while providing meaningful key stretching

### 6.2 Encryption

```
ciphertext = nonce (12 bytes) || AES-256-GCM(key, nonce, plaintext)
```

- **Algorithm**: AES-256-GCM (authenticated encryption with associated data)
- **Nonce**: 12 bytes of `secrets.token_bytes`, unique per write
- **Plaintext**: JSON-serialized secret store (all secrets in one encrypted
  blob)
- **Storage**: `~/.veilguard/store/secrets.enc` with `chmod 0600`

### 6.3 File Safety

- **Atomic writes**: All mutations use `write(tmpfile) → chmod 0600 → rename`
  to prevent partial writes
- **File locking**: `fcntl.flock(LOCK_EX)` around store/delete to prevent
  concurrent write races
- **Directory permissions**: `~/.veilguard/store/` created with `chmod 0700`

---

## 7. Limitations and Known Weaknesses

### 7.1 Default Key Material

When no custom key is configured, the encryption key is derived from `HOME`
and `USER` — values readable by any process running as the same user. This
protects against casual cross-user access but not against a determined local
attacker. VeilGuard warns on first use of default key material.

### 7.2 Regex-Based Detection

Pattern matching is inherently imprecise:

- **False negatives**: Novel credential formats not in the pattern library
  will be missed.
- **False positives**: Generic patterns (e.g. `sk-[a-zA-Z0-9]{48,}`) may
  match non-credential strings.
- **Evasion**: Credentials split across multiple lines, base64-encoded, or
  stored in binary files will not be detected.

### 7.3 AI Behavior Non-Determinism

Deny rules and instruction files are **advisory** for most AI tools. Only
Claude Code's PreToolUse hook provides a hard enforcement boundary. Other
tools (Cursor, Copilot, Windsurf, Cline) rely on the AI model respecting
instruction files, which is not guaranteed.

### 7.4 Transcript Coverage

VeilGuard currently targets Claude Code JSONL transcripts. Other AI tools may
store conversation data in different formats or locations not yet covered.

### 7.5 Single-Blob Store

All secrets are encrypted in a single JSON blob. This means:

- Every read decrypts the entire store
- Every write re-encrypts the entire store
- No per-secret access control or auditing

### 7.6 No Credential Rotation

VeilGuard detects and blocks credential exposure but does not automatically
rotate compromised credentials. Users must rotate manually using the guidance
provided by `scan --fix`.

### 7.7 Platform Dependency

File locking (`fcntl.flock`) is POSIX-specific. The current implementation
does not support Windows. PID-file-based watch daemon assumes Unix process
semantics.

---

## 8. Threat Model Summary

VeilGuard provides **defense in depth** against credential exposure to AI
coding assistants through five complementary mechanisms:

1. **Detection** — regex-based scanning of source, config, and transcript
   files
2. **Prevention** — tool-specific hooks, deny rules, and instruction files
3. **Remediation** — transcript redaction and fix guidance
4. **Isolation** — encrypted local secret store as an alternative to
   hardcoding
5. **Verification** — continuous monitoring that protections remain effective

The primary design principle is **fail-safe**: VeilGuard operates entirely
locally with no network communication, preferring false positives over missed
credentials, and providing multiple overlapping layers of protection.
