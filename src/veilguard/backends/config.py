"""Resolve which backend type to use."""

from __future__ import annotations

import json
import os
from pathlib import Path

SelectableBackendType = str  # "local" | future: keychain, vault, ...


def read_backend_config() -> dict[str, str]:
    path = Path.home() / ".veilguard" / "backend.json"
    if not path.is_file():
        return {}
    try:
        result: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
        return result
    except Exception as exc:
        import sys

        print(f"Warning: could not read backend config: {exc}", file=sys.stderr)
        return {}


def write_backend_config(data: dict[str, str]) -> None:
    root = Path.home() / ".veilguard"
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    path = root / "backend.json"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def resolve_backend_type(override: SelectableBackendType | None = None) -> SelectableBackendType:
    """Determine which backend to use (override > env > config > ``"local"``)."""
    if override:
        return override
    env = os.environ.get("VEILGUARD_BACKEND")
    if env:
        return env.strip().lower()
    cfg = read_backend_config()
    t = cfg.get("type", "local")
    if isinstance(t, str):
        return t.lower()
    return "local"
