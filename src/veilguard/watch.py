"""Transcript watcher (foreground polling)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from veilguard.transcript import atomic_write, discover_transcripts, scan_transcript_file

VEIL_DIR = Path.home() / ".veilguard"
PID_FILE = VEIL_DIR / "watch.pid"
DEBOUNCE_SEC = 3.0


def is_watch_running() -> bool:
    if not PID_FILE.is_file():
        return False
    try:
        data = json.loads(PID_FILE.read_text(encoding="utf-8"))
        pid = int(data.get("pid", 0))
    except Exception:
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def start_watch() -> None:
    VEIL_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    if is_watch_running():
        print("VeilGuard watch already running (pid file present and process alive).")
        return

    if PID_FILE.is_file():
        try:
            PID_FILE.unlink()
        except OSError:
            pass

    transcript_root = Path.home() / ".claude" / "projects"
    if not transcript_root.is_dir():
        print("Transcript directory not found:", transcript_root)
        print("Start a Claude Code session first, then re-run.")
        return

    pid_data = json.dumps({"pid": os.getpid(), "startedAt": int(time.time() * 1000)})
    try:
        fd = os.open(PID_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, pid_data.encode("utf-8"))
        finally:
            os.close(fd)
    except FileExistsError:
        print("Another watch instance may be starting; remove", PID_FILE, "if stuck.")
        return

    mtimes: dict[str, float] = {}
    print("VeilGuard watch running (Ctrl+C to stop). Polling every", DEBOUNCE_SEC, "s.")

    try:
        while True:
            for fp in discover_transcripts():
                try:
                    st = Path(fp).stat()
                except OSError:
                    continue
                prev = mtimes.get(fp)
                if prev is not None and st.st_mtime <= prev:
                    continue
                mtimes[fp] = st.st_mtime
                findings, redacted = scan_transcript_file(fp, dry_run=False)
                if findings and redacted is not None:
                    atomic_write(fp, redacted)
                    print("Redacted", len(findings), "finding(s) in", fp)
            time.sleep(DEBOUNCE_SEC)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        try:
            PID_FILE.unlink(missing_ok=True)
        except OSError:
            pass
