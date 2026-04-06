"""Smoke tests for CLI subcommands."""

import subprocess
import sys
import tempfile
from pathlib import Path


def _run(*args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "veilguard", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_version():
    r = _run("--version")
    assert r.returncode == 0
    assert "veilguard" in r.stdout


def test_scan_clean_project():
    with tempfile.TemporaryDirectory() as td:
        r = _run("scan", td)
        assert r.returncode == 0
        assert "No credential patterns matched" in r.stdout


def test_scan_finds_secret_exits_nonzero():
    with tempfile.TemporaryDirectory() as td:
        config = Path(td) / "config.json"
        config.write_text('{"token": "ghp_' + "a" * 36 + '"}')
        r = _run("scan", td)
        assert r.returncode == 1
        assert "GitHub" in r.stdout


def test_scan_json_output():
    with tempfile.TemporaryDirectory() as td:
        r = _run("scan", td, "--json")
        assert r.returncode == 0
        import json

        data = json.loads(r.stdout)
        assert isinstance(data, list)


def test_verify_clean():
    with tempfile.TemporaryDirectory() as td:
        r = _run("verify", td)
        assert r.returncode == 0
        assert "Passed: True" in r.stdout


def test_verify_json():
    with tempfile.TemporaryDirectory() as td:
        r = _run("verify", td, "--json")
        assert r.returncode == 0
        import json

        data = json.loads(r.stdout)
        assert "passed" in data


def test_status_json():
    with tempfile.TemporaryDirectory() as td:
        r = _run("status", td, "--json")
        assert r.returncode == 0
        import json

        data = json.loads(r.stdout)
        assert "is_protected" in data


def test_init_json():
    with tempfile.TemporaryDirectory() as td:
        r = _run("init", td, "--json")
        assert r.returncode == 0
        import json

        data = json.loads(r.stdout)
        assert "tools_configured" in data


def test_scan_with_fix():
    with tempfile.TemporaryDirectory() as td:
        config = Path(td) / "config.json"
        config.write_text('{"token": "ghp_' + "a" * 36 + '"}')
        r = _run("scan", td, "--fix")
        assert r.returncode == 1
        assert "Fix:" in r.stdout


def test_secret_get_not_found():
    r = _run("secret", "get", "nonexistent_key_12345")
    assert r.returncode != 0


def test_clean_with_path():
    with tempfile.TemporaryDirectory() as td:
        r = _run("clean", "--path", td, "--dry-run")
        assert r.returncode == 0
