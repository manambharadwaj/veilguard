"""Tests for the scan module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from veilguard.scan import _is_known_example, _is_test_file, _walk_source_files, scan


def test_scan_finds_github_pat_in_file():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.json"
        pat = "ghp_" + ("a" * 36)
        p.write_text(f'token = "{pat}"\n', encoding="utf-8")
        findings = scan(td, scan_global=False, scan_source=False)
        assert any(f.pattern_id.startswith("github") for f in findings)


def test_scan_respects_placeholder():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.py"
        p.write_text('k = "sk-ant-api03-fake_key_for_testing_only"\n', encoding="utf-8")
        findings = scan(td, scan_global=False)
        assert not findings


def test_scan_source_files():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "app.py"
        pat = "ghp_" + "a" * 36
        p.write_text(f'TOKEN = "{pat}"\n', encoding="utf-8")
        findings = scan(td, scan_global=False, scan_source=True)
        assert len(findings) >= 1
        assert findings[0].severity == "high"


def test_scan_skips_long_lines():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.json"
        long_key = "ghp_" + "a" * 36
        p.write_text("x" * 4090 + long_key + "\n", encoding="utf-8")
        findings = scan(td, scan_global=False, scan_source=False)
        assert len(findings) == 0


def test_scan_skips_test_dirs_by_default():
    with tempfile.TemporaryDirectory() as td:
        test_dir = Path(td) / "tests"
        test_dir.mkdir()
        p = test_dir / "test_app.py"
        p.write_text(f'SECRET = "ghp_{"a" * 36}"\n', encoding="utf-8")
        findings = scan(td, scan_global=False, include_tests=False)
        assert len(findings) == 0


def test_scan_includes_tests_when_flag_set():
    with tempfile.TemporaryDirectory() as td:
        test_dir = Path(td) / "tests"
        test_dir.mkdir()
        p = test_dir / "test_app.py"
        p.write_text(f'SECRET = "ghp_{"a" * 36}"\n', encoding="utf-8")
        findings = scan(td, scan_global=False, include_tests=True)
        assert len(findings) >= 1


def test_scan_fix_guidance():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.json"
        p.write_text(f'{{"key": "ghp_{"a" * 36}"}}\n', encoding="utf-8")
        findings = scan(td, scan_global=False)
        github_finding = next(f for f in findings if f.pattern_id.startswith("github"))
        assert github_finding.fix is not None
        assert "GITHUB_TOKEN" in github_finding.fix


def test_is_test_file():
    assert _is_test_file("test_app.py") is True
    assert _is_test_file("app.test.js") is True
    assert _is_test_file("app.spec.ts") is True
    assert _is_test_file("app_test.go") is True
    assert _is_test_file("app.py") is False
    assert _is_test_file("testing.py") is False


def test_is_known_example_known_keys():
    import re
    m = re.search(r"AKIA[0-9A-Z]{16}", "AKIAIOSFODNN7EXAMPLE")
    assert m is not None
    assert _is_known_example("AKIAIOSFODNN7EXAMPLE", m) is True


def test_is_known_example_placeholder():
    import re
    m = re.search(r"sk-[a-zA-Z0-9]{48,}", "sk-" + "a" * 48)
    assert m is not None
    assert _is_known_example("sk-" + "a" * 48, m) is False

    m2 = re.search(r"ghp_[a-zA-Z0-9]{36}", "ghp_your_token_placeholder_abcdefghijklmnop")
    if m2:
        assert _is_known_example("ghp_your_token_placeholder_abcdefghijklmnop", m2) is True


def test_walk_source_files_max():
    with tempfile.TemporaryDirectory() as td:
        for i in range(10):
            (Path(td) / f"file{i}.py").touch()
        result = _walk_source_files(Path(td), max_files=3, include_tests=True)
        assert len(result) == 3
