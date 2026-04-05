import tempfile
from pathlib import Path

from veilguard.scan import scan


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
