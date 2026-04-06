"""Tests for transcript discovery, scanning, and redaction."""

import json
import tempfile
from pathlib import Path

from veilguard.transcript import (
    atomic_write,
    clean_transcripts,
    deep_scan,
    scan_transcript_file,
)


def test_deep_scan_redacts_nested_secret():
    data = {"message": {"content": "key is sk-ant-api03-abcdefghijklmnopqrst"}}
    findings = []
    result = deep_scan(data, "", findings, ("test.jsonl", 1))
    assert len(findings) == 1
    assert findings[0].pattern_id == "anthropic"
    assert "REDACTED" in result["message"]["content"]


def test_deep_scan_skips_keys():
    data = {"uuid": "sk-ant-api03-abcdefghijklmnopqrst", "content": "safe text"}
    findings = []
    result = deep_scan(data, "", findings, ("test.jsonl", 1))
    assert len(findings) == 0
    assert result["uuid"] == data["uuid"]


def test_deep_scan_handles_list():
    data = [{"text": "ghp_" + "a" * 36}, "plain"]
    findings = []
    result = deep_scan(data, "", findings, ("test.jsonl", 1))
    assert len(findings) == 1
    assert "REDACTED" in result[0]["text"]
    assert result[1] == "plain"


def test_deep_scan_passthrough_none_and_numbers():
    findings = []
    assert deep_scan(None, "", findings, ("f", 1)) is None
    assert deep_scan(42, "", findings, ("f", 1)) == 42
    assert len(findings) == 0


def test_scan_transcript_file_jsonl():
    secret = "sk-ant-api03-abcdefghijklmnopqrst"
    with tempfile.NamedTemporaryFile(suffix=".jsonl", mode="w", delete=False) as f:
        f.write(json.dumps({"message": secret}) + "\n")
        f.write(json.dumps({"text": "safe"}) + "\n")
        path = f.name
    try:
        findings, redacted = scan_transcript_file(path, dry_run=True)
        assert len(findings) == 1
        assert redacted is None

        findings2, redacted2 = scan_transcript_file(path, dry_run=False)
        assert len(findings2) == 1
        assert redacted2 is not None
        assert "REDACTED" in redacted2[0]
    finally:
        Path(path).unlink(missing_ok=True)


def test_scan_transcript_file_md():
    with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as f:
        f.write("Some text with ghp_" + "a" * 36 + "\n")
        f.write("Safe line\n")
        path = f.name
    try:
        findings, _ = scan_transcript_file(path, dry_run=True)
        assert len(findings) == 1
    finally:
        Path(path).unlink(missing_ok=True)


def test_scan_transcript_file_invalid_json_line():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", mode="w", delete=False) as f:
        f.write("not json at all\n")
        f.write(json.dumps({"x": "safe"}) + "\n")
        path = f.name
    try:
        findings, _ = scan_transcript_file(path, dry_run=False)
        assert len(findings) == 0
    finally:
        Path(path).unlink(missing_ok=True)


def test_atomic_write():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        f.write("original\n")
        path = f.name
    try:
        atomic_write(path, ["line1", "line2"])
        content = Path(path).read_text()
        assert content == "line1\nline2"
    finally:
        Path(path).unlink(missing_ok=True)


def test_clean_transcripts_with_target_path():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.jsonl"
        secret = "sk-ant-api03-abcdefghijklmnopqrst"
        p.write_text(json.dumps({"msg": secret}) + "\n")

        result = clean_transcripts(dry_run=True, target_path=str(p))
        assert result.files_scanned == 1
        assert result.total_findings == 1
        assert result.total_redacted == 0

        original = p.read_text()
        assert secret in original
