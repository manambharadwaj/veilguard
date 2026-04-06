"""Tests for the verify module."""

import tempfile
from pathlib import Path

from veilguard.verify import verify


def test_verify_passed_with_no_exposures():
    with tempfile.TemporaryDirectory() as td:
        result = verify(td)
        assert result.passed is True
        assert result.exposed_in_context == []
        assert result.exposed_in_transcripts == []


def test_verify_detects_exposed_secret_in_context():
    with tempfile.TemporaryDirectory() as td:
        config = Path(td) / "config.json"
        config.write_text('{"key": "sk-ant-api03-abcdefghijklmnopqrst"}')
        result = verify(td)
        assert result.passed is False
        assert len(result.exposed_in_context) >= 1
        assert result.exposed_in_context[0]["pattern_name"] == "Anthropic API Key"


def test_verify_env_var_tracking():
    with tempfile.TemporaryDirectory() as td:
        result = verify(td)
        assert "ANTHROPIC_API_KEY" in result.env_vars
        assert "OPENAI_API_KEY" in result.env_vars


def test_verify_passed_true_even_without_env_vars():
    with tempfile.TemporaryDirectory() as td:
        result = verify(td)
        assert result.passed is True
