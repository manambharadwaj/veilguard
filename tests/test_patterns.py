"""Tests for credential pattern matching."""

import pytest

from veilguard.patterns import CREDENTIAL_PATTERNS, CREDENTIAL_PREFIX_QUICK_CHECK


def _find(pattern_id: str):
    return next(x for x in CREDENTIAL_PATTERNS if x.id == pattern_id)


def test_anthropic_pattern():
    p = _find("anthropic")
    assert p.regex.search("sk-ant-api03-xxxxxxxxxxxxxxxxxxxx")


def test_prefix_quick_check_skips_env_only_line():
    line = 'echo "${API_KEY}"'
    assert not CREDENTIAL_PREFIX_QUICK_CHECK.search(line)


@pytest.mark.parametrize(
    "pattern_id,sample",
    [
        ("anthropic", "sk-ant-api03-abcdefghijklmnopqrstu"),
        ("openai-proj", "sk-proj-abcdefghijklmnopqrstuvwx"),
        ("openai-legacy", "sk-" + "a" * 48),
        ("groq", "gsk_abcdefghijklmnopqrstuv"),
        ("replicate", "r8_abcdefghijklmnopqrstuv"),
        ("huggingface", "hf_abcdefghijklmnopqrstuv"),
        ("aws-access", "AKIAIOSFODNN7ABCDEFG"),
        ("aws-sts", "ASIAIOSFODNN7ABCDEFG"),
        ("github-pat", "ghp_" + "a" * 36),
        ("github-fine", "github_pat_" + "a" * 22 + "_" + "a" * 59),
        ("github-oauth", "gho_" + "a" * 36),
        ("github-app", "ghs_" + "a" * 36),
        ("gitlab", "glpat-abcdefghijklmnopqrstuvwxyz"),
        ("npm", "npm_" + "a" * 36),
        ("pypi", "pypi-" + "A" * 50),
        ("dockerhub", "dckr_pat_" + "a" * 20),
        ("stripe", "sk_live_" + "a" * 24),
        ("stripe-test", "sk_test_" + "a" * 24),
        ("stripe-webhook", "whsec_" + "a" * 32),
        ("slack", "xoxb-" + "1" * 10 + "-" + "2" * 10 + "-" + "a" * 24),
        ("sendgrid", "SG." + "a" * 22 + "." + "a" * 43),
        ("google", "AIzaSyD-abcdefghijklmnopqrstuvwxyz12345"),
        ("pem-private-key", "-----BEGIN RSA PRIVATE KEY-----"),
        ("mongodb", "mongodb+srv://user:pass@host.example.com/db"),
        ("postgres", "postgres://user:pass@localhost:5432/db"),
        ("mysql", "mysql://user:pass@localhost/db"),
        ("redis", "redis://user:pass@localhost:6379"),
        ("sentry", "sntrys_" + "a" * 40),
        ("linear", "lin_api_" + "a" * 40),
        ("newrelic", "NRAK-" + "A" * 27),
        ("digitalocean", "dop_v1_" + "a" * 64),
        ("netlify", "nfp_" + "a" * 40),
    ],
)
def test_pattern_matches(pattern_id, sample):
    p = _find(pattern_id)
    assert p.regex.search(sample), f"Pattern {pattern_id} did not match: {sample[:40]}..."


@pytest.mark.parametrize(
    "pattern_id,non_match",
    [
        ("anthropic", "sk-ant-short"),
        ("aws-access", "AKIA_short"),
        ("github-pat", "ghp_short"),
        ("stripe", "sk_live_short"),
    ],
)
def test_pattern_rejects_short(pattern_id, non_match):
    p = _find(pattern_id)
    assert not p.regex.search(non_match), f"Pattern {pattern_id} incorrectly matched: {non_match}"


def test_all_patterns_have_env_prefix():
    for p in CREDENTIAL_PATTERNS:
        assert p.env_prefix, f"Pattern {p.id} is missing env_prefix"


def test_all_patterns_have_category():
    for p in CREDENTIAL_PATTERNS:
        assert p.category, f"Pattern {p.id} is missing category"
