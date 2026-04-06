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
        ("openrouter", "sk-or-v1-" + "a" * 48),
        ("openai-legacy", "sk-" + "a" * 48),
        ("groq", "gsk_abcdefghijklmnopqrstuv"),
        ("replicate", "r8_abcdefghijklmnopqrstuv"),
        ("huggingface", "hf_abcdefghijklmnopqrstuv"),
        ("perplexity", "pplx-" + "a" * 48),
        ("fireworks", "fw_" + "a" * 20),
        ("aws-access", "AKIAIOSFODNN7ABCDEFG"),
        ("aws-sts", "ASIAIOSFODNN7ABCDEFG"),
        ("gcp-service-account", '"type": "service_account"'),
        ("digitalocean", "dop_v1_" + "a" * 64),
        ("heroku", "HRKU-" + "a" * 30),
        ("fly-io", "fo1_" + "a" * 20),
        ("netlify", "nfp_" + "a" * 40),
        ("azure", "AccountKey=" + "a" * 43 + "="),
        ("supabase", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "a" * 60),
        ("slack", "xoxb-" + "1" * 10 + "-" + "2" * 10 + "-" + "a" * 24),
        ("slack-webhook", "hooks.slack.com/services/T12345678/B12345678/" + "a" * 24),
        ("slack-app", "xapp-1-A12345-12345-" + "a" * 10),
        ("telegram-bot", "123456789:" + "A" * 35),
        ("discord-bot", "M" + "a" * 23 + "." + "a" * 6 + "." + "a" * 27),
        ("discord-webhook", "discord.com/api/webhooks/123456/" + "a" * 20),
        ("twilio", "SK" + "a" * 32),
        ("sendgrid", "SG." + "a" * 22 + "." + "a" * 43),
        ("github-pat", "ghp_" + "a" * 36),
        ("github-fine", "github_pat_" + "a" * 22 + "_" + "a" * 59),
        ("github-oauth", "gho_" + "a" * 36),
        ("github-app", "ghs_" + "a" * 36),
        ("github-refresh", "ghr_" + "a" * 36),
        ("gitlab", "glpat-abcdefghijklmnopqrstuvwxyz"),
        ("gitlab-pipeline", "glptt-" + "a" * 40),
        ("gitlab-runner", "GR1348941" + "a" * 20),
        ("npm", "npm_" + "a" * 36),
        ("pypi", "pypi-" + "A" * 50),
        ("dockerhub", "dckr_pat_" + "a" * 20),
        ("bitbucket", "ATBB" + "a" * 32),
        ("stripe-test", "sk_test_" + "a" * 24),
        ("stripe-restricted", "rk_live_" + "a" * 24),
        ("stripe", "sk_live_" + "a" * 24),
        ("stripe-webhook", "whsec_" + "a" * 32),
        ("square", "sq0atp-" + "a" * 22),
        ("mongodb", "mongodb+srv://user:pass@host.internal/db"),
        ("postgres", "postgres://user:pass@localhost:5432/db"),
        ("mysql", "mysql://user:pass@localhost/db"),
        ("redis", "redis://user:pass@localhost:6379"),
        ("google", "AIzaSyD-abcdefghijklmnopqrstuvwxyz12345"),
        ("google-oauth", "ya29." + "a" * 60),
        ("pem-private-key", "-----BEGIN RSA PRIVATE KEY-----"),
        ("firebase-fcm", "AAAA" + "a" * 7 + ":" + "a" * 152),
        ("newrelic", "NRAK-" + "A" * 27),
        ("newrelic-insight", "NRIQ-" + "A" * 27),
        ("sentry", "sntrys_" + "a" * 40),
        ("grafana", "glc_" + "a" * 32),
        ("linear", "lin_api_" + "a" * 40),
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
