import re

from veilguard.patterns import CREDENTIAL_PATTERNS, CREDENTIAL_PREFIX_QUICK_CHECK


def test_anthropic_pattern():
    p = next(x for x in CREDENTIAL_PATTERNS if x.id == "anthropic")
    assert p.regex.search("sk-ant-api03-xxxxxxxxxxxxxxxxxxxx")


def test_prefix_quick_check_skips_env_only_line():
    line = 'echo "${API_KEY}"'
    assert not CREDENTIAL_PREFIX_QUICK_CHECK.search(line)
