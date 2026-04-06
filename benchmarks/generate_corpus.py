#!/usr/bin/env python3
"""Generate the VeilGuard benchmark corpus and ground-truth manifest.

Run once to populate benchmarks/corpus/ with synthetic files for evaluation.
Produces benchmarks/corpus/manifest.json mapping each file to expected findings.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"
TP_DIR = CORPUS_DIR / "true_positives"
TN_DIR = CORPUS_DIR / "true_negatives"
EDGE_DIR = CORPUS_DIR / "edge_cases"

random.seed(42)


def _rand_hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _rand_alnum(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _rand_upper_alnum(n: int) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))


# ---------------------------------------------------------------------------
# True-positive samples: one file per pattern, realistic embedding context
# ---------------------------------------------------------------------------

TRUE_POSITIVE_SAMPLES: list[dict] = [
    {
        "id": "anthropic",
        "file": "anthropic_key.py",
        "content": 'import os\n\nANTHROPIC_API_KEY = "sk-ant-api03-{v}"\nclient = anthropic.Client(api_key=ANTHROPIC_API_KEY)\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
    {
        "id": "openai-proj",
        "file": "openai_proj.py",
        "content": 'OPENAI_KEY = "sk-proj-{v}"\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
    {
        "id": "openrouter",
        "file": "openrouter_config.json",
        "content": '{{"api_key": "sk-or-v1-{v}"}}\n',
        "gen": lambda: _rand_alnum(48),
        "count": 1,
    },
    {
        "id": "openai-legacy",
        "file": "openai_legacy.env",
        "content": 'OPENAI_API_KEY=sk-{v}\n',
        "gen": lambda: _rand_alnum(48),
        "count": 1,
    },
    {
        "id": "groq",
        "file": "groq_api.py",
        "content": 'groq_key = "gsk_{v}"\n',
        "gen": lambda: _rand_alnum(30),
        "count": 1,
    },
    {
        "id": "replicate",
        "file": "replicate_token.sh",
        "content": '#!/bin/bash\nexport REPLICATE_API_TOKEN="r8_{v}"\n',
        "gen": lambda: _rand_alnum(30),
        "count": 1,
    },
    {
        "id": "huggingface",
        "file": "hf_token.py",
        "content": 'HF_TOKEN = "hf_{v}"\n',
        "gen": lambda: _rand_alnum(30),
        "count": 1,
    },
    {
        "id": "perplexity",
        "file": "perplexity_key.env",
        "content": 'PERPLEXITY_API_KEY=pplx-{v}\n',
        "gen": lambda: _rand_alnum(48),
        "count": 1,
    },
    {
        "id": "fireworks",
        "file": "fireworks.py",
        "content": 'FW_KEY = "fw_{v}"\n',
        "gen": lambda: _rand_alnum(30),
        "count": 1,
    },
    {
        "id": "aws-access",
        "file": "aws_creds.py",
        "content": 'AWS_ACCESS_KEY_ID = "AKIA{v}"\nAWS_SECRET = "something"\n',
        "gen": lambda: _rand_upper_alnum(16),
        "count": 1,
    },
    {
        "id": "aws-sts",
        "file": "aws_sts.sh",
        "content": 'export AWS_ACCESS_KEY_ID="ASIA{v}"\n',
        "gen": lambda: _rand_upper_alnum(16),
        "count": 1,
    },
    {
        "id": "gcp-service-account",
        "file": "gcp_sa.json",
        "content": '{{\n  "type": "service_account",\n  "project_id": "my-project"\n}}\n',
        "gen": lambda: "",
        "count": 1,
    },
    {
        "id": "digitalocean",
        "file": "do_token.sh",
        "content": 'export DO_TOKEN="dop_v1_{v}"\n',
        "gen": lambda: _rand_hex(64),
        "count": 1,
    },
    {
        "id": "heroku",
        "file": "heroku_key.rb",
        "content": 'HEROKU_KEY = "HRKU-{v}"\n',
        "gen": lambda: _rand_alnum(30),
        "count": 1,
    },
    {
        "id": "fly-io",
        "file": "fly_token.sh",
        "content": 'FLY_TOKEN="fo1_{v}"\n',
        "gen": lambda: _rand_alnum(30),
        "count": 1,
    },
    {
        "id": "netlify",
        "file": "netlify_pat.env",
        "content": 'NETLIFY_AUTH_TOKEN=nfp_{v}\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
    {
        "id": "azure",
        "file": "azure_storage.py",
        "content": 'conn = "AccountKey={v}"\n',
        "gen": lambda: _rand_alnum(43) + "=",
        "count": 1,
    },
    {
        "id": "supabase",
        "file": "supabase_key.ts",
        "content": 'const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{v}"\n',
        "gen": lambda: _rand_alnum(60),
        "count": 1,
    },
    {
        "id": "slack",
        "file": "slack_bot.py",
        "content": 'SLACK_TOKEN = "xoxb-1234567890-1234567890-{v}"\n',
        "gen": lambda: _rand_alnum(24),
        "count": 1,
    },
    {
        "id": "slack-webhook",
        "file": "slack_webhook.sh",
        "content": 'WEBHOOK="https://hooks.slack.com/services/T12345678/B12345678/{v}"\n',
        "gen": lambda: _rand_alnum(24),
        "count": 1,
    },
    {
        "id": "slack-app",
        "file": "slack_app.env",
        "content": 'SLACK_APP_TOKEN=xapp-1-A12345-12345-{v}\n',
        "gen": lambda: _rand_hex(32),
        "count": 1,
    },
    {
        "id": "telegram-bot",
        "file": "telegram.py",
        "content": 'BOT_TOKEN = "123456789:{v}"\n',
        "gen": lambda: _rand_alnum(35),
        "count": 1,
    },
    {
        "id": "discord-bot",
        "file": "discord_bot.js",
        "content": 'const TOKEN = "M{a}.{b}.{c}";\n'.format(
            a=_rand_alnum(23), b=_rand_alnum(6), c=_rand_alnum(27)
        ),
        "gen": lambda: "",
        "count": 1,
    },
    {
        "id": "discord-webhook",
        "file": "discord_hook.sh",
        "content": 'HOOK="https://discord.com/api/webhooks/123456789/{v}"\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
    {
        "id": "twilio",
        "file": "twilio.py",
        "content": 'TWILIO_API_KEY = "SK{v}"\n',
        "gen": lambda: _rand_hex(32),
        "count": 1,
    },
    {
        "id": "sendgrid",
        "file": "sendgrid.env",
        "content": 'SENDGRID_API_KEY=SG.{a}.{b}\n',
        "gen": lambda: "",
        "count": 1,
        "content_fn": lambda: f'SENDGRID_API_KEY=SG.{_rand_alnum(22)}.{_rand_alnum(43)}\n',
    },
    {
        "id": "github-pat",
        "file": "gh_token.sh",
        "content": 'export GITHUB_TOKEN="ghp_{v}"\n',
        "gen": lambda: _rand_alnum(36),
        "count": 1,
    },
    {
        "id": "github-fine",
        "file": "gh_fine.env",
        "content": 'GH_TOKEN=github_pat_{a}_{b}\n',
        "gen": lambda: "",
        "count": 1,
        "content_fn": lambda: f'GH_TOKEN=github_pat_{_rand_alnum(22)}_{_rand_alnum(59)}\n',
    },
    {
        "id": "github-oauth",
        "file": "gh_oauth.py",
        "content": 'OAUTH_TOKEN = "gho_{v}"\n',
        "gen": lambda: _rand_alnum(36),
        "count": 1,
    },
    {
        "id": "github-app",
        "file": "gh_app.sh",
        "content": 'GHS_TOKEN="ghs_{v}"\n',
        "gen": lambda: _rand_alnum(36),
        "count": 1,
    },
    {
        "id": "github-refresh",
        "file": "gh_refresh.env",
        "content": 'GH_REFRESH=ghr_{v}\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
    {
        "id": "gitlab",
        "file": "gitlab_pat.sh",
        "content": 'export GITLAB_TOKEN="glpat-{v}"\n',
        "gen": lambda: _rand_alnum(20),
        "count": 1,
    },
    {
        "id": "gitlab-pipeline",
        "file": "gitlab_pipeline.yml",
        "content": 'trigger_token: "glptt-{v}"\n',
        "gen": lambda: _rand_hex(40),
        "count": 1,
    },
    {
        "id": "gitlab-runner",
        "file": "gitlab_runner.toml",
        "content": 'token = "GR1348941{v}"\n',
        "gen": lambda: _rand_alnum(20),
        "count": 1,
    },
    {
        "id": "npm",
        "file": "npmrc_token.sh",
        "content": 'NPM_TOKEN="npm_{v}"\n',
        "gen": lambda: _rand_alnum(36),
        "count": 1,
    },
    {
        "id": "pypi",
        "file": "pypi_token.env",
        "content": 'PYPI_API_TOKEN=pypi-{v}\n',
        "gen": lambda: _rand_alnum(50),
        "count": 1,
    },
    {
        "id": "dockerhub",
        "file": "docker_pat.sh",
        "content": 'DOCKER_TOKEN="dckr_pat_{v}"\n',
        "gen": lambda: _rand_alnum(20),
        "count": 1,
    },
    {
        "id": "bitbucket",
        "file": "bitbucket.env",
        "content": 'BITBUCKET_TOKEN=ATBB{v}\n',
        "gen": lambda: _rand_alnum(32),
        "count": 1,
    },
    {
        "id": "stripe-test",
        "file": "stripe_test.py",
        "content": 'STRIPE_KEY = "sk_test_{v}"\n',
        "gen": lambda: _rand_alnum(24),
        "count": 1,
    },
    {
        "id": "stripe-restricted",
        "file": "stripe_restricted.env",
        "content": 'STRIPE_RK=rk_live_{v}\n',
        "gen": lambda: _rand_alnum(24),
        "count": 1,
    },
    {
        "id": "stripe",
        "file": "stripe_live.py",
        "content": 'stripe.api_key = "sk_live_{v}"\n',
        "gen": lambda: _rand_alnum(24),
        "count": 1,
    },
    {
        "id": "stripe-webhook",
        "file": "stripe_hook.env",
        "content": 'STRIPE_WEBHOOK_SECRET=whsec_{v}\n',
        "gen": lambda: _rand_alnum(32),
        "count": 1,
    },
    {
        "id": "square",
        "file": "square.py",
        "content": 'SQUARE_TOKEN = "sq0atp-{v}"\n',
        "gen": lambda: _rand_alnum(22),
        "count": 1,
    },
    {
        "id": "mongodb",
        "file": "mongo_uri.py",
        "content": 'MONGO_URI = "mongodb+srv://admin:p4ssw0rd@cluster0.abc123.mongodb.net/mydb"\n',
        "gen": lambda: "",
        "count": 1,
    },
    {
        "id": "postgres",
        "file": "pg_uri.env",
        "content": 'DATABASE_URL=postgres://user:secretpass@db.internal.host:5432/prod\n',
        "gen": lambda: "",
        "count": 1,
    },
    {
        "id": "mysql",
        "file": "mysql_uri.py",
        "content": 'DB_URL = "mysql://root:password@localhost:3306/app"\n',
        "gen": lambda: "",
        "count": 1,
    },
    {
        "id": "redis",
        "file": "redis_uri.env",
        "content": 'REDIS_URL=redis://default:secretpass@redis.internal.host:6379/0\n',
        "gen": lambda: "",
        "count": 1,
    },
    {
        "id": "google",
        "file": "google_key.js",
        "content": 'const GOOGLE_KEY = "AIzaSyD-{v}";\n',
        "gen": lambda: _rand_alnum(33),
        "count": 1,
    },
    {
        "id": "google-oauth",
        "file": "google_oauth.py",
        "content": 'ACCESS_TOKEN = "ya29.{v}"\n',
        "gen": lambda: _rand_alnum(60),
        "count": 1,
    },
    {
        "id": "pem-private-key",
        "file": "private.pem",
        "content": '-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH...(truncated)\n-----END RSA PRIVATE KEY-----\n',
        "gen": lambda: "",
        "count": 1,
    },
    {
        "id": "firebase-fcm",
        "file": "firebase_key.json",
        "content": '{{"server_key": "AAAA{a}:{b}"}}\n',
        "gen": lambda: "",
        "count": 1,
        "content_fn": lambda: f'{{"server_key": "AAAA{_rand_alnum(7)}:{_rand_alnum(152)}"}}\n',
    },
    {
        "id": "newrelic",
        "file": "newrelic.env",
        "content": 'NEW_RELIC_API_KEY=NRAK-{v}\n',
        "gen": lambda: _rand_upper_alnum(27),
        "count": 1,
    },
    {
        "id": "newrelic-insight",
        "file": "newrelic_insight.sh",
        "content": 'export NR_INSIGHT="NRIQ-{v}"\n',
        "gen": lambda: _rand_upper_alnum(27),
        "count": 1,
    },
    {
        "id": "sentry",
        "file": "sentry.env",
        "content": 'SENTRY_AUTH_TOKEN=sntrys_{v}\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
    {
        "id": "grafana",
        "file": "grafana.env",
        "content": 'GRAFANA_API_KEY=glc_{v}\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
    {
        "id": "linear",
        "file": "linear.env",
        "content": 'LINEAR_API_KEY=lin_api_{v}\n',
        "gen": lambda: _rand_alnum(40),
        "count": 1,
    },
]

# Multi-secret files
MULTI_SECRET_FILES: list[dict] = [
    {
        "file": "multi_env.env",
        "content": (
            f'OPENAI_API_KEY=sk-proj-{_rand_alnum(40)}\n'
            f'ANTHROPIC_API_KEY=sk-ant-api03-{_rand_alnum(40)}\n'
            f'STRIPE_KEY=sk_live_{_rand_alnum(24)}\n'
            f'DATABASE_URL=postgres://user:pass@localhost:5432/db\n'
        ),
        "expected": [
            {"pattern_id": "openai-proj", "line": 1},
            {"pattern_id": "anthropic", "line": 2},
            {"pattern_id": "stripe", "line": 3},
            {"pattern_id": "postgres", "line": 4},
        ],
    },
    {
        "file": "multi_config.json",
        "content": json.dumps(
            {
                "github_token": f"ghp_{_rand_alnum(36)}",
                "slack_token": f"xoxb-1234567890-1234567890-{_rand_alnum(24)}",
                "sentry_dsn": f"sntrys_{_rand_alnum(40)}",
            },
            indent=2,
        )
        + "\n",
        "expected": [
            {"pattern_id": "github-pat", "line": 2},
            {"pattern_id": "slack", "line": 3},
            {"pattern_id": "sentry", "line": 4},
        ],
    },
]


# ---------------------------------------------------------------------------
# True-negative samples: clean files that should produce zero findings
# ---------------------------------------------------------------------------

TRUE_NEGATIVES: list[dict] = [
    {
        "file": "clean_python.py",
        "content": (
            'import os\n\napi_key = os.environ.get("API_KEY")\n'
            'db_url = os.environ["DATABASE_URL"]\n'
            "print(f'Using key from env: {api_key[:4]}...')\n"
        ),
    },
    {
        "file": "clean_javascript.js",
        "content": (
            'const apiKey = process.env.API_KEY;\n'
            'const dbUrl = process.env.DATABASE_URL;\n'
            'console.log("Connected to database");\n'
        ),
    },
    {
        "file": "clean_config_template.json",
        "content": json.dumps(
            {
                "api_key": "${API_KEY}",
                "database_url": "${DATABASE_URL}",
                "debug": True,
                "port": 8080,
            },
            indent=2,
        )
        + "\n",
    },
    {
        "file": "clean_env_example.env",
        "content": (
            '# Copy this to .env and fill in real values\n'
            'API_KEY=your_api_key_here\n'
            'DATABASE_URL=change_me_in_production\n'
            'SECRET_KEY=change_me_in_production\n'
        ),
    },
    {
        "file": "clean_readme.md",
        "content": (
            '# My Project\n\n'
            'Set your API key: `export API_KEY=your-key-here`\n\n'
            '## Configuration\n\n'
            'Copy `.env.example` to `.env` and fill in your values.\n'
        ),
    },
    {
        "file": "clean_dockerfile.sh",
        "content": (
            '#!/bin/bash\n'
            'docker build -t myapp .\n'
            'docker run -e API_KEY="${API_KEY}" myapp\n'
        ),
    },
    {
        "file": "clean_terraform.sh",
        "content": (
            '#!/bin/bash\nterraform init\nterraform plan\nterraform apply -auto-approve\n'
        ),
    },
    {
        "file": "clean_go.go",
        "content": (
            'package main\n\nimport (\n\t"os"\n\t"fmt"\n)\n\n'
            'func main() {\n\tkey := os.Getenv("API_KEY")\n'
            '\tfmt.Println("Key loaded:", len(key), "chars")\n}\n'
        ),
    },
    {
        "file": "clean_rust.rs",
        "content": (
            'use std::env;\n\nfn main() {\n'
            '    let key = env::var("API_KEY").expect("API_KEY not set");\n'
            '    println!("Key length: {}", key.len());\n}\n'
        ),
    },
    {
        "file": "clean_java.java",
        "content": (
            'public class Config {\n'
            '    private static final String API_KEY = System.getenv("API_KEY");\n'
            '    public static String getApiKey() { return API_KEY; }\n'
            '}\n'
        ),
    },
    {
        "file": "clean_yaml.yml",
        "content": (
            'database:\n  host: localhost\n  port: 5432\n  name: myapp\n'
            '  user: app_user\n  password: ${DB_PASSWORD}\n'
        ),
    },
    {
        "file": "clean_docker_compose.yml",
        "content": (
            'version: "3.8"\nservices:\n  web:\n    build: .\n'
            '    environment:\n      - API_KEY=${API_KEY}\n      - DB_URL=${DB_URL}\n'
        ),
    },
    {
        "file": "clean_gitignore.sh",
        "content": '#!/bin/bash\ngit add .\ngit commit -m "update"\ngit push origin main\n',
    },
    {
        "file": "clean_math.py",
        "content": (
            'import hashlib\n\n'
            'digest = hashlib.sha256(b"hello world").hexdigest()\n'
            'print(f"SHA-256: {digest}")\n'
        ),
    },
    {
        "file": "clean_uuid.py",
        "content": (
            'import uuid\n\n'
            'session_id = str(uuid.uuid4())\n'
            'request_id = "req_" + str(uuid.uuid4()).replace("-", "")\n'
            'print(session_id, request_id)\n'
        ),
    },
    {
        "file": "clean_base64.py",
        "content": (
            'import base64\n\n'
            'encoded = base64.b64encode(b"Hello, World!").decode()\n'
            'decoded = base64.b64decode(encoded)\n'
            'print(encoded, decoded)\n'
        ),
    },
    {
        "file": "clean_regex.py",
        "content": (
            'import re\n\n'
            '# Pattern to match email addresses\n'
            'EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")\n'
            'matches = EMAIL_RE.findall("contact user@example.com or admin@test.org")\n'
        ),
    },
    {
        "file": "clean_crypto.py",
        "content": (
            'from cryptography.fernet import Fernet\n\n'
            'key = Fernet.generate_key()\n'
            'cipher = Fernet(key)\n'
            'encrypted = cipher.encrypt(b"secret message")\n'
        ),
    },
    {
        "file": "clean_placeholder.py",
        "content": (
            '# These are example/placeholder values for documentation\n'
            'EXAMPLE_KEY = "sk-ant-api03-fake_key_for_testing_only"\n'
            'TEST_TOKEN = "ghp_example_placeholder_not_real_token_xyz"\n'
        ),
    },
    {
        "file": "clean_comments.js",
        "content": (
            '// Example: sk-ant-api03-abcdefghijklmnopqrst (placeholder)\n'
            '// Set ANTHROPIC_API_KEY in your .env file\n'
            'const key = process.env.ANTHROPIC_API_KEY;\n'
        ),
    },
    {
        "file": "clean_known_examples.py",
        "content": (
            '# AWS documentation examples (known safe)\n'
            'EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'EXAMPLE_KEY2 = "AKIAI44QH8DHBEXAMPLE"\n'
        ),
    },
    {
        "file": "clean_short_tokens.py",
        "content": (
            '# Short strings that look like prefixes but are too short\n'
            'x = "sk-ant-short"\n'
            'y = "ghp_short"\n'
            'z = "AKIA_short"\n'
        ),
    },
    {
        "file": "clean_html.html",
        "content": (
            '<!DOCTYPE html>\n<html>\n<head><title>App</title></head>\n'
            '<body>\n<form action="/login" method="POST">\n'
            '  <input type="password" name="password" placeholder="Enter password">\n'
            '</form>\n</body>\n</html>\n'
        ),
    },
    {
        "file": "clean_css.css",
        "content": (
            'body { font-family: sans-serif; }\n'
            '.token-display { color: #333; font-weight: bold; }\n'
            '.api-key-input { width: 300px; border: 1px solid #ccc; }\n'
        ),
    },
    {
        "file": "clean_sql.sql",
        "content": (
            'CREATE TABLE users (\n  id SERIAL PRIMARY KEY,\n'
            '  username VARCHAR(255) NOT NULL,\n'
            '  password_hash VARCHAR(255) NOT NULL\n);\n'
            'INSERT INTO users (username, password_hash) VALUES '
            "('admin', '$2b$12$LJ3LmE...');\n"
        ),
    },
]


# ---------------------------------------------------------------------------
# Edge-case samples: near-misses, tricky patterns, ambiguous strings
# ---------------------------------------------------------------------------

EDGE_CASES: list[dict] = [
    {
        "file": "edge_env_ref_with_secret.py",
        "content": (
            '# Has env ref AND a real secret on the same line\n'
            f'API_KEY = os.environ.get("KEY", "sk-ant-api03-{_rand_alnum(40)}")\n'
        ),
        "expected_count": 1,
        "description": "Env ref fallback contains real credential",
    },
    {
        "file": "edge_long_line.py",
        "content": "x = " + '"' + "a" * 4097 + '"\n',
        "expected_count": 0,
        "description": "Line exceeds 4096 char limit, should be skipped",
    },
    {
        "file": "edge_multiline_json.json",
        "content": json.dumps(
            {
                "nested": {
                    "deeply": {
                        "buried": f"ghp_{_rand_alnum(36)}"
                    }
                }
            },
            indent=2,
        )
        + "\n",
        "expected_count": 1,
        "description": "Secret buried in nested JSON",
    },
    {
        "file": "edge_mixed_content.py",
        "content": (
            'import os\n'
            '# This is safe\n'
            'x = os.environ["KEY"]\n'
            '# But this is not\n'
            f'BACKUP_KEY = "ghp_{_rand_alnum(36)}"\n'
            '# Back to safe\n'
            'y = os.environ["OTHER"]\n'
        ),
        "expected_count": 1,
        "description": "Secret sandwiched between safe env references",
    },
    {
        "file": "edge_url_like_redis.py",
        "content": (
            '# Not a credential: just a localhost dev URL with no password\n'
            'REDIS_URL = "redis://localhost:6379/0"\n'
        ),
        "expected_count": 1,
        "description": "Redis URL without password still matches pattern",
    },
    {
        "file": "edge_base64_blob.py",
        "content": (
            '# Long base64 that looks suspicious but is just data\n'
            f'DATA = "{_rand_alnum(100)}"\n'
        ),
        "expected_count": 0,
        "description": "Random alphanumeric that is not a credential",
    },
    {
        "file": "edge_uuid_heavy.py",
        "content": (
            'import uuid\n'
            'SESSION = "550e8400-e29b-41d4-a716-446655440000"\n'
            'REQUEST = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"\n'
            f'TRACE = "{_rand_hex(32)}"\n'
        ),
        "expected_count": 0,
        "description": "UUIDs and hex strings should not match",
    },
    {
        "file": "edge_pem_public_key.pem",
        "content": (
            '-----BEGIN PUBLIC KEY-----\n'
            'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n'
            '-----END PUBLIC KEY-----\n'
        ),
        "expected_count": 0,
        "description": "Public key header should not match private key pattern",
    },
    {
        "file": "edge_two_patterns_one_line.py",
        "content": (
            f'KEYS = "ghp_{_rand_alnum(36)}" + "sk-ant-api03-{_rand_alnum(40)}"\n'
        ),
        "expected_count": 1,
        "description": "Two secrets on one line; scanner takes first match",
    },
    {
        "file": "edge_comment_with_real.py",
        "content": (
            f'# TODO: remove this before push\n'
            f'SECRET = "sk-proj-{_rand_alnum(40)}"  # real key, DO NOT COMMIT\n'
        ),
        "expected_count": 1,
        "description": "Comment says not to commit, but key is real",
    },
]


def generate_true_positives(manifest: dict) -> None:
    for sample in TRUE_POSITIVE_SAMPLES:
        if "content_fn" in sample:
            content = sample["content_fn"]()
        else:
            val = sample["gen"]()
            content = sample["content"].format(v=val)
        path = TP_DIR / sample["file"]
        path.write_text(content, encoding="utf-8")

        lines = content.splitlines()
        expected = []
        for line_num, line in enumerate(lines, start=1):
            from veilguard.patterns import CREDENTIAL_PATTERNS
            for pat in CREDENTIAL_PATTERNS:
                if pat.id == sample["id"] and pat.regex.search(line):
                    expected.append({"pattern_id": pat.id, "line": line_num})
                    break

        manifest[f"true_positives/{sample['file']}"] = {
            "expected_findings": expected or [{"pattern_id": sample["id"], "line": 1}],
            "category": "true_positive",
        }

    for multi in MULTI_SECRET_FILES:
        path = TP_DIR / multi["file"]
        path.write_text(multi["content"], encoding="utf-8")
        manifest[f"true_positives/{multi['file']}"] = {
            "expected_findings": multi["expected"],
            "category": "true_positive",
        }


def generate_true_negatives(manifest: dict) -> None:
    for sample in TRUE_NEGATIVES:
        path = TN_DIR / sample["file"]
        path.write_text(sample["content"], encoding="utf-8")
        manifest[f"true_negatives/{sample['file']}"] = {
            "expected_findings": [],
            "category": "true_negative",
        }


def generate_edge_cases(manifest: dict) -> None:
    for sample in EDGE_CASES:
        path = EDGE_DIR / sample["file"]
        path.write_text(sample["content"], encoding="utf-8")
        manifest[f"edge_cases/{sample['file']}"] = {
            "expected_count": sample["expected_count"],
            "description": sample["description"],
            "category": "edge_case",
        }


def main() -> None:
    for d in (TP_DIR, TN_DIR, EDGE_DIR):
        d.mkdir(parents=True, exist_ok=True)

    manifest: dict = {}
    generate_true_positives(manifest)
    generate_true_negatives(manifest)
    generate_edge_cases(manifest)

    manifest_path = CORPUS_DIR / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    tp_count = sum(1 for v in manifest.values() if v["category"] == "true_positive")
    tn_count = sum(1 for v in manifest.values() if v["category"] == "true_negative")
    ec_count = sum(1 for v in manifest.values() if v["category"] == "edge_case")
    print(f"Generated {tp_count} true-positive, {tn_count} true-negative, {ec_count} edge-case files")
    print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
