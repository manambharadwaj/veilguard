"""
Credential patterns, file globs, and scan configuration.
Ordering: more specific prefixes before catch-alls (first match wins per line).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialPattern:
    """A compiled regex pattern that identifies a specific credential type.

    Attributes:
        id: Short unique identifier (e.g. ``"anthropic"``, ``"aws-access"``).
        name: Human-readable label (e.g. ``"Anthropic API Key"``).
        regex: Compiled regular expression that matches the credential.
        env_prefix: Conventional environment variable name for this credential.
        category: Grouping label (``"ai-ml"``, ``"cloud"``, ``"payment"``, etc.).
    """

    id: str
    name: str
    regex: re.Pattern[str]
    env_prefix: str
    category: str | None = None


def _p(
    pid: str,
    name: str,
    src: str,
    env_prefix: str,
    category: str,
    flags: int = 0,
) -> CredentialPattern:
    return CredentialPattern(
        id=pid,
        name=name,
        regex=re.compile(src, flags),
        env_prefix=env_prefix,
        category=category,
    )


CREDENTIAL_PATTERNS: list[CredentialPattern] = [
    _p("anthropic", "Anthropic API Key", r"sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}", "ANTHROPIC_API_KEY", "ai-ml"),
    _p("openai-proj", "OpenAI Project Key", r"sk-proj-[a-zA-Z0-9]{20,}", "OPENAI_API_KEY", "ai-ml"),
    _p("openrouter", "OpenRouter API Key", r"sk-or-v1-[a-zA-Z0-9]{48,}", "OPENROUTER_API_KEY", "ai-ml"),
    _p("openai-legacy", "OpenAI Legacy Key", r"sk-[a-zA-Z0-9]{48,}", "OPENAI_API_KEY", "ai-ml"),
    _p("groq", "Groq API Key", r"gsk_[a-zA-Z0-9]{20,}", "GROQ_API_KEY", "ai-ml"),
    _p("replicate", "Replicate API Token", r"r8_[a-zA-Z0-9]{20,}", "REPLICATE_API_TOKEN", "ai-ml"),
    _p("huggingface", "Hugging Face Token", r"hf_[a-zA-Z0-9]{20,}", "HUGGING_FACE_HUB_TOKEN", "ai-ml"),
    _p("perplexity", "Perplexity API Key", r"pplx-[a-zA-Z0-9]{48,}", "PERPLEXITY_API_KEY", "ai-ml"),
    _p("fireworks", "Fireworks AI Key", r"fw_[a-zA-Z0-9]{20,}", "FIREWORKS_API_KEY", "ai-ml"),
    _p("aws-access", "AWS Access Key", r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY_ID", "cloud"),
    _p("aws-sts", "AWS STS Temporary Key", r"ASIA[0-9A-Z]{16}", "AWS_ACCESS_KEY_ID", "cloud"),
    _p(
        "gcp-service-account",
        "GCP Service Account JSON",
        r'"type"\s*:\s*"service_account"',
        "GOOGLE_APPLICATION_CREDENTIALS",
        "cloud",
    ),
    _p("digitalocean", "DigitalOcean PAT", r"dop_v1_[a-f0-9]{64}", "DIGITALOCEAN_TOKEN", "cloud"),
    _p("heroku", "Heroku API Key", r"HRKU-[a-zA-Z0-9_-]{30,}", "HEROKU_API_KEY", "cloud"),
    _p("fly-io", "Fly.io Token", r"fo1_[a-zA-Z0-9_-]{20,}", "FLY_API_TOKEN", "cloud"),
    _p("netlify", "Netlify PAT", r"nfp_[a-zA-Z0-9]{40,}", "NETLIFY_AUTH_TOKEN", "cloud"),
    _p(
        "azure",
        "Azure Key",
        r"(?:AccountKey|SharedAccessKey|azure[_-]?(?:storage|key|account))\s*[=:]\s*[a-zA-Z0-9+/]{43}=",
        "AZURE_API_KEY",
        "cloud",
        re.IGNORECASE,
    ),
    _p(
        "supabase",
        "Supabase Service Key",
        r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{50,}",
        "SUPABASE_SERVICE_ROLE_KEY",
        "cloud",
    ),
    _p(
        "slack",
        "Slack Token",
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "SLACK_TOKEN",
        "communication",
    ),
    _p(
        "slack-webhook",
        "Slack Webhook URL",
        r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}",
        "SLACK_WEBHOOK_URL",
        "communication",
    ),
    _p(
        "slack-app",
        "Slack App Token",
        r"xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+",
        "SLACK_APP_TOKEN",
        "communication",
    ),
    _p(
        "telegram-bot",
        "Telegram Bot Token",
        r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        "TELEGRAM_BOT_TOKEN",
        "communication",
    ),
    _p(
        "discord-bot",
        "Discord Bot Token",
        r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",
        "DISCORD_BOT_TOKEN",
        "communication",
    ),
    _p(
        "discord-webhook",
        "Discord Webhook URL",
        r"discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "DISCORD_WEBHOOK_URL",
        "communication",
    ),
    _p("twilio", "Twilio API Key", r"SK[0-9a-fA-F]{32}", "TWILIO_API_KEY", "communication"),
    _p(
        "sendgrid",
        "SendGrid Key",
        r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "SENDGRID_API_KEY",
        "communication",
    ),
    _p("github-pat", "GitHub Token", r"ghp_[a-zA-Z0-9]{36}", "GITHUB_TOKEN", "developer"),
    _p(
        "github-fine",
        "GitHub Fine-Grained PAT",
        r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "GITHUB_TOKEN",
        "developer",
    ),
    _p("github-oauth", "GitHub OAuth Token", r"gho_[a-zA-Z0-9]{36}", "GITHUB_TOKEN", "developer"),
    _p("github-app", "GitHub App Installation Token", r"ghs_[a-zA-Z0-9]{36}", "GITHUB_TOKEN", "developer"),
    _p("github-refresh", "GitHub Refresh Token", r"ghr_[a-zA-Z0-9]{36,}", "GITHUB_TOKEN", "developer"),
    _p("gitlab", "GitLab PAT", r"glpat-[a-zA-Z0-9_-]{20,}", "GITLAB_TOKEN", "developer"),
    _p(
        "gitlab-pipeline",
        "GitLab Pipeline Trigger",
        r"glptt-[a-f0-9]{40,}",
        "GITLAB_TOKEN",
        "developer",
    ),
    _p(
        "gitlab-runner",
        "GitLab Runner Token",
        r"GR1348941[a-zA-Z0-9_-]{20,}",
        "GITLAB_TOKEN",
        "developer",
    ),
    _p("npm", "npm Access Token", r"npm_[a-zA-Z0-9]{36}", "NPM_TOKEN", "developer"),
    _p("pypi", "PyPI API Token", r"pypi-[A-Za-z0-9_-]{50,}", "PYPI_API_TOKEN", "developer"),
    _p("dockerhub", "Docker Hub PAT", r"dckr_pat_[a-zA-Z0-9_-]{20,}", "DOCKER_TOKEN", "developer"),
    _p("bitbucket", "Bitbucket App Password", r"ATBB[a-zA-Z0-9]{32,}", "BITBUCKET_TOKEN", "developer"),
    _p("stripe-test", "Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24,}", "STRIPE_SECRET_KEY", "payment"),
    _p(
        "stripe-restricted",
        "Stripe Restricted Key",
        r"rk_live_[0-9a-zA-Z]{24,}",
        "STRIPE_RESTRICTED_KEY",
        "payment",
    ),
    _p("stripe", "Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24,}", "STRIPE_SECRET_KEY", "payment"),
    _p(
        "stripe-webhook",
        "Stripe Webhook Secret",
        r"whsec_[a-zA-Z0-9]{32,}",
        "STRIPE_WEBHOOK_SECRET",
        "payment",
    ),
    _p(
        "square",
        "Square API Key",
        r"sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}",
        "SQUARE_ACCESS_TOKEN",
        "payment",
    ),
    _p("mongodb", "MongoDB Connection String", r"mongodb\+srv://[^\s]{10,}", "MONGODB_URI", "database"),
    _p("postgres", "PostgreSQL Connection String", r"postgres(?:ql)?://[^\s]{10,}", "DATABASE_URL", "database"),
    _p("mysql", "MySQL Connection String", r"mysql://[^\s]{10,}", "DATABASE_URL", "database"),
    _p("redis", "Redis Connection String", r"rediss?://[^\s]{10,}", "REDIS_URL", "database"),
    _p("google", "Google API Key", r"AIza[0-9A-Za-z_-]{35}", "GOOGLE_API_KEY", "auth"),
    _p(
        "google-oauth",
        "Google OAuth Access Token",
        r"ya29\.[a-zA-Z0-9_-]{50,}",
        "GOOGLE_ACCESS_TOKEN",
        "auth",
    ),
    _p(
        "pem-private-key",
        "PEM Private Key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "PRIVATE_KEY",
        "auth",
    ),
    _p(
        "firebase-fcm",
        "Firebase FCM Server Key",
        r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140,}",
        "FIREBASE_SERVER_KEY",
        "auth",
    ),
    _p("newrelic", "New Relic API Key", r"NRAK-[A-Z0-9]{27}", "NEW_RELIC_API_KEY", "monitoring"),
    _p(
        "newrelic-insight",
        "New Relic Insights Key",
        r"NRIQ-[A-Z0-9]{27,}",
        "NEW_RELIC_API_KEY",
        "monitoring",
    ),
    _p("sentry", "Sentry Auth Token", r"sntrys_[a-zA-Z0-9]{40,}", "SENTRY_AUTH_TOKEN", "monitoring"),
    _p(
        "grafana",
        "Grafana Cloud API Key",
        r"glc_[a-zA-Z0-9_+/]{32,}=*",
        "GRAFANA_API_KEY",
        "monitoring",
    ),
    _p("linear", "Linear API Key", r"lin_api_[a-zA-Z0-9]{40,}", "LINEAR_API_KEY", "monitoring"),
]


def _build_prefix_quick_check(patterns: list[CredentialPattern]) -> re.Pattern[str]:
    parts: list[str] = []
    for p in patterns:
        src = p.regex.pattern
        m = re.match(r"^([a-zA-Z0-9_\-.+:/]{3,})", src)
        if not m:
            continue
        lit = re.escape(m.group(1))
        if lit not in parts:
            parts.append(lit)
    if not parts:
        return re.compile("$^")
    return re.compile("|".join(parts))


CREDENTIAL_PREFIX_QUICK_CHECK: re.Pattern[str] = _build_prefix_quick_check(CREDENTIAL_PATTERNS)

KNOWN_EXAMPLE_KEYS: frozenset[str] = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
        "sk-proj-abc123",
    }
)

PLACEHOLDER_INDICATORS: tuple[str, ...] = (
    "example",
    "placeholder",
    "your_",
    "your-",
    "insert_",
    "insert-",
    "xxx",
    "XXXX",
    "test_key",
    "test_secret",
    "fake_",
    "fake-",
    "dummy",
    "sample",
    "replace_me",
    "change_me",
    "todo",
    "<your",
    "not-a-real",
    "not_a_real",
    "just-for-testing",
    "supabase-demo",
)

SECRET_FILE_PATTERNS: list[str] = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.crt",
    ".aws/credentials",
    ".ssh/*",
    ".docker/config.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "*.tfstate",
    "*.tfvars",
    "secrets/",
    "credentials/",
    ".veilguard/",
]

CONFIG_FILES: list[str] = [
    "config.json",
    "config.yaml",
    "config.yml",
    ".env",
    ".env.local",
    "package.json",
    "mcp.json",
    "CLAUDE.md",
    ".openclaw/config.json",
    ".moltbot/config.json",
    "openclaw.json",
    "moltbot.json",
    ".curse/mcp.json",
    ".vscode/mcp.json",
    ".claude/settings.json",
    ".cursor/settings.json",
    ".github/copilot-instructions.md",
    ".nanobot/config.json",
    "nanobot.yaml",
    "nanobot.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.override.yml",
    "terraform.tfvars",
    "terraform.tfvars.json",
    ".codeium/config.json",
    ".tabnine/config.json",
    "kubeconfig.yaml",
    ".kube/config",
]

SOURCE_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".py",
        ".go",
        ".java",
        ".rb",
        ".rs",
        ".cs",
        ".php",
        ".swift",
        ".kt",
        ".kts",
        ".scala",
        ".sh",
        ".bash",
        ".zsh",
    }
)

SOURCE_SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        ".svn",
        ".hg",
        "vendor",
        "dist",
        "build",
        "out",
        ".next",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
        "bin",
        "obj",
        ".gradle",
        ".maven",
        "coverage",
        ".nyc_output",
    }
)
