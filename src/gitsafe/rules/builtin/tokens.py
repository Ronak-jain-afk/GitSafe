"""Token detection rules — GitHub, GitLab, Slack, Stripe, generic JWT, etc."""

from gitsafe.rules.models import Rule

GITHUB_TOKEN = Rule(
    id="GITHUB_TOKEN",
    name="GitHub Personal Access Token",
    description="Detects GitHub PATs (ghp_, gho_, ghu_, ghs_, ghr_ prefixed).",
    category="secret",
    severity="critical",
    pattern=r"(?P<secret>gh[pousr]_[A-Za-z0-9_]{36,255})",
    allowlist_patterns=[r"example", r"test", r"ghp_xxxx"],
)

GITLAB_TOKEN = Rule(
    id="GITLAB_TOKEN",
    name="GitLab Personal Access Token",
    description="Detects GitLab PATs (glpat- prefix).",
    category="secret",
    severity="critical",
    pattern=r"(?P<secret>glpat-[A-Za-z0-9\-_]{20,})",
    allowlist_patterns=[r"example", r"test"],
)

GENERIC_JWT = Rule(
    id="GENERIC_JWT",
    name="JSON Web Token",
    description="Detects JWTs (eyJ... three-part base64url tokens).",
    category="secret",
    severity="high",
    pattern=r"(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)",
    allowlist_patterns=[r"example", r"test"],
)

SLACK_TOKEN = Rule(
    id="SLACK_TOKEN",
    name="Slack Token",
    description="Detects Slack bot/user/workspace tokens.",
    category="secret",
    severity="critical",
    pattern=r"(?P<secret>xox[bporsca]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)",
    allowlist_patterns=[r"example", r"test"],
)

SLACK_WEBHOOK = Rule(
    id="SLACK_WEBHOOK",
    name="Slack Webhook URL",
    description="Detects Slack incoming webhook URLs.",
    category="secret",
    severity="high",
    pattern=r"(?P<secret>https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)",
)

STRIPE_SECRET_KEY = Rule(
    id="STRIPE_SECRET_KEY",
    name="Stripe Secret Key",
    description="Detects Stripe secret API keys (sk_live_ prefix).",
    category="secret",
    severity="critical",
    pattern=r"(?P<secret>sk_live_[A-Za-z0-9]{24,})",
    allowlist_patterns=[r"example", r"test"],
)

STRIPE_PUBLISHABLE_KEY = Rule(
    id="STRIPE_PUBLISHABLE_KEY",
    name="Stripe Publishable Key",
    description="Detects Stripe publishable keys. Lower severity since they are semi-public.",
    category="key",
    severity="low",
    pattern=r"(?P<secret>pk_live_[A-Za-z0-9]{24,})",
)

GENERIC_API_KEY = Rule(
    id="GENERIC_API_KEY",
    name="Generic API Key Assignment",
    description="Detects generic API key assignments in code.",
    category="secret",
    severity="medium",
    pattern=r"(?i)(?:api_key|apikey|api_secret|api_token)\s*[:=]\s*['\"](?P<secret>[A-Za-z0-9_\-]{16,})['\"]",
    allowlist_patterns=[r"example", r"test", r"dummy", r"placeholder", r"your[-_]?api"],
)

GENERIC_TOKEN = Rule(
    id="GENERIC_TOKEN",
    name="Generic Token Assignment",
    description="Detects generic token assignments (token = '...').",
    category="secret",
    severity="medium",
    pattern=r"(?i)(?:token|access_token|auth_token|secret_token)\s*[:=]\s*['\"](?P<secret>[A-Za-z0-9_\-]{16,})['\"]",
    allowlist_patterns=[r"example", r"test", r"dummy", r"placeholder", r"your[-_]?token"],
)

ALL_TOKEN_RULES = [
    GITHUB_TOKEN,
    GITLAB_TOKEN,
    GENERIC_JWT,
    SLACK_TOKEN,
    SLACK_WEBHOOK,
    STRIPE_SECRET_KEY,
    STRIPE_PUBLISHABLE_KEY,
    GENERIC_API_KEY,
    GENERIC_TOKEN,
]
