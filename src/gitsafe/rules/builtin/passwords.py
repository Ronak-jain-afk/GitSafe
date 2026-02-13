"""Password and connection string detection rules."""

from gitsafe.rules.models import Rule

HARDCODED_PASSWORD = Rule(
    id="HARDCODED_PASSWORD",
    name="Hardcoded Password",
    description="Detects password assignments in code (password = '...').",
    category="credential",
    severity="high",
    pattern=r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['\"](?P<secret>[^'\"]{8,})['\"]",
    allowlist_patterns=[
        r"example",
        r"test",
        r"dummy",
        r"placeholder",
        r"changeme",
        r"password",
        r"\*{3,}",
        r"x{4,}",
        r"your[-_]?pass",
    ],
)

CONNECTION_STRING = Rule(
    id="CONNECTION_STRING",
    name="Database Connection String",
    description="Detects connection strings with embedded credentials.",
    category="credential",
    severity="high",
    pattern=(
        r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)"
        r"://[^:]+:(?P<secret>[^@\s]{8,})@[^\s]+"
    ),
    allowlist_patterns=[r"localhost", r"127\.0\.0\.1", r"example\.com", r"test"],
)

BASIC_AUTH_URL = Rule(
    id="BASIC_AUTH_URL",
    name="Basic Auth in URL",
    description="Detects URLs with embedded username:password.",
    category="credential",
    severity="high",
    pattern=r"https?://[^:]+:(?P<secret>[^@\s]{8,})@[^\s]+",
    allowlist_patterns=[r"localhost", r"127\.0\.0\.1", r"example\.com", r"test"],
)

ALL_PASSWORD_RULES = [HARDCODED_PASSWORD, CONNECTION_STRING, BASIC_AUTH_URL]
