"""AWS-related detection rules."""

from gitsafe.rules.models import Rule

AWS_ACCESS_KEY = Rule(
    id="AWS_ACCESS_KEY",
    name="AWS Access Key ID",
    description="Detects AWS access key IDs (starts with AKIA).",
    category="key",
    severity="critical",
    pattern=r"(?:^|[^A-Za-z0-9])(?P<secret>AKIA[0-9A-Z]{16})(?:$|[^A-Za-z0-9])",
    allowlist_patterns=[r"AKIAIOSFODNN7EXAMPLE", r"example", r"test"],
)

AWS_SECRET_KEY = Rule(
    id="AWS_SECRET_KEY",
    name="AWS Secret Access Key",
    description="Detects AWS secret access keys assigned in code.",
    category="secret",
    severity="critical",
    pattern=r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?",
    allowlist_patterns=[r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", r"example", r"test"],
)

AWS_SESSION_TOKEN = Rule(
    id="AWS_SESSION_TOKEN",
    name="AWS Session Token",
    description="Detects AWS session tokens.",
    category="secret",
    severity="high",
    pattern=r"(?i)(?:aws_session_token)\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{100,})['\"]?",
)

ALL_AWS_RULES = [AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_SESSION_TOKEN]
