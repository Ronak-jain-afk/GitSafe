"""File-level detection rules — .env, PEM, credentials files, etc."""

from gitsafe.rules.models import Rule

ENV_FILE = Rule(
    id="ENV_FILE",
    name=".env File",
    description="Detects .env files containing environment variable secrets.",
    category="config",
    severity="high",
    file_patterns=[".env", ".env.*", "*.env"],
    allowlist_patterns=[r"\.env\.example$", r"\.env\.template$", r"\.env\.sample$"],
)

PEM_FILE = Rule(
    id="PEM_FILE",
    name="PEM Key File",
    description="Detects PEM-encoded key/certificate files.",
    category="key",
    severity="critical",
    file_patterns=["*.pem", "*.key"],
)

SSH_KEY_FILE = Rule(
    id="SSH_KEY_FILE",
    name="SSH Private Key File",
    description="Detects SSH private key files (id_rsa, id_ed25519, etc.).",
    category="key",
    severity="critical",
    file_patterns=["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"],
)

CREDENTIALS_FILE = Rule(
    id="CREDENTIALS_FILE",
    name="Credentials File",
    description="Detects common credential files (credentials.json, .htpasswd, etc.).",
    category="config",
    severity="high",
    file_patterns=[
        "credentials.json",
        "service-account*.json",
        ".htpasswd",
        ".netrc",
        ".npmrc",
        ".pypirc",
    ],
)

KEYSTORE_FILE = Rule(
    id="KEYSTORE_FILE",
    name="Keystore File",
    description="Detects Java/Android keystore files.",
    category="key",
    severity="high",
    file_patterns=["*.keystore", "*.jks"],
)

ALL_ENV_RULES = [ENV_FILE, PEM_FILE, SSH_KEY_FILE, CREDENTIALS_FILE, KEYSTORE_FILE]
