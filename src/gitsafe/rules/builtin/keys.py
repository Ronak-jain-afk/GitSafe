"""Private key and certificate detection rules."""

from gitsafe.rules.models import Rule

PRIVATE_KEY = Rule(
    id="PRIVATE_KEY",
    name="Private Key",
    description="Detects PEM-encoded private keys (RSA, EC, DSA, OpenSSH).",
    category="key",
    severity="critical",
    pattern=r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
)

PGP_PRIVATE_KEY = Rule(
    id="PGP_PRIVATE_KEY",
    name="PGP Private Key Block",
    description="Detects PGP private key blocks.",
    category="key",
    severity="critical",
    pattern=r"(?P<secret>-----BEGIN PGP PRIVATE KEY BLOCK-----)",  # gitsafe-ignore[PGP_PRIVATE_KEY]
)

PKCS12_FILE = Rule(
    id="PKCS12_FILE",
    name="PKCS#12 / PFX File",
    description="Detects PKCS#12 certificate bundles staged by filename.",
    category="key",
    severity="high",
    file_patterns=["*.p12", "*.pfx"],
)

ALL_KEY_RULES = [PRIVATE_KEY, PGP_PRIVATE_KEY, PKCS12_FILE]
