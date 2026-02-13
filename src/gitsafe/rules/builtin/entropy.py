"""Entropy-based detection rule (meta rule — delegates to entropy scanner)."""

from gitsafe.rules.models import Rule

HIGH_ENTROPY_STRING = Rule(
    id="HIGH_ENTROPY_STRING",
    name="High-Entropy String",
    description="Detects strings with high Shannon entropy that may be secrets.",
    category="sensitive",
    severity="medium",
    min_entropy=4.0,
    min_length=16,
)

ALL_ENTROPY_RULES = [HIGH_ENTROPY_STRING]
