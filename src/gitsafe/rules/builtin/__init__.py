"""Built-in rules — aggregate all categories."""

from gitsafe.rules.builtin.aws import ALL_AWS_RULES
from gitsafe.rules.builtin.entropy import ALL_ENTROPY_RULES
from gitsafe.rules.builtin.env_files import ALL_ENV_RULES
from gitsafe.rules.builtin.keys import ALL_KEY_RULES
from gitsafe.rules.builtin.passwords import ALL_PASSWORD_RULES
from gitsafe.rules.builtin.tokens import ALL_TOKEN_RULES
from gitsafe.rules.models import Rule

ALL_BUILTIN_RULES: list[Rule] = [
    *ALL_AWS_RULES,
    *ALL_TOKEN_RULES,
    *ALL_KEY_RULES,
    *ALL_PASSWORD_RULES,
    *ALL_ENV_RULES,
    *ALL_ENTROPY_RULES,
]

__all__ = ["ALL_BUILTIN_RULES"]
