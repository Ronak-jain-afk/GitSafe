"""Default configuration values and starter .gitsafe.toml template."""

DEFAULT_TOML = """\
# GitSafe Configuration
# See https://github.com/gitsafe/gitsafe for documentation
version = "1.0"

[scan]
fail_on = "high"          # low | medium | high | critical — fail at or above this level
scan_unstaged = false
max_file_size_kb = 512
# early_exit = false      # stop rule loop on first critical per line (performance mode)

[output]
format = "terminal"       # terminal | json | sarif
show_summary = true
show_severity = true

[rules]
# enable = ["AWS_ACCESS_KEY", "PRIVATE_KEY"]   # empty = all enabled
# disable = ["HIGH_ENTROPY_STRING"]

[entropy]
enabled = true
min_entropy = 4.0
min_length = 16

[ignore]
# files = ["tests/*", "docs/*"]
# rules = ["HARDCODED_PASSWORD"]
# paths = ["config/example.env"]

[allowlist]
# patterns = ["example", "localhost", "dummy_key", "test"]

[ci]
# annotation_format = "github"   # github | gitlab | bitbucket | none
# full_redaction = true
# max_findings = 50              # circuit-breaker
"""

FULL_TOML = DEFAULT_TOML  # v1: same content; extended in future
