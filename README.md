# GitSafe

A CLI tool that scans staged Git changes before commit and blocks sensitive data, secrets, and insecure patterns from entering a repository.

## Features

- **Pre-commit hook** — catches secrets before they're committed
- **CI mode** — scans PR/push diffs in pipelines (GitHub Actions, GitLab CI, etc.)
- **25+ built-in rules** — AWS keys, JWTs, private keys, passwords, .env files, and more
- **Entropy detection** — finds high-entropy strings that may be secrets
- **Inline suppression** — `#gitsafe-ignore` with optional rule scoping
- **Custom rules** — define your own via YAML files
- **Multiple output formats** — Rich terminal, JSON, SARIF
- **Fast** — sub-100ms for typical commits

## Installation

```bash
pip install gitsafe
```

## Quick Start

```bash
# Install as a pre-commit hook (primary method)
gitsafe install

# Or scan manually
gitsafe scan

# Generate a starter config file
gitsafe init
```

## Usage

### Scan staged changes

```bash
gitsafe scan
```

### Scan with options

```bash
gitsafe scan --format json --fail-on critical --output report.json
```

### CI mode

```bash
# Auto-detected when CI=true is set
gitsafe scan --ci --from $BASE_SHA --to $HEAD_SHA --format sarif
```

### Dry run

```bash
gitsafe scan --dry-run
```

### Audit suppression comments

```bash
gitsafe audit
```

## Configuration

Create a `.gitsafe.toml` in your repo root:

```bash
gitsafe init
```

Example config:

```toml
version = "1.0"

[scan]
fail_on = "high"          # fail at or above this severity
max_file_size_kb = 512

[entropy]
enabled = true
min_entropy = 4.0
min_length = 16

[rules]
# disable = ["HIGH_ENTROPY_STRING"]

[allowlist]
# patterns = ["example", "localhost", "dummy_key"]

[ignore]
# files = ["tests/*", "docs/*"]
```

## CI Environment Variables

| Variable | Effect |
|---|---|
| `CI_GITSAFE_FAIL_ON` | Override fail severity threshold |
| `CI_GITSAFE_FORMAT` | Override output format |
| `CI_GITSAFE_DISABLE_RULES` | Comma-separated rule IDs to disable |
| `CI_GITSAFE_IGNORE_PATHS` | Additional ignore paths |
| `CI_GITSAFE_EXIT_ZERO` | Set to `1` for audit-only mode |
| `CI_GITSAFE_MAX_FINDINGS` | Circuit-breaker: fail at N findings |

## Inline Suppression

```python
# Suppress all rules on this line
password = "test123"  #gitsafe-ignore

# Suppress specific rules
key = "AKIA..."  #gitsafe-ignore[AWS_ACCESS_KEY]

# Suppress next line (standalone comment)
#gitsafe-ignore
secret_value = "..."
```

## `.gitsafeignore`

```gitignore
# Ignore test fixtures
tests/fixtures/*

# Rule-scoped ignore
rule:HIGH_ENTROPY_STRING tests/*
```

## Custom Rules

Add YAML files to `.gitsafe-rules/`:

```yaml
- id: INTERNAL_API_KEY
  name: Internal API Key
  pattern: "internal-api-[a-zA-Z0-9]{32}"
  severity: critical
  category: secret
  allowlist_patterns: ["example", "test"]
```

## Pipeline Integration

### GitHub Actions

```yaml
name: Secret Scan
on: [pull_request, push]
jobs:
  gitsafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: pip install gitsafe
      - name: Scan
        run: |
          gitsafe scan --ci \
            --from ${{ github.event.pull_request.base.sha }} \
            --to ${{ github.event.pull_request.head.sha }} \
            --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: results.sarif }
```

### GitLab CI

```yaml
secret-scan:
  stage: test
  script:
    - pip install gitsafe
    - gitsafe scan --ci --format json --output gl-secret-report.json
      --from $CI_MERGE_REQUEST_DIFF_BASE_SHA --to $CI_COMMIT_SHA
  artifacts:
    reports:
      secret_detection: gl-secret-report.json
```

### pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitsafe/gitsafe
    rev: v1.0.0
    hooks:
      - id: gitsafe
```

## Exit Codes

| Code | Meaning |
|---|---|
| **0** | Clean — no actionable findings |
| **1** | Findings at or above `fail_on` severity |
| **2** | Config error, git unavailable, or internal error |

## Built-in Rules

| Rule ID | Category | Severity | Description |
|---|---|---|---|
| `AWS_ACCESS_KEY` | key | critical | AWS access key IDs (AKIA...) |
| `AWS_SECRET_KEY` | secret | critical | AWS secret access keys |
| `AWS_SESSION_TOKEN` | secret | high | AWS session tokens |
| `GITHUB_TOKEN` | secret | critical | GitHub PATs (ghp_, gho_, etc.) |
| `GITLAB_TOKEN` | secret | critical | GitLab PATs (glpat-) |
| `GENERIC_JWT` | secret | high | JSON Web Tokens |
| `SLACK_TOKEN` | secret | critical | Slack bot/user tokens |
| `SLACK_WEBHOOK` | secret | high | Slack webhook URLs |
| `STRIPE_SECRET_KEY` | secret | critical | Stripe secret keys (sk_live_) |
| `STRIPE_PUBLISHABLE_KEY` | key | low | Stripe publishable keys |
| `GENERIC_API_KEY` | secret | medium | Generic api_key assignments |
| `GENERIC_TOKEN` | secret | medium | Generic token assignments |
| `PRIVATE_KEY` | key | critical | PEM private keys |
| `PGP_PRIVATE_KEY` | key | critical | PGP private key blocks |
| `HARDCODED_PASSWORD` | credential | high | Password assignments |
| `CONNECTION_STRING` | credential | high | DB connection strings |
| `BASIC_AUTH_URL` | credential | high | URLs with embedded credentials |
| `ENV_FILE` | config | high | .env files |
| `PEM_FILE` | key | critical | PEM key files |
| `SSH_KEY_FILE` | key | critical | SSH private key files |
| `CREDENTIALS_FILE` | config | high | Credential files |
| `KEYSTORE_FILE` | key | high | Java/Android keystores |
| `HIGH_ENTROPY_STRING` | sensitive | medium | High-entropy strings |

## License

MIT
