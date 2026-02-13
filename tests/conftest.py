"""Shared test fixtures — sample diffs, configs, temp git repos."""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def sample_diff_clean() -> str:
    """A diff with no secrets."""
    return textwrap.dedent("""\
        diff --git a/hello.py b/hello.py
        new file mode 100644
        index 0000000..e69de29
        --- /dev/null
        +++ b/hello.py
        @@ -0,0 +1,3 @@
        +def greet(name):
        +    return f"Hello, {name}!"
        +
    """)


@pytest.fixture
def sample_diff_with_aws_key() -> str:
    """A diff containing an AWS access key."""
    return textwrap.dedent("""\
        diff --git a/config.py b/config.py
        new file mode 100644
        index 0000000..abc1234
        --- /dev/null
        +++ b/config.py
        @@ -0,0 +1,4 @@
        +import os
        +
        +AWS_KEY = "AKIAIOSFODNN7REAL123"
        +DB_HOST = "localhost"
    """)


@pytest.fixture
def sample_diff_with_private_key() -> str:
    """A diff containing a private key header."""
    return textwrap.dedent("""\
        diff --git a/key.pem b/key.pem
        new file mode 100644
        index 0000000..def5678
        --- /dev/null
        +++ b/key.pem
        @@ -0,0 +1,3 @@
        +-----BEGIN RSA PRIVATE KEY-----
        +MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF068wME
        +-----END RSA PRIVATE KEY-----
    """)


@pytest.fixture
def sample_diff_with_password() -> str:
    """A diff with a hardcoded password."""
    return textwrap.dedent("""\
        diff --git a/app.py b/app.py
        index 1234567..abcdef0 100644
        --- a/app.py
        +++ b/app.py
        @@ -10,0 +11,1 @@
        +password = "SuperS3cretP@ssw0rd!"
    """)


@pytest.fixture
def sample_diff_with_suppression() -> str:
    """A diff with inline suppression."""
    return textwrap.dedent("""\
        diff --git a/config.py b/config.py
        new file mode 100644
        index 0000000..abc1234
        --- /dev/null
        +++ b/config.py
        @@ -0,0 +1,4 @@
        +import os
        +
        +AWS_KEY = "AKIAIOSFODNN7REAL123"  #gitsafe-ignore
        +DB_HOST = "localhost"
    """)


@pytest.fixture
def sample_diff_binary() -> str:
    """A diff with a binary file."""
    return textwrap.dedent("""\
        diff --git a/image.png b/image.png
        new file mode 100644
        Binary files /dev/null and b/image.png differ
    """)


@pytest.fixture
def sample_diff_rename() -> str:
    """A diff with a renamed file."""
    return textwrap.dedent("""\
        diff --git a/old_name.py b/new_name.py
        similarity index 97%
        rename from old_name.py
        rename to new_name.py
        index abc1234..def5678 100644
        --- a/old_name.py
        +++ b/new_name.py
        @@ -1,0 +2,1 @@
        +# New line added after rename
    """)


@pytest.fixture
def sample_diff_mode_only() -> str:
    """A diff with only file mode change."""
    return textwrap.dedent("""\
        diff --git a/script.sh b/script.sh
        old mode 100644
        new mode 100755
    """)


@pytest.fixture
def sample_diff_submodule() -> str:
    """A diff with submodule pointer change."""
    return textwrap.dedent("""\
        diff --git a/vendor/lib b/vendor/lib
        index abc1234..def5678 160000
        --- a/vendor/lib
        +++ b/vendor/lib
        @@ -1 +1 @@
        -Subproject commit abc1234567890abcdef1234567890abcdef123456
        +Subproject commit def4567890abcdef1234567890abcdef123456ab
    """)


@pytest.fixture
def sample_diff_no_newline() -> str:
    """A diff with 'No newline at end of file' marker."""
    return textwrap.dedent("""\
        diff --git a/data.txt b/data.txt
        new file mode 100644
        index 0000000..abc1234
        --- /dev/null
        +++ b/data.txt
        @@ -0,0 +1 @@
        +final line without newline
        \\ No newline at end of file
    """)


@pytest.fixture
def sample_diff_env_file() -> str:
    """A diff that adds a .env file."""
    return textwrap.dedent("""\
        diff --git a/.env b/.env
        new file mode 100644
        index 0000000..abc1234
        --- /dev/null
        +++ b/.env
        @@ -0,0 +1,2 @@
        +DATABASE_URL=postgres://user:pass@localhost/db
        +SECRET_KEY=mysecretkey123
    """)


@pytest.fixture
def sample_diff_jwt() -> str:
    """A diff containing a JWT."""
    return textwrap.dedent("""\
        diff --git a/auth.py b/auth.py
        new file mode 100644
        index 0000000..abc1234
        --- /dev/null
        +++ b/auth.py
        @@ -0,0 +1,2 @@
        +# Test token
        +TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    """)


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository for integration tests."""
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    # Initial commit
    readme = tmp_path / "README.md"
    readme.write_text("# Test\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    return tmp_path
