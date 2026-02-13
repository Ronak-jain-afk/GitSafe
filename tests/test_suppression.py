"""Tests for the suppression system."""

from pathlib import Path

from gitsafe.scanner.suppression import (
    GitSafeIgnore,
    SuppressionChecker,
    parse_inline_suppression,
)


class TestInlineParsing:
    def test_gitsafe_ignore(self):
        ok, ids = parse_inline_suppression('key = "secret"  #gitsafe-ignore')
        assert ok is True
        assert ids is None  # suppress all

    def test_nosec(self):
        ok, ids = parse_inline_suppression('key = "secret"  #nosec')
        assert ok is True
        assert ids is None

    def test_rule_scoped(self):
        ok, ids = parse_inline_suppression('key = "x"  #gitsafe-ignore[AWS_ACCESS_KEY, PRIVATE_KEY]')
        assert ok is True
        assert ids == frozenset({"AWS_ACCESS_KEY", "PRIVATE_KEY"})

    def test_no_suppression(self):
        ok, ids = parse_inline_suppression('key = "normal"')
        assert ok is False
        assert ids is None

    def test_with_spaces(self):
        ok, ids = parse_inline_suppression('x = 1  # gitsafe-ignore')
        assert ok is True


class TestSuppressionChecker:
    def test_same_line_suppression(self):
        checker = SuppressionChecker()
        checker.register_lines("test.py", [
            (1, 'import os'),
            (2, 'key = "AKIAIOSFODNN7REAL123"  #gitsafe-ignore'),
            (3, 'x = 1'),
        ])
        sup = checker.is_suppressed("test.py", 2, "AWS_ACCESS_KEY")
        assert sup is not None
        assert sup.reason == "inline"

    def test_next_line_suppression(self):
        checker = SuppressionChecker()
        checker.register_lines("test.py", [
            (10, '# gitsafe-ignore'),
            (11, 'key = "AKIAIOSFODNN7REAL123"'),
            (12, 'x = 1'),
        ])
        # Line 11 should be suppressed (previous line is a standalone comment)
        sup = checker.is_suppressed("test.py", 11, "AWS_ACCESS_KEY")
        assert sup is not None

        # Line 12 should NOT be suppressed
        sup = checker.is_suppressed("test.py", 12, "AWS_ACCESS_KEY")
        assert sup is None

    def test_rule_scoped_suppression(self):
        checker = SuppressionChecker()
        checker.register_lines("test.py", [
            (1, 'key = "x"  #gitsafe-ignore[AWS_ACCESS_KEY]'),
        ])
        # AWS_ACCESS_KEY is suppressed
        assert checker.is_suppressed("test.py", 1, "AWS_ACCESS_KEY") is not None
        # PRIVATE_KEY is NOT suppressed
        assert checker.is_suppressed("test.py", 1, "PRIVATE_KEY") is None

    def test_no_suppression(self):
        checker = SuppressionChecker()
        checker.register_lines("test.py", [
            (1, 'key = "AKIAIOSFODNN7REAL123"'),
        ])
        assert checker.is_suppressed("test.py", 1, "AWS_ACCESS_KEY") is None


class TestGitSafeIgnore:
    def test_global_pattern(self, tmp_path: Path):
        ignore_file = tmp_path / ".gitsafeignore"
        ignore_file.write_text("tests/*\ndocs/*\n")
        gi = GitSafeIgnore.from_file(ignore_file)
        assert gi.is_ignored("tests/test_foo.py") is True
        assert gi.is_ignored("src/main.py") is False

    def test_rule_scoped_pattern(self, tmp_path: Path):
        ignore_file = tmp_path / ".gitsafeignore"
        ignore_file.write_text("rule:HIGH_ENTROPY_STRING tests/*\n")
        gi = GitSafeIgnore.from_file(ignore_file)
        # Only ignored for HIGH_ENTROPY_STRING
        assert gi.is_ignored("tests/test.py", "HIGH_ENTROPY_STRING") is True
        assert gi.is_ignored("tests/test.py", "AWS_ACCESS_KEY") is False
        assert gi.is_ignored("tests/test.py") is False

    def test_comments_ignored(self, tmp_path: Path):
        ignore_file = tmp_path / ".gitsafeignore"
        ignore_file.write_text("# This is a comment\ntests/*\n")
        gi = GitSafeIgnore.from_file(ignore_file)
        assert gi.is_ignored("tests/test.py") is True

    def test_missing_file(self, tmp_path: Path):
        gi = GitSafeIgnore.from_file(tmp_path / ".gitsafeignore")
        assert gi.is_ignored("anything.py") is False
