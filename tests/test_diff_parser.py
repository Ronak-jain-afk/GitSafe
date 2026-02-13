"""Tests for the unified diff parser — covers all spec edge cases."""

from gitsafe.git.diff_parser import DiffParser
from gitsafe.git.models import DiffFile, DiffLine, FileSkipped, FileStatus, LineType


class TestBasicParsing:
    def test_added_lines(self, sample_diff_clean):
        items = list(DiffParser(sample_diff_clean).parse())
        diff_files = [i for i in items if isinstance(i, DiffFile)]
        diff_lines = [i for i in items if isinstance(i, DiffLine)]

        assert len(diff_files) == 1
        assert diff_files[0].path == "hello.py"
        assert len(diff_lines) == 3
        assert all(dl.line_type == LineType.ADDED for dl in diff_lines)
        assert diff_lines[0].content == 'def greet(name):'
        assert diff_lines[0].line_no == 1

    def test_aws_key_lines(self, sample_diff_with_aws_key):
        items = list(DiffParser(sample_diff_with_aws_key).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 4
        # Line 3 should contain the AWS key
        assert "AKIAIOSFODNN7REAL123" in lines[2].content

    def test_password_diff(self, sample_diff_with_password):
        items = list(DiffParser(sample_diff_with_password).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 1
        assert "SuperS3cretP@ssw0rd!" in lines[0].content
        assert lines[0].line_no == 11


class TestEdgeCases:
    def test_binary_file_skipped(self, sample_diff_binary):
        items = list(DiffParser(sample_diff_binary).parse())
        skipped = [i for i in items if isinstance(i, FileSkipped)]
        assert len(skipped) == 1
        assert skipped[0].reason == "binary"
        assert skipped[0].path == "image.png"

    def test_rename_tracked(self, sample_diff_rename):
        items = list(DiffParser(sample_diff_rename).parse())
        files = [i for i in items if isinstance(i, DiffFile)]
        assert len(files) == 1
        assert files[0].path == "new_name.py"
        assert files[0].old_path == "old_name.py"
        assert files[0].status == FileStatus.RENAMED

    def test_mode_only_skipped(self, sample_diff_mode_only):
        items = list(DiffParser(sample_diff_mode_only).parse())
        skipped = [i for i in items if isinstance(i, FileSkipped)]
        assert len(skipped) == 1
        assert skipped[0].reason == "mode_only"

    def test_submodule_ignored(self, sample_diff_submodule):
        items = list(DiffParser(sample_diff_submodule).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        # Subproject commit lines should be skipped
        assert len(lines) == 0

    def test_no_newline_marker_ignored(self, sample_diff_no_newline):
        items = list(DiffParser(sample_diff_no_newline).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 1
        assert lines[0].content == "final line without newline"

    def test_single_line_hunk_header(self):
        """Hunk header without comma implies count=1."""
        diff = (
            "diff --git a/f.txt b/f.txt\n"
            "index abc..def 100644\n"
            "--- a/f.txt\n"
            "+++ b/f.txt\n"
            "@@ -1 +1 @@\n"
            "+replaced line\n"
        )
        items = list(DiffParser(diff).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 1
        assert lines[0].line_no == 1

    def test_consecutive_hunks(self):
        """Two hunks in the same file — line counter resets."""
        diff = (
            "diff --git a/f.py b/f.py\n"
            "index abc..def 100644\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -5,0 +5,1 @@\n"
            "+line at 5\n"
            "@@ -20,0 +21,1 @@\n"
            "+line at 21\n"
        )
        items = list(DiffParser(diff).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 2
        assert lines[0].line_no == 5
        assert lines[1].line_no == 21

    def test_deleted_file_no_added_lines(self):
        """Deleted files have only '-' lines — parser yields zero added lines."""
        diff = (
            "diff --git a/old.py b/old.py\n"
            "deleted file mode 100644\n"
            "index abc..000 100644\n"
            "--- a/old.py\n"
            "+++ /dev/null\n"
            "@@ -1,3 +0,0 @@\n"
            "-line one\n"
            "-line two\n"
            "-line three\n"
        )
        items = list(DiffParser(diff).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 0

    def test_bom_stripped(self):
        """UTF-8 BOM at start of content is removed."""
        diff = (
            "diff --git a/bom.txt b/bom.txt\n"
            "new file mode 100644\n"
            "index 0000000..abc1234\n"
            "--- /dev/null\n"
            "+++ b/bom.txt\n"
            "@@ -0,0 +1,1 @@\n"
            "+\ufeffhello world\n"
        )
        items = list(DiffParser(diff).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 1
        assert lines[0].content == "hello world"

    def test_file_headers_not_content(self):
        """--- a/file and +++ b/file should not appear as added lines."""
        diff = (
            "diff --git a/config.py b/config.py\n"
            "index abc..def 100644\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -1,0 +2,1 @@\n"
            "+new line\n"
        )
        items = list(DiffParser(diff).parse())
        lines = [i for i in items if isinstance(i, DiffLine)]
        assert len(lines) == 1
        assert "---" not in lines[0].content
        assert "+++" not in lines[0].content
