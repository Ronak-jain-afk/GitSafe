"""Tests for the CLI commands."""

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gitsafe.cli import app

runner = CliRunner()


class TestVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "gitsafe" in result.output


class TestInit:
    def test_creates_config(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert (tmp_git_repo / ".gitsafe.toml").exists()

    def test_refuses_overwrite(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        (tmp_git_repo / ".gitsafe.toml").write_text("existing")
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 1


class TestInstallUninstall:
    def test_install_creates_hook(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        result = runner.invoke(app, ["install"])
        assert result.exit_code == 0
        hook = tmp_git_repo / ".git" / "hooks" / "pre-commit"
        assert hook.exists()
        assert "gitsafe" in hook.read_text()

    def test_uninstall_removes_hook(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        runner.invoke(app, ["install"])
        result = runner.invoke(app, ["uninstall"])
        assert result.exit_code == 0
        hook = tmp_git_repo / ".git" / "hooks" / "pre-commit"
        assert not hook.exists()

    def test_install_refuses_existing(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        hooks_dir = tmp_git_repo / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho existing\n")
        result = runner.invoke(app, ["install"])
        assert result.exit_code == 1

    def test_install_force(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        hooks_dir = tmp_git_repo / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho existing\n")
        result = runner.invoke(app, ["install", "--force"])
        assert result.exit_code == 0


class TestScan:
    def test_no_staged_changes(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0

    def test_clean_staged_file(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        (tmp_git_repo / "clean.py").write_text("x = 1\n")
        subprocess.run(["git", "add", "clean.py"], cwd=tmp_git_repo, capture_output=True)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0

    def test_secret_blocks_commit(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        (tmp_git_repo / "leak.py").write_text(
            'API_KEY = "AKIAIOSFODNN7REAL123"\n'
        )
        subprocess.run(["git", "add", "leak.py"], cwd=tmp_git_repo, capture_output=True)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1

    def test_dry_run(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        (tmp_git_repo / "file.py").write_text("x = 1\n")
        subprocess.run(["git", "add", "file.py"], cwd=tmp_git_repo, capture_output=True)
        result = runner.invoke(app, ["scan", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output

    def test_json_format(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        (tmp_git_repo / "leak.py").write_text(
            'API_KEY = "AKIAIOSFODNN7REAL123"\n'
        )
        subprocess.run(["git", "add", "leak.py"], cwd=tmp_git_repo, capture_output=True)
        result = runner.invoke(app, ["scan", "--format", "json"])
        assert result.exit_code == 1
        import json
        data = json.loads(result.output)
        assert data["blocked"] is True


class TestExitCodes:
    def test_exit_0_clean(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0

    def test_exit_2_bad_format(self, tmp_git_repo: Path, monkeypatch):
        monkeypatch.chdir(tmp_git_repo)
        (tmp_git_repo / "f.py").write_text("x=1\n")
        subprocess.run(["git", "add", "f.py"], cwd=tmp_git_repo, capture_output=True)
        result = runner.invoke(app, ["scan", "--format", "invalid"])
        assert result.exit_code == 2
