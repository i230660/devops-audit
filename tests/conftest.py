import subprocess

import pytest


def git(cwd, *a):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *a],
                   cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / ".github" / "workflows").mkdir(parents=True)
    (r / "README.md").write_text("# demo\n")
    (r / "config.py").write_text('API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz"\nDATA = "/home/bob/data"\n')
    (r / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs: {}\n")
    git(r, "init", "-q")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "initial commit")
    return r
