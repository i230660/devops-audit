import subprocess

from tools import RepoTools, redact


def test_list_files_only_tracked(repo):
    (repo / "untracked.tmp").write_text("x")
    out = RepoTools(repo).list_files()
    assert "config.py" in out and "untracked.tmp" not in out


def test_read_file_numbers_lines_and_redacts(repo):
    t = RepoTools(repo)
    out = t.read_file("config.py")
    assert "sk-live" not in out and "[REDACTED]" in out
    assert "    2| DATA" in out
    assert t.was_inspected("config.py")


def test_path_traversal_and_git_dir_blocked(repo):
    t = RepoTools(repo)
    assert t.dispatch("read_file", {"path": "../../etc/passwd"}).startswith("ERROR")
    assert t.dispatch("read_file", {"path": ".git/config"}).startswith("ERROR")


def test_missing_file_is_reported_not_raised(repo):
    assert "not found" in RepoTools(repo).read_file("nope.txt")


def test_search_code_finds_and_marks_inspected(repo):
    t = RepoTools(repo)
    out = t.search_code("/home/")
    assert "config.py:2:" in out and t.was_inspected("config.py")
    assert "No matches" in t.search_code("zzz_not_here")


def test_search_invalid_regex_returns_error(repo):
    assert RepoTools(repo).search_code("(").startswith("ERROR")


def test_git_log(repo):
    assert "initial commit" in RepoTools(repo).git_log()


def test_bad_arguments_and_unknown_tool(repo):
    t = RepoTools(repo)
    assert t.dispatch("read_file", {"bogus": 1}).startswith("ERROR")
    assert t.dispatch("rm_rf", {}).startswith("ERROR")


def test_tools_leave_repo_unchanged(repo):
    t = RepoTools(repo)
    t.list_files(); t.read_file("config.py"); t.search_code("api"); t.git_log()
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                            capture_output=True, text=True).stdout
    assert status == ""


def test_redact_preserves_lines_and_ignores_references():
    pem = "a\n-----BEGIN RSA PRIVATE KEY-----\nAAA\nBBB\n-----END RSA PRIVATE KEY-----\nb"
    assert redact(pem).count("\n") == pem.count("\n")
    assert "AAA" not in redact(pem)
    assert redact('password: "${DB_PASS}"') == 'password: "${DB_PASS}"'
    assert "[REDACTED]" in redact("token = 'abcdef123456'")
