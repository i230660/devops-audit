
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

MAX_OUTPUT_CHARS = 12_000
MAX_READ_BYTES = 300_000
MAX_LIST_ENTRIES = 500
MAX_SEARCH_HITS = 60
DEFAULT_READ_LINES = 400
GIT_TIMEOUT = 30
COLLAPSE_THRESHOLD = 100  
SUSPECT_TRACKED = re.compile(
    r"(^|/)(__pycache__|node_modules|\.venv|venv|site-packages|\.idea|\.vscode|dist|build)(/|$)"
    r"|\.pyc$|\.DS_Store$|\.log$|(^|/)\.env$")

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
)
_TOKEN_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
]
_ASSIGNMENT = re.compile(
    r"""(?i)((?:api[_-]?key|secret|token|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key)\w*["']?\s*[:=]\s*)(["'])(?![$<{])([^"'\s]{6,})\2"""
)


def redact(text: str) -> str:
    """Mask credential-like literals. Preserves line count."""
    if not text:
        return text
    text = _PRIVATE_KEY.sub(
        lambda m: "[REDACTED PRIVATE KEY]" + "\n" * m.group(0).count("\n"), text
    )
    for pat in _TOKEN_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]{m.group(2)}", text)


class RepoTools:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.inspected = set()  

    @staticmethod
    def normalize_path(rel: str) -> str:
        return str(rel).strip().replace("\\", "/").removeprefix("./")

    def _git(self, *args, timeout=GIT_TIMEOUT):
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat",
               "GIT_OPTIONAL_LOCKS": "0"}
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            capture_output=True, text=True, errors="replace", timeout=timeout, env=env,
        )

    def _resolve(self, rel) -> Path:
        if not isinstance(rel, str) or not rel.strip():
            raise ValueError("path must be a non-empty string")
        p = (self.root / self.normalize_path(rel)).resolve()
        if p != self.root and self.root not in p.parents:
            raise ValueError("path escapes the repository root")
        parts = p.relative_to(self.root).parts
        if parts and parts[0] == ".git":
            raise ValueError("access to .git internals is not allowed; use git_log")
        return p

    def line_count(self, rel):
        """Number of lines in a repo file, or None if it is not a readable file."""
        try:
            p = self._resolve(rel)
            if not p.is_file():
                return None
            data = p.read_bytes()[:MAX_READ_BYTES]
        except (ValueError, OSError):
            return None
        return len(data.decode("utf-8", "replace").splitlines())

    def was_inspected(self, rel) -> bool:
        return self.normalize_path(rel) in self.inspected

    # -- required tools
    def list_files(self, directory: str = "") -> str:
        prefix = (directory or "").strip().replace("\\", "/").strip("/")
        r = self._git("ls-files", "-z")
        if r.returncode == 0:
            files = [f for f in r.stdout.split("\0") if f]
        else:  # not a git checkout: fall back to a filesystem walk
            files = []
            for dp, dn, fn in os.walk(self.root):
                dn[:] = [d for d in dn if d != ".git"]
                files += [str(Path(dp, f).relative_to(self.root)) for f in fn]
        if prefix:
            files = [f for f in files if f == prefix or f.startswith(prefix + "/")]
        files.sort()
        depth = len(prefix.split("/")) if prefix else 0

        def key(f):
            parts = f.split("/")
            return "/".join(parts[:depth + 1]) if len(parts) > depth + 1 else None

        counts = Counter(k for k in map(key, files) if k)
        collapsed = {k for k, c in counts.items() if c > COLLAPSE_THRESHOLD}
        shown = [f for f in files if key(f) not in collapsed]
        out = [f"{len(files)} git-tracked files" + (f" under '{prefix}/'" if prefix else "")]
        for k in sorted(collapsed):
            samples = [f for f in files if key(f) == k][:3]
            out.append(f"[collapsed] {k}/  {counts[k]} tracked files, e.g. {', '.join(samples)} "
                       f"(pass directory='{k}' to expand)")
        suspects = [f for f in files if SUSPECT_TRACKED.search(f)]
        if suspects:
            out.append(f"[note] {len(suspects)} tracked path(s) look generated/vendored/local, "
                       f"e.g. {', '.join(suspects[:3])}")
        for f in shown[:MAX_LIST_ENTRIES]:
            try:
                size = (self.root / f).lstat().st_size
            except OSError:
                size = -1
            out.append(f"{f}  ({size} bytes)")
        if len(shown) > MAX_LIST_ENTRIES:
            out.append(f"...({len(shown) - MAX_LIST_ENTRIES} more not shown; pass directory=...)")
        return "\n".join(out)

    def read_file(self, path: str, start_line: int = 1, max_lines: int = DEFAULT_READ_LINES) -> str:
        p = self._resolve(path)
        if not p.exists():
            return f"ERROR: file not found: {path} (it may simply not exist in the repo)"
        if p.is_dir():
            return f"ERROR: {path} is a directory; use list_files(directory=...)"
        raw = p.read_bytes()
        truncated = len(raw) > MAX_READ_BYTES
        raw = raw[:MAX_READ_BYTES]
        if b"\0" in raw[:4096]:
            self.inspected.add(self.normalize_path(path))
            return f"{path}: binary file ({p.stat().st_size} bytes), content not shown"
        lines = redact(raw.decode("utf-8", "replace")).splitlines()
        start = max(1, int(start_line))
        count = max(1, min(int(max_lines), 1000))
        chunk = lines[start - 1:start - 1 + count]
        body = "\n".join(f"{i:>5}| {ln[:300]}" for i, ln in enumerate(chunk, start))
        end = start + len(chunk) - 1
        note = " (file truncated at size limit)" if truncated else ""
        self.inspected.add(self.normalize_path(path))
        return f"{path} (lines {start}-{end} of {len(lines)}){note}\n{body}"

    def search_code(self, pattern: str, path_glob: str = None, ignore_case: bool = True) -> str:
        if not isinstance(pattern, str) or not pattern:
            return "ERROR: pattern must be a non-empty regex string"
        try:
            if re.search(pattern, ""):
                return ("ERROR: that pattern matches every line, which is useless. Use a specific pattern, "
                        "or read_file / list_files to check whether a file exists.")
        except re.error:
            pass
        args = ["grep", "-n", "-I", "-E", "--no-color"]
        if ignore_case:
            args.append("-i")
        args += ["-e", pattern]
        if path_glob:
            args += ["--", path_glob]
        r = self._git(*args, timeout=20)
        if r.returncode == 1:
            return f"No matches for /{pattern}/ in tracked text files"
        if r.returncode != 0:
            return f"ERROR: search failed: {r.stderr.strip()[:200]}"
        out, hits = [], r.stdout.splitlines()
        for line in hits[:MAX_SEARCH_HITS]:
            out.append(redact(line[:220]))
            self.inspected.add(line.split(":", 1)[0])
        head = f"{len(hits)} match(es) for /{pattern}/"
        if len(hits) > MAX_SEARCH_HITS:
            head += f" (showing first {MAX_SEARCH_HITS}; narrow the pattern or path_glob)"
        return head + " [file:line:text]\n" + "\n".join(out)

    def git_log(self, max_count: int = 30, path: str = None, pattern: str = None) -> str:
        n = max(1, min(int(max_count), 100))
        args = ["log", f"-n{n}", "--date=short", "--pretty=format:%h %ad %an: %s"]
        if pattern:
            args += ["-i", f"-G{pattern}"]  # commits whose diff added/removed matching text
        if path:
            self._resolve(path)
            args += ["--", self.normalize_path(path)]
        r = self._git(*args)
        if r.returncode != 0:
            return f"ERROR: git log failed: {r.stderr.strip()[:200]}"
        total = self._git("rev-list", "--count", "HEAD").stdout.strip() or "?"
        shallow = (self.root / ".git" / "shallow").exists()
        head = f"{len(r.stdout.splitlines())} commit(s) shown; {total} reachable"
        if shallow:
            head += " (shallow clone: older history not available)"
        return head + "\n" + redact(r.stdout)

    def git_show(self, commit: str, path: str = None, max_lines: int = 200) -> str:
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{4,40}|HEAD(~\d{1,3})?", commit.strip()):
            return "ERROR: commit must be a hex hash (4-40 chars) or HEAD / HEAD~N"
        args = ["show", "--no-color", "--no-ext-diff", "--no-textconv", "-U2", "--date=short",
                "--pretty=format:commit %h %ad %an: %s", commit.strip()]
        if path:
            self._resolve(path)
            args += ["--", self.normalize_path(path)]
        r = self._git(*args, timeout=30)
        if r.returncode != 0:
            return f"ERROR: git show failed: {r.stderr.strip()[:200]}"
        lines = redact(r.stdout).splitlines()
        n = max(1, min(int(max_lines), 400))
        extra = f"\n...[{len(lines) - n} more lines not shown]" if len(lines) > n else ""
        return "\n".join(ln[:240] for ln in lines[:n]) + extra

    # -- dispatch
    def dispatch(self, name: str, args: dict) -> str:
        fn = {"list_files": self.list_files, "read_file": self.read_file,
              "search_code": self.search_code, "git_log": self.git_log,
              "git_show": self.git_show}.get(name)
        if fn is None:
            return f"ERROR: unknown tool {name!r}"
        args = {k: v for k, v in (args or {}).items() if k != "reasoning"}
        try:
            out = fn(**args)
        except TypeError as e:
            return f"ERROR: bad arguments for {name}: {e}"
        except (ValueError, OSError) as e:
            return f"ERROR: {e}"
        except subprocess.TimeoutExpired:
            return f"ERROR: {name} timed out"
        if len(out) > MAX_OUTPUT_CHARS:
            out = out[:MAX_OUTPUT_CHARS] + "\n...[output truncated]"
        return out


REASONING_PROP = {"type": "string", "description": "1-3 sentences: what you observed, what you suspect, "
                  "and why you are calling this tool now"}


def _with_reasoning(spec):
    schema = spec["input_schema"]
    schema["properties"] = {"reasoning": REASONING_PROP, **schema["properties"]}
    schema["required"] = ["reasoning"] + schema.get("required", [])
    return spec


TOOL_SPECS = [
    {"name": "list_files",
     "description": "List git-tracked files with sizes (tracked files only, so ignored files never appear). "
                    "Optionally restrict to a directory.",
     "input_schema": {"type": "object", "properties": {
         "directory": {"type": "string", "description": "Repo-relative directory, e.g. '.github/workflows'"}}}},
    {"name": "read_file",
     "description": "Read a repo file with line numbers. Credential-like literals are shown as [REDACTED]; "
                    "treat a [REDACTED] literal as evidence of a hardcoded secret.",
     "input_schema": {"type": "object", "properties": {
         "path": {"type": "string"},
         "start_line": {"type": "integer"},
         "max_lines": {"type": "integer"}}, "required": ["path"]}},
    {"name": "search_code",
     "description": "Regex search (extended, case-insensitive by default) over tracked text files. "
                    "Returns file:line:text.",
     "input_schema": {"type": "object", "properties": {
         "pattern": {"type": "string"},
         "path_glob": {"type": "string", "description": "Optional pathspec such as '*.yml' or 'src/*'"},
         "ignore_case": {"type": "boolean"}}, "required": ["pattern"]}},
    {"name": "git_log",
     "description": "Recent commit history (hash, date, author, subject), optionally for one path. "
                    "With `pattern` (regex) it lists only commits whose diff added or removed matching text, "
                    "which finds credentials or files that were committed and later deleted.",
     "input_schema": {"type": "object", "properties": {
         "max_count": {"type": "integer"}, "path": {"type": "string"}, "pattern": {"type": "string"}}}},
    {"name": "git_show",
     "description": "Show one commit's diff (secrets redacted), optionally limited to a path. "
                    "commit must be a hex hash from git_log or HEAD / HEAD~N.",
     "input_schema": {"type": "object", "properties": {
         "commit": {"type": "string"}, "path": {"type": "string"},
         "max_lines": {"type": "integer"}}, "required": ["commit"]}},
]
TOOL_SPECS = [_with_reasoning(s) for s in TOOL_SPECS]