import json
import os
import tempfile
from pathlib import Path

from tools import redact

CATEGORY_PREFIX = {
    "repository_hygiene": "REPO", "dependency_management": "DEP", "code_quality": "QLT",
    "testing": "TST", "ci_cd": "CI", "security": "SEC", "configuration": "CFG",
    "collaboration": "COL", "build_release": "BLD",
}
SEVERITIES = ("critical", "high", "medium", "low")
FIELDS = ("rule_id", "category", "severity", "file", "line",
          "description", "evidence", "recommendation")


class FindingStore:

    def __init__(self, tools):
        self.tools = tools
        self.violations = []
        self._counters = {}
        self._seen = set()

    def add(self, raw: dict):
        if not isinstance(raw, dict):
            return False, "REJECTED: arguments must be an object"
        missing = [k for k in ("category", "severity", "description", "evidence", "recommendation")
                   if k not in raw]
        if missing:
            return False, f"REJECTED: missing fields {missing}"
        cat, sev = raw["category"], raw["severity"]
        if cat not in CATEGORY_PREFIX:
            return False, f"REJECTED: category must be one of {sorted(CATEGORY_PREFIX)}"
        if sev not in SEVERITIES:
            return False, f"REJECTED: severity must be one of {list(SEVERITIES)}"
        texts = {}
        for k in ("description", "evidence", "recommendation"):
            v = raw[k]
            if not isinstance(v, str) or not v.strip():
                return False, f"REJECTED: {k} must be a non-empty string"
            texts[k] = redact(v.strip())[:600]

        file, line = raw.get("file"), raw.get("line")
        if isinstance(line, float) and line.is_integer():
            line = int(line)
        n = None
        if file in (None, ""):
            file = None
        else:
            if not isinstance(file, str):
                return False, "REJECTED: file must be a string or null"
            file = self.tools.normalize_path(file)
            n = self.tools.line_count(file)
            if n is None:
                return False, (f"REJECTED: '{file}' does not exist in the repo. If the problem is "
                               "that something is MISSING, use file=null and line=null.")
            if not self.tools.was_inspected(file):
                return False, f"REJECTED: you have not read or searched '{file}' yet. Inspect it first."
        if line is not None:
            if file is None:
                return False, "REJECTED: line requires a file; use line=null when file=null"
            if isinstance(line, bool) or not isinstance(line, int) or not 1 <= line <= n:
                return False, f"REJECTED: line must be an integer between 1 and {n} (or null)"

        keys = {(cat, file, line, texts["description"].lower())}
        if file and line:
            keys.add((cat, file, line))
        if keys & self._seen:
            return False, "REJECTED: duplicate of an existing finding"
        self._seen |= keys

        prefix = CATEGORY_PREFIX[cat]
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        self.violations.append({
            "rule_id": f"{prefix}-{self._counters[prefix]:03d}",
            "category": cat, "severity": sev, "file": file, "line": line, **texts,
        })
        return True, f"ACCEPTED as {self.violations[-1]['rule_id']}"


def write_report(path, repo: str, violations: list):
    for v in violations:
        assert all(f in v for f in FIELDS), f"incomplete violation: {v}"
    report = {"repository": repo, "violations": violations}
    json.dumps(report)  
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)