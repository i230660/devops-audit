import json

from audit_agent import AuditAgent
from report import FindingStore, write_report
from tools import RepoTools


class FakeLLM:
    def __init__(self, script):
        self.script = list(script)

    def create(self, system, messages, tools):
        return self.script.pop(0), "tool_use"


def use(i, name, **inp):
    return {"type": "tool_use", "id": f"t{i}", "name": name, "input": inp}


FINDING = dict(category="security", severity="critical", file="config.py", line=1,
               description="Hardcoded API credential", evidence="literal assigned in source",
               recommendation="Use an environment variable")


def test_full_loop_dispatches_tools_and_records_finding(repo, tmp_path):
    llm = FakeLLM([
        [{"type": "text", "text": "Look at structure"}, use(1, "list_files")],
        [use(2, "read_file", path="config.py")],
        [use(3, "report_violation", **FINDING)],
        [use(4, "report_violation", **FINDING)],  # duplicate -> rejected
        [use(5, "finish_audit", summary="done")],
    ])
    trace = tmp_path / "t.jsonl"
    v = AuditAgent(RepoTools(repo), llm, "https://github.com/x/y", max_steps=10, trace_path=trace).run()
    assert len(v) == 1 and v[0]["rule_id"] == "SEC-001"
    assert set(v[0]) == {"rule_id", "category", "severity", "file", "line",
                         "description", "evidence", "recommendation"}
    tools_used = [json.loads(l).get("tool") for l in trace.read_text().splitlines()]
    assert tools_used[:2] == ["list_files", "read_file"]
    assert not llm.script


def test_rejects_uninspected_missing_and_bad_line(repo):
    store = FindingStore(RepoTools(repo))
    ok, msg = store.add(FINDING)
    assert not ok and "not read" in msg
    ok, msg = store.add({**FINDING, "file": "ghost.py"})
    assert not ok and "does not exist" in msg
    store.tools.read_file("config.py")
    ok, msg = store.add({**FINDING, "line": 99})
    assert not ok and "between 1 and" in msg
    ok, msg = store.add({**FINDING, "severity": "urgent"})
    assert not ok
    ok, _ = store.add({**FINDING, "file": None, "line": None, "category": "testing", "severity": "medium",
                       "description": "No tests found"})
    assert ok and store.violations[0]["rule_id"] == "TST-001"


def test_secret_values_never_reach_report(repo):
    store = FindingStore(RepoTools(repo))
    store.tools.read_file("config.py")
    store.add({**FINDING, "evidence": 'API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz"'})
    assert "sk-live" not in json.dumps(store.violations)


def test_agent_stops_when_model_never_calls_tools(repo):
    llm = FakeLLM([[{"type": "text", "text": "hmm"}]] * 3)
    assert AuditAgent(RepoTools(repo), llm, "u", max_steps=10).run() == []


def test_empty_report_is_valid_json(tmp_path):
    p = tmp_path / "out" / "report.json"
    write_report(p, "https://github.com/x/y", [])
    assert json.loads(p.read_text()) == {"repository": "https://github.com/x/y", "violations": []}


def test_float_line_and_omitted_nulls_accepted(repo):
    store = FindingStore(RepoTools(repo))
    store.tools.read_file("config.py")
    ok, _ = store.add({**FINDING, "line": 2.0})
    assert ok and store.violations[0]["line"] == 2
    raw = {k: v for k, v in FINDING.items() if k not in ("file", "line")}
    ok, _ = store.add({**raw, "category": "testing", "description": "No tests"})
    assert ok and store.violations[-1]["file"] is None
