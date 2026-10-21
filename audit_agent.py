"""The explicit agent loop: the LLM decides which tool to call next; Python executes it."""
import json
import time
from pathlib import Path

from prompts import INITIAL_MESSAGE, SYSTEM_PROMPT
from report import CATEGORY_PREFIX, SEVERITIES, FindingStore
from tools import TOOL_SPECS, RepoTools, redact

REPORT_TOOL_SPECS = [
    {"name": "report_violation",
     "description": "Record one confirmed DevOps violation. Rejected if the file does not exist, was never "
                    "inspected, the line is out of range, or it duplicates an earlier finding.",
     "input_schema": {"type": "object", "properties": {
         "category": {"type": "string", "enum": sorted(CATEGORY_PREFIX)},
         "severity": {"type": "string", "enum": list(SEVERITIES)},
         "file": {"type": ["string", "null"], "description": "Omit or null if the problem is something missing"},
         "line": {"type": ["integer", "null"]},
         "description": {"type": "string"},
         "evidence": {"type": "string", "description": "What you observed; never include secret values"},
         "recommendation": {"type": "string"}},
         "required": ["category", "severity", "description", "evidence", "recommendation"]}},
    {"name": "finish_audit",
     "description": "Call when the investigation is complete.",
     "input_schema": {"type": "object", "properties": {"summary": {"type": "string"}}}},
]
ALL_TOOL_SPECS = TOOL_SPECS + REPORT_TOOL_SPECS


class AuditAgent:
    def __init__(self, tools: RepoTools, llm, repo_url: str, max_steps=40,
                 time_budget=600, trace_path=None):
        self.tools, self.llm, self.repo_url = tools, llm, repo_url
        self.max_steps, self.time_budget = max_steps, time_budget
        self.store = FindingStore(tools)
        self.trace_path = Path(trace_path) if trace_path else None
        if self.trace_path:
            self.trace_path.parent.mkdir(parents=True, exist_ok=True)
            self.trace_path.write_text("")

    # -- logging (tool-call trace for the instructor)
    def _log(self, event: dict):
        if not self.trace_path:
            return
        event["ts"] = round(time.time(), 3)
        with open(self.trace_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    # -- context control: keep recent tool outputs, shrink old ones
    @staticmethod
    def _prune(messages, keep=6):
        idx = [i for i, m in enumerate(messages) if m["role"] == "user"
               and isinstance(m["content"], list)
               and any(b.get("type") == "tool_result" for b in m["content"])]
        for i in idx[:-keep]:
            for b in messages[i]["content"]:
                if (b.get("type") == "tool_result" and len(b["content"]) > 300
                        and "[older output elided" not in b["content"]):
                    b["content"] = b["content"][:300] + "\n...[older output elided; re-run the tool if needed]"

    def _execute(self, use):
        name, args = use["name"], use.get("input") or {}
        if name == "finish_audit":
            return "Audit marked complete.", True
        if name == "report_violation":
            _, msg = self.store.add(args)
            return msg, False
        return self.tools.dispatch(name, args), False

    def run(self) -> list:
        deadline = time.monotonic() + self.time_budget
        messages = [{"role": "user", "content": INITIAL_MESSAGE.format(repo=self.repo_url)}]
        nudges = 0
        for step in range(1, self.max_steps + 1):
            if time.monotonic() > deadline:
                self._log({"event": "time_budget_exhausted"})
                break
            self._prune(messages)
            blocks, _ = self.llm.create(SYSTEM_PROMPT, messages, ALL_TOOL_SPECS)
            messages.append({"role": "assistant", "content": blocks})
            thought = " ".join(b["text"] for b in blocks if b["type"] == "text").strip()
            uses = [b for b in blocks if b["type"] == "tool_use"]
            if not uses:
                self._log({"step": step, "thought": redact(thought), "event": "no_tool_call"})
                if nudges < 2:
                    nudges += 1
                    messages.append({"role": "user", "content":
                                     "Continue investigating with tools, or call finish_audit if done."})
                    continue
                break
            results, done = [], False
            for u in uses:
                out, finished = self._execute(u)
                done = done or finished
                self._log({"step": step, "thought": redact(thought), "tool": u["name"],
                           "args": u.get("input"), "output_preview": out[:400]})
                results.append({"type": "tool_result", "tool_use_id": u["id"], "content": out})
            if step == self.max_steps - 2 and not done:
                results.append({"type": "text", "text":
                                "Only 2 steps remain: report any confirmed findings and call finish_audit."})
            messages.append({"role": "user", "content": results})
            if done:
                break
        self._log({"event": "finished", "violations": len(self.store.violations)})
        return self.store.violations