# DevOps Repository Auditing Agent

An LLM-driven agent that clones a public GitHub repository, investigates it with read-only tools, and writes an
evidence-based JSON report of DevOps best-practice violations. The agent loop, tool dispatch and control flow are
plain Python (no LangChain/LangGraph/n8n); the only provider dependency is the Google Gemini SDK (`google-genai`) in `llm.py`, using Gemini's free tier.

## Architecture

```
agent.py          CLI: validate URL -> shallow clone to temp dir -> run loop -> write report -> cleanup
audit_agent.py    Explicit loop: LLM message -> tool_use blocks -> Python executes -> tool_result back to LLM
tools.py          list_files, read_file, search_code, git_log (read-only, path-confined, secret-redacting)
report.py         FindingStore (validation, de-duplication, auto rule_id) + atomic JSON writer
prompts.py        System prompt: method, areas to probe, evidence rules, severity guide
llm.py            Gemini SDK wrapper: tool-call translation, free-tier throttling, retry/backoff (swap this file to change provider)
tests/            pytest suite (tools + agent loop with a scripted fake LLM)
```

Cycle: **Observe** (tool output) -> **Reason** (LLM states what it saw/suspects) -> **Select tool** (LLM picks the
next tool and arguments, including follow-ups) -> **Execute** (Python) -> **Interpret** (next LLM turn) ->
**Report** (`report_violation`, then `finish_audit`). There is no fixed checklist: the LLM decides every tool call.
Every call is logged to `<output>.trace.jsonl` (thought, tool, args, output preview).

### Precision / safety design
- `report_violation` is validated in Python: the file must exist, must have been read or appeared in a search, the line
  must be in range, and duplicates are rejected. Missing things are reported with `file: null, line: null`.
- The prompt encodes the evidence rule: acceptable alternatives are not defects; branch protection is never inferred.
- Target code is never executed (no pytest/ruff run on untrusted code). The clone lives in a temp dir that is deleted;
  nothing is written to or pushed to the target.
- Secret-like literals are redacted in every tool output, the trace and the report.
- Errors: invalid URL (exit 2), missing API key (2), clone failure (3), LLM failure (4), report write failure (5),
  unexpected (1). Step and time budgets bound the loop.

## Setup
```bash
git clone <this-repo> && cd <this-repo>
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # then set GEMINI_API_KEY (free: https://aistudio.google.com/apikey)
```
Requires Python 3.10+ and `git` on PATH.

## Run
```bash
python agent.py --repo https://github.com/<owner>/<repo> --output report.json
```
Options: `--max-steps 40`, `--time-budget 900`, `--trace path.jsonl`, `--model <name>`.

### Free-tier notes
Calls are throttled (`GEMINI_MIN_INTERVAL`, default 5 s) and retried on HTTP 429/5xx. If the daily quota is exhausted the
agent exits with code 4 and a clear message. Set `GEMINI_MODEL` to any free model; `python llm.py` lists the models your
key can use. Free-tier prompts may be used by Google to improve its products, which is fine for public repositories.

## Tests
```bash
pytest -q
```

## Report format
`{"repository": "...", "violations": [{rule_id, category, severity, file, line, description, evidence, recommendation}]}`
Categories: repository_hygiene, dependency_management, code_quality, testing, ci_cd, security, configuration,
collaboration, build_release. Severities: critical, high, medium, low. `sample_report.json` is real output.

## Limitations
Shallow clone (200 commits). Remote settings (branch protection, secret scanning) cannot be inspected from files
and are never reported. Findings depend on LLM judgement; the trace shows how each was reached.
