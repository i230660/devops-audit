# DevOps Repository Auditing Agent

An LLM-powered agent that audits public GitHub repositories for potential DevOps best-practice violations and generates an evidence-based JSON report with recommendations.

The agent uses Python for its control flow and tool execution, with Google's Gemini API for reasoning and tool selection. It follows an **Observe → Reason → Select Tool → Execute → Interpret → Report** loop, allowing the LLM to decide what to inspect next rather than following a fixed checklist.

## Features

- Audits repository hygiene, dependencies, code quality, testing, CI/CD, security, configuration, collaboration, and build/release practices.
- Uses read-only tools to list files, read code, search content, and inspect Git history.
- Validates findings, checks evidence and line numbers, and removes duplicates.
- Records the audit process in a JSONL trace for debugging and review.
- Redacts secret-like values from tool outputs, traces, and reports.
- Uses a temporary shallow clone and never modifies the target repository or executes its code.
- Includes step limits, time limits, API retries, and error handling.

## Project Structure

- `agent.py` — CLI, cloning, and cleanup.
- `audit_agent.py` — Main agent loop and tool execution.
- `tools.py` — Read-only repository inspection tools.
- `report.py` — Finding validation and JSON report generation.
- `prompts.py` — Audit instructions and evidence requirements.
- `llm.py` — Gemini integration, tool-call handling, and rate limiting.
- `tests/` — Tests for repository tools and agent behavior.

## Setup

Requires Python 3.10+, Git, and a Gemini API key.

```bash
git clone https://github.com/i230660/devops-audit.git
cd devops-audit

python -m venv .venv
```

Activate the virtual environment, then install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file from `.env.example` and add your API key:

```dotenv
GEMINI_API_KEY=your_api_key_here
```

Get a key from [Google AI Studio](https://aistudio.google.com/apikey).

## Usage

```bash
python agent.py --repo https://github.com/<owner>/<repo> --output report.json
```

Optional arguments include `--max-steps`, `--time-budget`, `--trace`, and `--model`.

Run the tests with:

```bash
pytest -q
```

## Report

The agent generates a JSON report containing the repository URL and a list of violations. Each finding includes a rule ID, category, severity, file and line (when applicable), evidence, description, and recommendation.

See `sample_report.json` for an example.

## Limitations

- Only the latest 200 commits are cloned.
- Remote GitHub settings, such as branch protection and secret scanning, cannot be verified.
- Findings depend on the LLM's judgment and should be reviewed.
- Gemini free-tier quotas and rate limits may restrict usage.