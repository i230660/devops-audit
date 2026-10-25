#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv

from audit_agent import AuditAgent
from llm import GeminiLLM, LLMError
from report import write_report
from tools import RepoTools

GITHUB_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?:\.git)?/?$")


class CloneError(Exception):
    pass


def clone_repo(url: str, dest: Path, depth=200, timeout=180):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        r = subprocess.run(["git", "clone", "--quiet", "--no-tags", "--depth", str(depth), url, str(dest)],
                           capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise CloneError(f"timed out cloning {url}")
    except FileNotFoundError:
        raise CloneError("git is not installed or not on PATH")
    if r.returncode != 0:
        raise CloneError(f"could not clone {url} (private or non-existent?): {r.stderr.strip()[:300]}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LLM-driven DevOps repository auditing agent")
    ap.add_argument("--repo", required=True, help="public GitHub repository URL")
    ap.add_argument("--output", required=True, help="path of the JSON report to write")
    ap.add_argument("--max-steps", type=int, default=40)
    ap.add_argument("--time-budget", type=int, default=900, help="seconds for the agent loop")
    ap.add_argument("--trace", help="tool-call trace file (default: <output>.trace.jsonl)")
    ap.add_argument("--model", help="override GEMINI_MODEL")
    args = ap.parse_args(argv)

    load_dotenv()
    repo = args.repo.strip()
    if not GITHUB_RE.match(repo):
        print("error: --repo must look like https://github.com/<owner>/<name>", file=sys.stderr)
        return 2
    try:
        llm = GeminiLLM(model=args.model)
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    trace = args.trace or str(Path(args.output).with_suffix("")) + ".trace.jsonl"
    try:
        with tempfile.TemporaryDirectory(prefix="audit_") as tmp:
            dest = Path(tmp) / "repo"
            try:
                clone_repo(repo, dest)
            except CloneError as e:
                print(f"error: {e}", file=sys.stderr)
                return 3
            agent = AuditAgent(RepoTools(dest), llm, repo, args.max_steps, args.time_budget, trace)
            violations = agent.run()
        write_report(args.output, repo.rstrip("/"), violations)
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    except OSError as e:
        print(f"error: could not write report: {e}", file=sys.stderr)
        return 5
    except Exception as e:  # last-resort guard: never a traceback with secrets
        print(f"error: unexpected failure: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"Audit complete: {len(violations)} violation(s) -> {args.output} (trace: {trace})")
    return 0


if __name__ == "__main__":
    sys.exit(main())