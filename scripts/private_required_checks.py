#!/usr/bin/env python3
"""Run private-repository required checks inside the public CI bridge."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable


CONTEXTS = (
    "pr-title-check",
    "secret-scan",
    "language-check",
    "risk-policy",
    "issue-contract",
    "broken-dev-policy",
)
TITLE_PATTERN = re.compile(
    r"^(feat|fix|docs|refactor|perf|test|build|ci|chore|deps|spike)"
    r"(\([^)]+\))?!?:\s.+"
)
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class CheckFailure(RuntimeError):
    pass


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _pull_request(event: dict[str, Any]) -> dict[str, Any] | None:
    value = event.get("pull_request")
    return value if isinstance(value, dict) else None


def check_title(event: dict[str, Any]) -> None:
    pull = _pull_request(event)
    if pull is None:
        return
    title = pull.get("title")
    if not isinstance(title, str) or TITLE_PATTERN.fullmatch(title) is None:
        raise CheckFailure("PR title does not follow the Conventional Commits contract")


def required_risk_labels(paths: list[str]) -> set[str]:
    required: set[str] = set()

    def matches(prefix: str) -> bool:
        return any(path == prefix or path.startswith(prefix + "/") for path in paths)

    if any(matches(prefix) for prefix in ("src/trading", "src/broker", "src/risk", "scripts/trading")):
        required.add("risk:trading")
    if any(matches(prefix) for prefix in (".github/workflows", "infra", "deploy", "systemd", "scripts/deploy")):
        required.add("risk:infra")
    if any(matches(prefix) for prefix in ("migrations", "schema", "db")):
        required.add("risk:data-contract")
    return required


def check_risk(event: dict[str, Any], paths: list[str]) -> None:
    pull = _pull_request(event)
    if pull is None:
        return
    labels = {
        row.get("name")
        for row in pull.get("labels", [])
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    missing = sorted(required_risk_labels(paths) - labels)
    if missing:
        raise CheckFailure("missing required risk labels: " + ", ".join(missing))
    base = pull.get("base")
    head = pull.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise CheckFailure("pull request branch metadata is missing")
    if base.get("ref") == "main":
        if not str(head.get("ref", "")).startswith("promote/dev-to-main-"):
            raise CheckFailure("main accepts only the automated promotion branch")
        if pull.get("title") != "chore: promote dev to main (auto)":
            raise CheckFailure("main accepts only the automated promotion title")


def check_code_only(candidate: Path) -> None:
    ignore = candidate / ".gitignore"
    lines = set(ignore.read_text(encoding="utf-8").splitlines())
    if "docs/" not in lines or "*.md" not in lines:
        raise CheckFailure("code-only ignore policy is incomplete")
    for path in candidate.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(candidate).as_posix()
        if relative.startswith("docs/") or relative.endswith(".md"):
            raise CheckFailure("tracked documentation violates the code-only policy")


def _command_check(
    command: list[str],
    *,
    cwd: Path,
    details: list[str],
    env: dict[str, str] | None = None,
) -> None:
    completed = _run(command, cwd=cwd, env=env)
    if completed.stdout:
        details.append(completed.stdout)
    if completed.stderr:
        details.append(completed.stderr)
    if completed.returncode != 0:
        raise CheckFailure(f"command exited with status {completed.returncode}")


def check_secret(candidate: Path, details: list[str]) -> None:
    _command_check(
        ["gitleaks", "detect", "--source", ".", "--no-git", "--redact", "--verbose"],
        cwd=candidate,
        details=details,
    )


def check_language(candidate: Path, details: list[str]) -> None:
    check_code_only(candidate)
    _command_check(
        [sys.executable, "scripts/deploy/language_policy.py", "--check", "--root", str(candidate)],
        cwd=candidate,
        details=details,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


def check_issue_contract(
    trusted: Path,
    candidate: Path,
    event_path: Path,
    event_name: str,
    repository: str,
    token: str,
    details: list[str],
) -> None:
    trusted_files = (
        "config/issue-contract-policy-v1.json",
        "scripts/process_rollout/issue_contract.py",
        "scripts/process_rollout/issue_contract_pr.py",
    )
    candidate_files = (*trusted_files, ".github/workflows/issue-contract.yml")
    if not all((trusted / path).is_file() and not (trusted / path).is_symlink() for path in trusted_files):
        raise CheckFailure("trusted issue-contract validator is incomplete")
    if not all((candidate / path).is_file() and not (candidate / path).is_symlink() for path in candidate_files):
        raise CheckFailure("candidate issue-contract closure is incomplete")
    _command_check(
        [
            sys.executable,
            "scripts/process_rollout/issue_contract_pr.py",
            "--event-file",
            str(event_path),
            "--event-name",
            event_name,
            "--repo",
            repository,
        ],
        cwd=trusted,
        details=details,
        env={
            **os.environ,
            "GITHUB_TOKEN": token,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": ".",
        },
    )


def check_broken_dev(
    trusted: Path,
    event_path: Path,
    event_name: str,
    repository: str,
    token: str,
    details: list[str],
) -> None:
    files = (
        "scripts/deploy/t6_github_policy.py",
        "scripts/deploy/t6_release_promotion.py",
    )
    if not all((trusted / path).is_file() and not (trusted / path).is_symlink() for path in files):
        raise CheckFailure("trusted broken-dev policy closure is incomplete")
    _command_check(
        [sys.executable, "scripts/deploy/t6_github_policy.py"],
        cwd=trusted,
        details=details,
        env={
            **os.environ,
            "GITHUB_EVENT_NAME": event_name,
            "GITHUB_EVENT_PATH": str(event_path),
            "GITHUB_REPOSITORY": repository,
            "GITHUB_TOKEN": token,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": ".",
        },
    )


def _record(
    results: dict[str, dict[str, str]],
    details: list[str],
    context: str,
    check: Callable[[], None],
) -> None:
    try:
        check()
    except (CheckFailure, OSError, ValueError, subprocess.SubprocessError) as exc:
        results[context] = {"state": "failure", "description": f"{context} failed"}
        details.append(f"[{context}] {exc}")
    else:
        results[context] = {"state": "success", "description": f"{context} passed"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--trusted-base", type=Path, required=True)
    parser.add_argument("--meta", type=Path, required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--changed-files", type=Path, required=True)
    parser.add_argument("--details", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()

    meta = json.loads(args.meta.read_text(encoding="utf-8"))
    event = json.loads(args.event.read_text(encoding="utf-8"))
    paths = json.loads(args.changed_files.read_text(encoding="utf-8"))
    repository = meta.get("repo")
    token = os.environ.get("CI_TOKEN", "")
    if not isinstance(repository, str) or REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise SystemExit("private required checks: invalid repository")
    if not token or "\n" in token:
        raise SystemExit("private required checks: missing token")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise SystemExit("private required checks: invalid changed-file list")

    event_name = "pull_request" if _pull_request(event) is not None else "push"
    results: dict[str, dict[str, str]] = {}
    details: list[str] = []
    _record(results, details, "pr-title-check", lambda: check_title(event))
    _record(results, details, "secret-scan", lambda: check_secret(args.candidate, details))
    _record(results, details, "language-check", lambda: check_language(args.candidate, details))
    _record(results, details, "risk-policy", lambda: check_risk(event, paths))
    _record(
        results,
        details,
        "issue-contract",
        lambda: check_issue_contract(
            args.trusted_base,
            args.candidate,
            args.event,
            event_name,
            repository,
            token,
            details,
        ),
    )
    _record(
        results,
        details,
        "broken-dev-policy",
        lambda: check_broken_dev(
            args.trusted_base,
            args.event,
            event_name,
            repository,
            token,
            details,
        ),
    )

    args.results.write_text(
        json.dumps(results, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    args.details.write_text("\n".join(details)[-65536:], encoding="utf-8")
    return 0 if all(row["state"] == "success" for row in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
