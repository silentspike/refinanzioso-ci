from __future__ import annotations

from pathlib import Path
import unittest

from scripts.private_required_checks import (
    CheckFailure,
    check_risk,
    check_title,
    required_risk_labels,
)


def event(*, title: str = "fix(ci): test", labels: tuple[str, ...] = ()) -> dict:
    return {
        "pull_request": {
            "title": title,
            "labels": [{"name": label} for label in labels],
            "base": {"ref": "dev"},
            "head": {"ref": "issue-1-test"},
        }
    }


class PrivateRequiredChecksTests(unittest.TestCase):
    def test_workflow_installs_hash_locked_private_runtime(self) -> None:
        workflow = (Path(__file__).parents[1] / ".github/workflows/bridge-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Install pinned private runtime", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("private-source/requirements/runtime.lock", workflow)

    def test_full_mode_publishes_secret_and_language_statuses(self) -> None:
        workflow = (Path(__file__).parents[1] / ".github/workflows/bridge-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count("required_contexts=(secret-scan language-check)"), 2)
        self.assertIn("for context in \"${required_contexts[@]}\"", workflow)

    def test_title_requires_conventional_commit_shape(self) -> None:
        check_title(event(title="fix(collectors): restore runtime"))
        with self.assertRaises(CheckFailure):
            check_title(event(title="restore runtime"))

    def test_risk_paths_require_exact_labels(self) -> None:
        paths = ["scripts/deploy/runner.py", "migrations/001.sql"]
        self.assertEqual(required_risk_labels(paths), {"risk:infra", "risk:data-contract"})
        check_risk(event(labels=("risk:infra", "risk:data-contract")), paths)
        with self.assertRaises(CheckFailure):
            check_risk(event(labels=("risk:infra",)), paths)

    def test_main_accepts_only_automated_promotion(self) -> None:
        value = event(title="chore: promote dev to main (auto)")
        value["pull_request"]["base"]["ref"] = "main"
        value["pull_request"]["head"]["ref"] = "promote/dev-to-main-123"
        check_risk(value, [])
        value["pull_request"]["head"]["ref"] = "feature/manual"
        with self.assertRaises(CheckFailure):
            check_risk(value, [])


if __name__ == "__main__":
    unittest.main()
