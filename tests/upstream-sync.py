"""Exercise the real sync script with local Git remotes and a fake GitHub CLI."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/upstream-sync.sh"


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.origin = self.root / "origin.git"
        self.upstream = self.root / "upstream.git"
        self.work = self.root / "work"
        self.env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": str(self.root / "gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.test",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.test",
            "GITHUB_ACTIONS": "true",
            "GITHUB_STEP_SUMMARY": str(self.root / "summary.md"),
            "GH_REPO": "mangyan1/NPMplus",
            "GH_TEST_LOG": str(self.root / "gh.jsonl"),
        }
        for bare in (self.origin, self.upstream):
            self.git("init", "--bare", str(bare), cwd=self.root)
        self.git("init", "-b", "develop", str(self.work), cwd=self.root)
        self.commit("shared.txt", "original\n")
        self.base = self.git("rev-parse", "HEAD")
        self.git("remote", "add", "origin", str(self.origin))
        self.git("push", "origin", "develop")
        self.git("push", str(self.upstream), "develop")
        self.git("config", f"url.{self.upstream}.insteadOf", "https://github.com/ZoeyVid/NPMplus.git")
        binaries = self.root / "bin"
        binaries.mkdir()
        gh = binaries / "gh"
        gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
with open(os.environ["GH_TEST_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
assert args[args.index("--repo") + 1] == "mangyan1/NPMplus", args
if args[:2] == ["pr", "list"]:
    if os.environ.get("GH_TEST_LIST_FAIL"):
        sys.exit(1)
    if os.environ.get("GH_TEST_RACE"):
        subprocess.run(["git", "--git-dir", os.environ["GH_TEST_RACE"], "update-ref",
                        "refs/heads/automation/upstream-sync", os.environ["GH_TEST_RACE_SHA"]], check=True)
    print(os.environ.get("GH_TEST_COUNT", "0"))
elif args[:2] == ["pr", "create"]:
    body = pathlib.Path(args[args.index("--body-file") + 1]).read_text()
    assert "FORK.md" in body and "Approve workflows to run" in body
    if os.environ.get("GH_TEST_CREATE_FAIL"):
        sys.exit(1)
else:
    raise AssertionError(args)
''', encoding="utf-8")
        gh.chmod(0o755)
        self.env["PATH"] = f"{binaries}{os.pathsep}{self.env['PATH']}"

    def git(self, *args, cwd=None):
        return subprocess.check_output(
            ["git", *args], cwd=cwd or self.work, env=self.env, stderr=subprocess.PIPE, text=True
        ).strip()

    def commit(self, name, content):
        (self.work / name).write_text(content, encoding="utf-8")
        self.git("add", name)
        self.git("commit", "-m", "update fixture")

    def diverge(self, conflict=False):
        self.commit("shared.txt" if conflict else "fork.txt", "fork behavior\n")
        self.git("push", "origin", "develop")
        self.fork_tip = self.git("rev-parse", "HEAD")
        self.git("switch", "-c", "upstream-fixture", self.base)
        self.commit("shared.txt" if conflict else "upstream.txt", "upstream behavior\n")
        self.git("push", str(self.upstream), "HEAD:develop")
        self.git("switch", "develop")

    def run_sync(self, **extra):
        result = subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.work, env={**self.env, **extra},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.assertEqual(self.git("--git-dir", str(self.origin), "rev-parse", "develop"),
                         getattr(self, "fork_tip", self.base), result.stdout)
        return result

    def calls(self):
        log = self.root / "gh.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def proposal_tip(self):
        return self.git("ls-remote", "--heads", "origin", "refs/heads/automation/upstream-sync").split("\t")[0]

    def test_already_synced_does_not_publish(self):
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.proposal_tip(), "")

    def test_clean_merge_preserves_both_sides_and_targets_fork(self):
        self.diverge()
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([call[:2] for call in self.calls()], [["pr", "list"], ["pr", "create"]])
        tip = self.proposal_tip()
        for name in ("fork.txt", "upstream.txt"):
            self.assertIn("behavior", self.git("--git-dir", str(self.origin), "show", f"{tip}:{name}"))

    def test_existing_proposal_is_refreshed_without_duplicate_pr(self):
        self.diverge()
        self.git("push", "origin", "HEAD:automation/upstream-sync")
        old_tip = self.proposal_tip()
        result = self.run_sync(GH_TEST_COUNT="1")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotEqual(old_tip, self.proposal_tip())
        self.assertEqual(len(self.calls()), 1)

    def prepare_deleted_report(self, upstream_edits_report=False):
        self.commit("internal-review.md", "historical report fixture\n")
        report_base = self.git("rev-parse", "HEAD")
        self.git("rm", "internal-review.md")
        self.git("commit", "-m", "remove published report fixture")
        for name in (".gitignore", ".dockerignore"):
            self.commit(name, "internal-review.md\n.local-*/\n")
        self.git("push", "origin", "develop")
        self.fork_tip = self.git("rev-parse", "HEAD")
        self.git("switch", "-c", "upstream-fixture", report_base)
        self.commit("internal-review.md" if upstream_edits_report else "upstream.txt",
                    "upstream update\n")
        self.git("push", str(self.upstream), "HEAD:develop")
        self.git("switch", "develop")

    def test_merge_preserves_report_deletion_and_ignore_rules(self):
        self.prepare_deleted_report()
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        tip = self.proposal_tip()
        self.assertNotIn("internal-review.md", self.git("ls-tree", "--name-only", tip).splitlines())
        for name in (".gitignore", ".dockerignore"):
            self.assertEqual(self.git("show", f"{tip}:{name}"), "internal-review.md\n.local-*/")
        self.assertEqual(self.git("show", f"{tip}:upstream.txt"), "upstream update")

    def test_upstream_edit_of_deleted_report_stops_without_publishing(self):
        self.prepare_deleted_report(upstream_edits_report=True)
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proposal_tip(), "")
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.work / "internal-review.md").exists())
        self.assertIn("internal-review.md", (self.root / "summary.md").read_text())

    def test_conflict_preserves_existing_proposal_and_aborts(self):
        self.diverge(conflict=True)
        self.git("push", "origin", "HEAD:automation/upstream-sync")
        old_tip = self.proposal_tip()
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(old_tip, self.proposal_tip())
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertIn("shared.txt", (self.root / "summary.md").read_text())

    def test_concurrent_branch_creation_fails_the_lease(self):
        self.diverge()
        result = self.run_sync(GH_TEST_RACE=str(self.origin), GH_TEST_RACE_SHA=self.fork_tip)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proposal_tip(), self.fork_tip)
        self.assertEqual(len(self.calls()), 1)

    def test_pr_lookup_failure_does_not_push(self):
        self.diverge()
        result = self.run_sync(GH_TEST_LIST_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proposal_tip(), "")

    def test_pr_creation_failure_is_reported_without_changing_develop(self):
        self.diverge()
        result = self.run_sync(GH_TEST_CREATE_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(self.proposal_tip(), "")
        self.assertIn("PR creation failed", (self.root / "summary.md").read_text())

    def test_dirty_checkout_is_refused(self):
        (self.work / "operator.txt").write_text("keep me\n")
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing a dirty checkout", result.stdout)
        self.assertEqual((self.work / "operator.txt").read_text(), "keep me\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
