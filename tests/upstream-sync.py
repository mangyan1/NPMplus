"""Exercise the real sync script with local Git remotes and a fake GitHub CLI."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/upstream-sync.sh"

if os.name == "nt":
    # Git Bash aliases the Windows temp directory to /tmp and rewrites paths created
    # under it, which native tools cannot open. Keep the sandbox out of that alias.
    scratch = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                           "npmplus-upstream-sync-tests")
    os.makedirs(scratch, exist_ok=True)
    tempfile.tempdir = scratch

# Calls that change repository state. Reads (pr list, issue list, label list) are
# allowed anywhere; the invariants below are about what gets published.
PUBLISHED = {("pr", "create"), ("issue", "create"), ("issue", "edit"), ("issue", "close"), ("label", "create")}


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.origin = self.root / "origin.git"
        self.upstream = self.root / "upstream.git"
        self.work = self.root / "work"
        self.state = self.root / "gh-state.json"
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
            "GH_TEST_STATE": str(self.state),
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
        # Git Bash cannot exec a shebang script whose interpreter is a native .exe:
        # it hands that interpreter a mangled path. So the fake CLI implementation is
        # fed to Python on stdin by a POSIX wrapper, and every path the implementation
        # opens is either a Windows path from this env or one the script under test
        # created inside TMPDIR.
        gh = binaries / "gh-impl.py"
        gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, sys

def native(value):
    # bash reports paths in POSIX form (/c/dir/file); the native interpreter needs C:/dir/file.
    drive = re.match(r"^/([A-Za-z])/(.*)$", value)
    return f"{drive.group(1)}:/{drive.group(2)}" if drive else value

args = sys.argv[1:]
with open(native(os.environ["GH_TEST_LOG"]), "a") as log:
    log.write(json.dumps(args) + "\\n")
assert args[args.index("--repo") + 1] == "mangyan1/NPMplus", args
state_path = pathlib.Path(native(os.environ["GH_TEST_STATE"]))
state = json.loads(state_path.read_text()) if state_path.exists() else {"labels": [], "issues": []}

def save():
    state_path.write_text(json.dumps(state))

def flag(name, default=None):
    return args[args.index(name) + 1] if name in args else default

def body_of(number):
    return next(issue for issue in state["issues"] if issue["number"] == int(number))

if args[:2] == ["pr", "list"]:
    assert flag("--jq") == "length", args
    if os.environ.get("GH_TEST_LIST_FAIL"):
        sys.exit(1)
    if os.environ.get("GH_TEST_RACE"):
        subprocess.run(["git", "--git-dir", os.environ["GH_TEST_RACE"], "update-ref",
                        "refs/heads/automation/upstream-sync", os.environ["GH_TEST_RACE_SHA"]], check=True)
    print(os.environ.get("GH_TEST_COUNT", "0"))
elif args[:2] == ["pr", "create"]:
    body = pathlib.Path(native(flag("--body-file"))).read_text()
    assert "FORK.md" in body and "Approve workflows to run" in body
    if os.environ.get("GH_TEST_CREATE_FAIL"):
        sys.exit(1)
elif args[:2] == ["label", "list"]:
    assert flag("--json") == "name", args
    assert flag("--jq", "").startswith("map(.name) | index("), args
    print("true" if "upstream-sync" in state["labels"] else "false")
elif args[:2] == ["label", "create"]:
    assert args[2] == "upstream-sync" and flag("--color") and flag("--description"), args
    state["labels"].append(args[2])
    save()
elif args[:2] == ["issue", "list"]:
    assert flag("--search") == "label:upstream-sync state:open", args
    open_issues = [issue for issue in state["issues"] if issue["state"] == "open"]
    key = flag("--json")
    assert flag("--jq", "").startswith("[.[] | .body") == (key == "body"), args
    if key == "number":
        assert flag("--jq") == '.[-1].number // "none"', args
        print(open_issues[-1]["number"] if open_issues else "none")
    elif key == "body":
        print("\\\\n".join(issue["body"] for issue in open_issues))
    else:
        raise AssertionError(args)
elif args[:2] == ["issue", "create"]:
    body = pathlib.Path(native(flag("--body-file"))).read_text()
    assert "FORK.md" in body and "upstream-sync:" in body, body
    issue = {"number": 7 + len(state["issues"]), "state": "open", "body": body}
    state["issues"].append(issue)
    save()
    print("https://github.com/mangyan1/NPMplus/issues/%d" % issue["number"])
elif args[:2] == ["issue", "edit"]:
    body = pathlib.Path(native(flag("--body-file"))).read_text()
    assert "FORK.md" in body and "upstream-sync:" in body, body
    body_of(args[2])["body"] = body
    save()
elif args[:2] == ["issue", "close"]:
    body_of(args[2])["state"] = "closed"
    save()
else:
    raise AssertionError(args)
'''.replace(chr(13) + chr(10), chr(10)), encoding="utf-8", newline=chr(10))
        gh.chmod(0o755)
        wrapper = binaries / "gh"
        wrapper.write_text("#!/bin/sh\nexec \"$GH_FAKE_PYTHON\" - \"$@\" <\"$GH_FAKE_IMPL\"\n",
                           encoding="utf-8", newline=chr(10))
        wrapper.chmod(0o755)
        self.env["GH_FAKE_PYTHON"] = sys.executable
        self.env["GH_FAKE_IMPL"] = str(gh)
        (self.root / "tmp").mkdir()
        self.env["TMPDIR"] = str(self.root / "tmp")
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
        self.upstream_tip = self.git("rev-parse", "upstream-fixture")
        self.git("switch", "develop")

    def push_upstream_edit(self, name, content):
        """One more upstream commit on top of upstream develop, as upstream pushing would."""
        self.git("switch", "-C", "upstream-next", "upstream-fixture")
        self.commit(name, content)
        self.git("push", str(self.upstream), "HEAD:develop")
        self.upstream_tip = self.git("rev-parse", "upstream-next")
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

    def published(self):
        """State-changing calls only: an issue report is not a published proposal."""
        return [call[:2] for call in self.calls() if tuple(call[:2]) in PUBLISHED]

    def reset_calls(self):
        (self.root / "gh.jsonl").unlink(missing_ok=True)

    def issues(self):
        return json.loads(self.state.read_text())["issues"] if self.state.exists() else []

    def seed_tracking_issue(self, body):
        self.state.write_text(json.dumps(
            {"labels": ["upstream-sync"], "issues": [{"number": 7, "state": "open", "body": body}]}
        ), encoding="utf-8")

    def proposal_tip(self):
        return self.git("ls-remote", "--heads", "origin", "refs/heads/automation/upstream-sync").split("\t")[0]

    def test_already_synced_does_not_publish(self):
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.published(), [])
        self.assertEqual(self.proposal_tip(), "")

    def test_clean_merge_preserves_both_sides_and_targets_fork(self):
        self.diverge()
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([call[:2] for call in self.calls() if call[:2][0] == "pr"], [["pr", "list"], ["pr", "create"]])
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
        self.assertEqual(len([call for call in self.calls() if call[:2][0] == "pr"]), 1)

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
        self.upstream_tip = self.git("rev-parse", "upstream-fixture")
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

    def test_upstream_edit_of_deleted_report_opens_no_proposal(self):
        # A modify/delete conflict must not produce a proposal; the only writes are the
        # blocked-merge bookkeeping.
        self.prepare_deleted_report(upstream_edits_report=True)
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proposal_tip(), "")
        self.assertNotIn(["pr", "create"], self.published())
        self.assertEqual(self.published(), [["label", "create"], ["issue", "create"]])
        self.assertFalse((self.work / "internal-review.md").exists())
        self.assertIn("internal-review.md", (self.root / "summary.md").read_text())

    def test_conflict_preserves_existing_proposal_and_aborts(self):
        self.diverge(conflict=True)
        self.git("push", "origin", "HEAD:automation/upstream-sync")
        old_tip = self.proposal_tip()
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(old_tip, self.proposal_tip())
        self.assertEqual(self.published(), [["label", "create"], ["issue", "create"]])
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertIn("shared.txt", (self.root / "summary.md").read_text())

    def test_concurrent_branch_creation_fails_the_lease(self):
        self.diverge()
        result = self.run_sync(GH_TEST_RACE=str(self.origin), GH_TEST_RACE_SHA=self.fork_tip)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proposal_tip(), self.fork_tip)
        self.assertEqual(len([call for call in self.calls() if call[:2][0] == "pr"]), 1)

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

    def test_pr_create_failure_does_not_resolve_the_tracking_issue(self):
        # The proposal is not live when `gh pr create` fails, so a tracking issue
        # must stay open.
        self.diverge()
        self.seed_tracking_issue("blocked by an earlier revision\nupstream-sync:deadbeefdeadbeef\n")
        result = self.run_sync(GH_TEST_CREATE_FAIL="1", GITHUB_EVENT_NAME="schedule")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual([call for call in self.published() if call[0] != "pr"], [])
        self.assertEqual(self.issues()[0]["state"], "open")

    def test_dirty_checkout_is_refused(self):
        (self.work / "operator.txt").write_text("keep me\n")
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing a dirty checkout", result.stdout)
        self.assertEqual((self.work / "operator.txt").read_text(), "keep me\n")

    # --- blocked-conflict reporting -------------------------------------------------
    #
    # The same conflict repeats on every scheduled run until a human lands a
    # reconciliation merge. A repeat must not notify again; only a change in the
    # blocked state (new upstream revision, new conflicted files) may report, and a
    # manual run always reports so debugging keeps its full signal.

    def test_first_conflict_opens_one_tracking_issue(self):
        self.diverge(conflict=True)
        result = self.run_sync(GITHUB_EVENT_NAME="schedule")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.published(), [["label", "create"], ["issue", "create"]])
        self.assertEqual(self.proposal_tip(), "")
        body = self.issues()[0]["body"]
        for needle in ("shared.txt", self.upstream_tip, "upstream-sync:", "FORK.md"):
            self.assertIn(needle, body)
        self.assertIn("::error", result.stdout)

    def test_identical_scheduled_conflict_is_not_reported_twice(self):
        self.diverge(conflict=True)
        first = self.run_sync(GITHUB_EVENT_NAME="schedule")
        self.assertNotEqual(first.returncode, 0, first.stdout)
        marker = [line for line in self.issues()[0]["body"].splitlines() if line.startswith("upstream-sync:")]
        self.assertEqual(len(marker), 1, self.issues()[0]["body"])
        self.reset_calls()
        second = self.run_sync(GITHUB_EVENT_NAME="schedule")
        self.assertEqual(second.returncode, 0, second.stdout)
        self.assertEqual(self.published(), [])
        self.assertEqual(len(self.issues()), 1)
        self.assertIn(marker[0], second.stdout + (self.root / "summary.md").read_text())

    def test_manual_run_reports_an_already_known_conflict(self):
        self.diverge(conflict=True)
        first = self.run_sync(GITHUB_EVENT_NAME="schedule")
        self.assertNotEqual(first.returncode, 0, first.stdout)
        self.reset_calls()
        (self.root / "summary.md").write_text("", encoding="utf-8")
        manual = self.run_sync(GITHUB_EVENT_NAME="workflow_dispatch")
        self.assertNotEqual(manual.returncode, 0, manual.stdout)
        self.assertEqual(self.published(), [["issue", "edit"]])
        self.assertEqual(len(self.issues()), 1)
        self.assertIn("::error", manual.stdout)

    def test_clean_merge_closes_the_tracking_issue(self):
        # A clean merge still proposes a PR for the new upstream revision, and it also
        # retires the stale blocked-merge issue.
        self.seed_tracking_issue("blocked by an earlier revision\nupstream-sync:deadbeefdeadbeef\n")
        self.diverge()
        result = self.run_sync(GITHUB_EVENT_NAME="schedule")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.published(), [["pr", "create"], ["issue", "close"]])
        self.assertEqual(self.issues()[0]["state"], "closed")

    def test_already_synced_closes_a_stale_tracking_issue(self):
        self.seed_tracking_issue("blocked by an earlier revision\nupstream-sync:deadbeefdeadbeef\n")
        result = self.run_sync(GITHUB_EVENT_NAME="schedule")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.published(), [["issue", "close"]])
        self.assertEqual(self.proposal_tip(), "")

    def test_tracking_issue_is_created_once_and_reused(self):
        self.diverge(conflict=True)
        first = self.run_sync(GITHUB_EVENT_NAME="workflow_dispatch")
        self.assertNotEqual(first.returncode, 0, first.stdout)
        self.assertEqual(self.published(), [["label", "create"], ["issue", "create"]])
        self.reset_calls()
        self.push_upstream_edit("shared.txt", "upstream behavior v2\n")
        second = self.run_sync(GITHUB_EVENT_NAME="workflow_dispatch")
        self.assertNotEqual(second.returncode, 0, second.stdout)
        self.assertEqual(self.published(), [["issue", "edit"]])
        self.assertEqual(len(self.issues()), 1)
        self.assertIn(self.upstream_tip, self.issues()[0]["body"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
