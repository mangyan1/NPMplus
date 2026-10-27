"""Keep automated dependency proposals from removing already integrated fixes."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == "posix", "workflow shell contracts run on Linux")
class ForwardUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fake_gh = self.root / "gh"
        fake_gh.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$@" > "$TEST_ARGUMENTS"\n'
            'printf "%s\\n" "$TEST_COMPARE_STATUS"\n'
            'exit "$TEST_COMPARE_EXIT"\n'
        )
        fake_gh.chmod(0o755)

    def compare(self, status, api_exit=0):
        arguments = self.root / "arguments"
        result = subprocess.run(
            [
                "bash",
                str(Path(__file__).resolve().parents[1] / ".github/scripts/check-forward-update.sh"),
                "crowdsecurity/lua-cs-bouncer",
                "a" * 40,
                "b" * 40,
            ],
            env={
                **os.environ,
                "PATH": f"{self.root}:{os.environ['PATH']}",
                "TEST_ARGUMENTS": str(arguments),
                "TEST_COMPARE_STATUS": status,
                "TEST_COMPARE_EXIT": str(api_exit),
            },
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            arguments.read_text().splitlines(),
            ["api", f"repos/crowdsecurity/lua-cs-bouncer/compare/{'a' * 40}...{'b' * 40}", "--jq", ".status"],
        )
        return result.returncode

    def test_newer_descendant_can_be_proposed(self):
        self.assertEqual(self.compare("ahead"), 0)

    def test_older_release_cannot_remove_a_fix(self):
        self.assertEqual(self.compare("behind"), 1)

    def test_identical_release_needs_no_proposal(self):
        self.assertEqual(self.compare("identical"), 1)

    def test_diverged_history_requires_review(self):
        self.assertEqual(self.compare("diverged"), 2)

    def test_unexpected_response_fails_closed(self):
        self.assertEqual(self.compare("null"), 2)

    def test_network_failure_is_not_a_successful_skip(self):
        self.assertEqual(self.compare("", api_exit=1), 2)


if __name__ == "__main__":
    unittest.main()
