"""Exercise the daily heal script's fail-open posture migration in a temporary layout.

Run with Python 3 on Linux (bash required). No daemon, root access, network, or
real /opt data is used. The shell fragment comes from the installer's generated
npmplus-crowdsec-heal script.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


INSTALLER = (Path(__file__).resolve().parents[1] / "setup-npmplus.sh").read_text()
HEAL = re.search(
	r"write_root_file /usr/local/bin/npmplus-crowdsec-heal 755 <<'EOF'\n(.*?)\nEOF\n",
	INSTALLER,
	re.S,
).group(1)

CONF_LIVE = """ENABLED=true
API_URL=http://127.0.0.1:8080
API_KEY=fixture-key
MODE=live
APPSEC_URL={appsec_url}
APPSEC_FAILURE_ACTION={action}
"""


class HealMigrationTests(unittest.TestCase):
	def setUp(self):
		self.temp = tempfile.TemporaryDirectory(prefix="npmplus-heal-")
		self.addCleanup(self.temp.cleanup)
		self.root = Path(self.temp.name)
		self.data = self.root / "opt/npmplus/crowdsec"
		self.data.mkdir(parents=True)
		(self.root / "var/log").mkdir(parents=True)
		# byte-exact fixtures: text-mode writes translate newlines on Windows
		# and grep '$'-anchored patterns stop matching the conf
		(self.root / "opt/npmplus/compose.yaml").write_bytes(b"services:\n  npmplus:\n    image: test\n")
		(self.data / "lapi-ui.key").write_bytes(b"fixture-ui-key\n")
		(self.data / "lapi-ui-machine.key").write_bytes(b"fixture-machine-key\n")

	def write_conf(self, *, appsec_url="http://172.21.0.2:7422", action="passthrough", mode="live"):
		self.data.joinpath("crowdsec.conf").write_bytes(
			CONF_LIVE.format(appsec_url=appsec_url, action=action).replace("MODE=live", f"MODE={mode}").encode()
		)

	def heal(self, **env):
		# Rewrite only absolute host paths; the fixtures keep their opt/... shape.
		# as_posix keeps Windows fixture roots free of backslashes, which bash
		# would otherwise eat as escapes inside the generated code.
		code = re.sub(r"(?<![\w}$])/(opt|var|run|etc)/", lambda match: self.root.as_posix() + match.group(), HEAL)
		stub = r'''
set -uo pipefail
sleep() { :; }
dpkg-query() { echo "unknown ok not-installed"; }
systemctl() { return 0; }
iptables-save() { return 1; }
curl() {
  case "$*" in
    *'watchers/login'*) echo 200 ;;
    *) echo 200 ;;
  esac
}
docker() {
  echo "$*" >>"$FIXTURE_ROOT/docker.calls"
  case "$*" in
    'ps --format {{.Names}}') echo crowdsec ;;
    *) return 0 ;;
  esac
}
'''
		return subprocess.run(
			["bash", "-c", stub + code],
			env={**os.environ, "FIXTURE_ROOT": self.root.as_posix(), **env},
			text=True,
			capture_output=True,
			timeout=20,
		)

	def conf(self):
		return (self.data / "crowdsec.conf").read_text()

	def calls(self):
		path = self.root / "docker.calls"
		return path.read_text() if path.exists() else ""

	def test_live_and_wired_passthrough_migrate_and_restart(self):
		self.write_conf()
		result = self.heal()
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertIn("MODE=stream", self.conf())
		self.assertIn("APPSEC_FAILURE_ACTION=deny", self.conf())
		self.assertIn("restart npmplus", self.calls())
		self.assertIn("migrated fail-open posture: mode=live->stream appsec=passthrough->deny", self.heal_log())

	def test_keep_fail_open_marker_disables_the_migration(self):
		self.write_conf()
		(self.data / "keep-fail-open").write_text("")
		result = self.heal()
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertIn("MODE=live", self.conf())
		self.assertIn("APPSEC_FAILURE_ACTION=passthrough", self.conf())
		self.assertNotIn("restart npmplus", self.calls())

	def test_passthrough_without_a_wired_appsec_keeps_only_the_mode_migration(self):
		self.write_conf(appsec_url="", action="passthrough")
		result = self.heal()
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertIn("MODE=stream", self.conf())
		self.assertIn("APPSEC_FAILURE_ACTION=passthrough", self.conf())
		self.assertIn("restart npmplus", self.calls())
		self.assertIn("migrated fail-open posture: mode=live->stream", self.heal_log())
		self.assertNotIn("appsec=passthrough->deny", self.heal_log())

	def test_an_already_fail_closed_conf_is_untouched(self):
		self.write_conf(action="deny", mode="stream")
		result = self.heal()
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertNotIn("restart npmplus", self.calls())
		self.assertNotIn("migrated", self.heal_log())

	def heal_log(self):
		path = self.root / "var/log/npmplus-crowdsec-heal.log"
		return path.read_text() if path.exists() else ""


if __name__ == "__main__":
	unittest.main(verbosity=2)