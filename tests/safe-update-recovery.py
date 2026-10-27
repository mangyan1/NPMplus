"""Run the generated updater against disposable Linux files and fake host tools."""

import fcntl
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import tempfile
import time
import unittest


INSTALLER = (Path(__file__).resolve().parents[1] / "setup-npmplus.sh").read_text()
WRAPPER = re.search(r"write_root_file /usr/local/bin/npmplus-safe-update 700 <<'EOF'\n(.*?)\nEOF", INSTALLER, re.S).group(1)
PIN_IMAGE = re.search(r"^pin_image\(\).*?^}\n", INSTALLER, re.M | re.S).group()


class SafeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="npmplus-safe-update-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in ["opt/npmplus/npmplus", "opt/npmplus/access", "opt/npmplus/nginx/proxy_host", "opt/npmplus/crowdsec",
                     "var/backups/npmplus-last-good", "var/log", "run/lock", "etc/cron.d", "usr/local/bin", "usr/local/sbin", "bin"]:
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.data = self.root / "opt/npmplus"
        self.backup = self.root / "var/backups/npmplus-last-good"
        self.original = "services:\n  npmplus:\n    image: fixture@sha256:old\n"
        (self.data / "compose.yaml").write_text(self.original)
        (self.data / "access/proxy_host_1").write_text("original-auth")
        (self.data / "nginx/proxy_host/1.conf").write_text("original-nginx")
        (self.data / "npmplus/env.sha512sum").write_text("original-fingerprint")
        (self.data / "crowdsec/lapi-ui.key").write_text("original-bouncer-key")
        (self.data / "crowdsec/crowdsec.conf").write_text("APPSEC_FAILURE_ACTION=deny\nMODE=stream\n")
        with sqlite3.connect(self.data / "npmplus/database.sqlite") as db:
            db.execute("create table records (value text)")
            db.execute("insert into records values ('original')")
        (self.backup / "compose.yaml").write_text("previous-known-good-compose")
        (self.backup / "database.sqlite").write_text("previous-known-good-database")
        (self.backup / "keep-marker").write_text("previous-known-good-marker")
        self.previous = {p.name: p.read_bytes() for p in self.backup.iterdir()}
        self.write_tool("sleep", "#!/bin/sh\nexit 0\n")
        self.write_tool("timeout", """#!/bin/bash
if [[ ${1:-} == 3 && ${2:-} == bash ]]; then exit 0; fi
exec /usr/bin/timeout "$@"
""")
        self.write_tool("curl", '#!/bin/sh\nprintf \'{"status":"OK"}\\n\'\n')
        self.write_tool("systemctl", """#!/bin/bash
printf '%s\n' "$*" >>"$FIXTURE_ROOT/systemctl.calls"
exit 0
""")
        self.write_tool("iptables", "#!/bin/sh\nexit 1\n")
        self.write_tool("ip6tables", "#!/bin/sh\nexit 1\n")
        self.write_tool("docker", """#!/bin/bash
set -eu
printf '%s\n' "$*" >>"$FIXTURE_ROOT/docker.calls"
if [[ $1 == compose ]]; then
  case "$*" in
    *'config --services'*) echo npmplus ;;
    *'ps --status running --format'*) : ;;
    *'ps '*'-q npmplus'*) echo fixture ;;
    *'ps -q npmplus'*) echo fixture ;;
    *' down'*)
      if [[ $FIXTURE_CASE == bouncer-race && ! -f "$FIXTURE_ROOT/bouncer-stopped" ]]; then
        echo 'bouncer startup gate recreated CrowdSec during shutdown' >&2
        exit 15
      fi
      touch "$FIXTURE_ROOT/stopped" ;;
    *' up -d'*)
      [[ $FIXTURE_CASE != rollback-fails ]] || exit 7
      rm -f "$FIXTURE_ROOT/stopped"
      [[ $FIXTURE_CASE == rollback-unhealthy ]] || rm -f "$FIXTURE_ROOT/unhealthy"
      ;;
  esac
elif [[ $1 == inspect ]]; then
  case "$*" in
    *State.Status*) [[ -e "$FIXTURE_ROOT/stopped" ]] && echo exited || echo running ;;
    *State.Health*) [[ -e "$FIXTURE_ROOT/unhealthy" ]] && echo unhealthy || echo healthy ;;
    *.Image*) [[ $FIXTURE_CASE != lost-image ]] || exit 4; echo sha256:old ;;
  esac
elif [[ $1 == exec ]]; then
  [[ $FIXTURE_CASE != snapshot-fails ]] || exit 6
  python3 - <<'PY'
import os, sqlite3
from pathlib import Path
root = Path(os.environ['FIXTURE_ROOT']) / 'opt/npmplus/npmplus'
with sqlite3.connect(root / 'database.sqlite') as source, sqlite3.connect(root / 'database.pre-update.sqlite') as destination:
    source.backup(destination)
PY
fi
""")
        self.write_tool("mv", """#!/bin/bash
if [[ $FIXTURE_CASE == promote-fails && ${2:-} == */npmplus-update.* && ${3:-} == */npmplus-last-good ]]; then exit 8; fi
exec /bin/mv "$@"
""")
        setup = self.data / "setup-npmplus.sh"
        setup.write_text("""#!/bin/bash
# SCRIPT_VERSION="1.71"
set -eu
printf '%s\n' "$$" >"$FIXTURE_ROOT/deployment-child.pid"
if [[ $FIXTURE_CASE == success ]]; then
  python3 - <<'PY'
import os, sqlite3
with sqlite3.connect(os.environ['FIXTURE_ROOT'] + '/opt/npmplus/npmplus/database.sqlite') as db:
    db.execute("insert into records values ('updated')")
PY
  exit 0
fi
printf '# changed by failed update\n' >>"$FIXTURE_ROOT/opt/npmplus/compose.yaml"
printf 'corrupt' >"$FIXTURE_ROOT/opt/npmplus/npmplus/database.sqlite"
printf 'changed-auth' >"$FIXTURE_ROOT/opt/npmplus/access/proxy_host_1"
printf 'changed-nginx' >"$FIXTURE_ROOT/opt/npmplus/nginx/proxy_host/1.conf"
printf 'changed-fingerprint' >"$FIXTURE_ROOT/opt/npmplus/npmplus/env.sha512sum"
printf 'changed-key' >"$FIXTURE_ROOT/opt/npmplus/crowdsec/lapi-ui.key"
printf 'APPSEC_FAILURE_ACTION=passthrough\nMODE=live\n' >"$FIXTURE_ROOT/opt/npmplus/crowdsec/crowdsec.conf"
touch "$FIXTURE_ROOT/deployment-started" "$FIXTURE_ROOT/unhealthy"
if [[ $FIXTURE_CASE == interrupt || $FIXTURE_CASE == timeout ]]; then
  trap '' TERM
  /bin/sleep 30
  printf 'late-corruption' >"$FIXTURE_ROOT/opt/npmplus/npmplus/database.sqlite"
fi
[[ $FIXTURE_CASE != post-health-fails ]] || exit 0
exit 42
""")
        setup.chmod(0o700)
        code = re.sub(r"(?<![\w}$])/(opt|var|run|etc|usr/local)/", lambda m: str(self.root) + m.group(), WRAPPER)
        code = code.replace("-C / ", f"-C '{self.root}' ")
        self.script = self.root / "wrapper.sh"
        self.script.write_text(code)

    def write_tool(self, name, code):
        path = self.root / "bin" / name
        path.write_text(code)
        path.chmod(0o755)

    def run_wrapper(self, case="failure", interrupt=None, close_output=False):
        env = {**os.environ, "PATH": str(self.root / "bin") + ":" + os.environ["PATH"], "FIXTURE_ROOT": str(self.root),
               "FIXTURE_CASE": case, "NPMPLUS_UPDATE_TIMEOUT_SECONDS": "1" if case == "timeout" else "20",
               "NPMPLUS_RECOVERY_TIMEOUT_SECONDS": "1"}
        log = (self.root / "run.log").open("w+")
        process = subprocess.Popen(["bash", str(self.script)], env=env, stdout=subprocess.PIPE if close_output else log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            if interrupt:
                deadline = time.monotonic() + 5
                while not (self.root / "deployment-started").exists() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertTrue((self.root / "deployment-started").exists(), self.output(log))
                if close_output:
                    process.stdout.close()
                os.kill(process.pid, interrupt)
            process.wait(timeout=18)
            diagnostics = "\n".join(p.read_text() for p in (self.root / "var/log").glob("npmplus-update.*/progress.log"))
            return process.returncode, self.output(log) + diagnostics
        finally:
            # Only this test's isolated process groups may be stopped.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            log.close()

    @staticmethod
    def output(log):
        log.flush()
        return Path(log.name).read_text()

    def assert_restored(self):
        self.assertEqual((self.data / "compose.yaml").read_text(), self.original)
        with sqlite3.connect(self.data / "npmplus/database.sqlite") as db:
            self.assertEqual(db.execute("select value from records").fetchall(), [("original",)])
        for name, expected in [("access/proxy_host_1", "original-auth"), ("nginx/proxy_host/1.conf", "original-nginx"),
                               ("npmplus/env.sha512sum", "original-fingerprint"), ("crowdsec/lapi-ui.key", "original-bouncer-key"),
                               ("crowdsec/crowdsec.conf", "APPSEC_FAILURE_ACTION=deny\nMODE=stream\n")]:
            self.assertEqual((self.data / name).read_text(), expected, name)
        self.assertFalse((self.root / "stopped").exists())
        pidfile = self.root / "deployment-child.pid"
        if pidfile.exists():
            stat = Path("/proc") / pidfile.read_text().strip() / "stat"
            if stat.exists():
                self.assertEqual(stat.read_text().split()[2], "Z", "deployment writer survived rollback")

    def assert_previous_snapshot(self):
        self.assertEqual({p.name: p.read_bytes() for p in self.backup.iterdir()}, self.previous)
        self.assertFalse((self.root / "deployment-started").exists())

    def test_unhealthy_preflight_preserves_every_previous_snapshot_file(self):
        (self.root / "unhealthy").touch()
        code, output = self.run_wrapper()
        self.assertNotEqual(code, 0, output)
        self.assert_previous_snapshot()

    def test_incomplete_snapshot_keeps_previous_known_good(self):
        code, output = self.run_wrapper("snapshot-fails")
        self.assertNotEqual(code, 0, output)
        self.assert_previous_snapshot()

    def test_failed_firewall_enforcement_preserves_the_previous_snapshot(self):
        marker = self.root / "var/lib/npmplus/installed-firewall-bouncer"
        marker.parent.mkdir(parents=True)
        marker.touch()
        self.write_tool("systemctl", "#!/bin/sh\nexit 1\n")
        code, output = self.run_wrapper()
        self.assertNotEqual(code, 0, output)
        self.assertIn("pre-update check failed", output)
        self.assert_previous_snapshot()

    def test_lost_image_aborts_without_promoting_an_incomplete_snapshot(self):
        code, output = self.run_wrapper("lost-image")
        self.assertNotEqual(code, 0, output)
        self.assert_previous_snapshot()

    def test_failed_helper_copy_cannot_promote_an_incomplete_snapshot(self):
        (self.root / "usr/local/bin/npmplus-backup").write_text("original-backup-helper")
        self.write_tool("cp", '''#!/bin/bash
if [[ $* == *usr/local/bin/npmplus-backup* ]]; then exit 9; fi
exec /bin/cp "$@"
''')
        code, output = self.run_wrapper()
        self.assertNotEqual(code, 0, output)
        self.assert_previous_snapshot()

    def test_failed_snapshot_promotion_restores_the_previous_directory(self):
        code, output = self.run_wrapper("promote-fails")
        self.assertNotEqual(code, 0, output)
        self.assert_previous_snapshot()

    def test_a_second_maintenance_job_cannot_change_any_snapshot(self):
        with (self.root / "run/lock/npmplus-maintenance.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, output = self.run_wrapper()
        self.assertNotEqual(code, 0, output)
        self.assert_previous_snapshot()

    def test_failed_startup_restores_database_configs_and_credentials(self):
        code, output = self.run_wrapper()
        self.assertNotEqual(code, 0, output)
        self.assert_restored()
        self.assertIn("reverted - failure diagnostics are in", output)

    def test_bouncer_activation_cannot_race_with_database_restoration(self):
        marker = self.root / "var/lib/npmplus/installed-firewall-bouncer"
        marker.parent.mkdir(parents=True)
        marker.touch()
        self.write_tool("systemctl", '''#!/bin/bash
printf '%s\\n' "$*" >>"$FIXTURE_ROOT/systemctl.calls"
if [[ $* == 'stop crowdsec-firewall-bouncer.service' ]]; then touch "$FIXTURE_ROOT/bouncer-stopped"; fi
''')
        self.write_tool("iptables-save", '''#!/bin/sh
echo '-A INPUT -m set --match-set crowdsec-blacklists src -j DROP'
echo '-A FORWARD -m set --match-set crowdsec-blacklists src -j DROP'
''')
        code, output = self.run_wrapper("bouncer-race")
        self.assertNotEqual(code, 0, output)
        self.assert_restored()
        self.assertIn("reverted - failure diagnostics are in", output)

    def test_ctrl_c_restores_state_and_stops_the_deployment_child(self):
        code, output = self.run_wrapper("interrupt", signal.SIGINT)
        self.assertNotEqual(code, 0, output)
        self.assert_restored()
        time.sleep(0.2)
        self.assert_restored()

    def test_sigterm_restores_state_and_stops_the_deployment_child(self):
        code, output = self.run_wrapper("interrupt", signal.SIGTERM)
        self.assertNotEqual(code, 0, output)
        self.assert_restored()

    def test_ssh_disconnect_restores_state_and_stops_the_deployment_child(self):
        code, output = self.run_wrapper("interrupt", signal.SIGHUP)
        self.assertNotEqual(code, 0, output)
        self.assert_restored()

    def test_closed_terminal_output_does_not_abort_recovery(self):
        code, output = self.run_wrapper("interrupt", signal.SIGINT, close_output=True)
        self.assertNotEqual(code, 0, output)
        self.assert_restored()
        self.assertIn("reverted - failure diagnostics are in", output)

    def test_a_stalled_deployment_times_out_and_rolls_back(self):
        code, output = self.run_wrapper("timeout")
        self.assertNotEqual(code, 0, output)
        self.assert_restored()

    def test_failed_rollback_never_reports_success(self):
        code, output = self.run_wrapper("rollback-fails")
        self.assertNotEqual(code, 0, output)
        self.assertNotIn("reverted - failure diagnostics are in", output)
        self.assertIn("rollback FAILED", output)

    def test_unhealthy_restored_service_never_reports_success(self):
        code, output = self.run_wrapper("rollback-unhealthy")
        self.assertNotEqual(code, 0, output)
        self.assertNotIn("reverted - failure diagnostics are in", output)
        self.assertIn("rollback FAILED", output)

    def test_post_deployment_health_failure_restores_the_snapshot(self):
        code, output = self.run_wrapper("post-health-fails")
        self.assertNotEqual(code, 0, output)
        self.assert_restored()

    def test_healthy_update_commits_a_complete_rollback_snapshot(self):
        code, output = self.run_wrapper("success")
        self.assertEqual(code, 0, output)
        self.assertIn("update healthy - last good snapshot kept", output)
        self.assertTrue((self.backup / "complete").is_file())
        self.assertEqual((self.backup / "compose.yaml").read_text(), self.original)
        with sqlite3.connect(self.data / "npmplus/database.sqlite") as db:
            self.assertEqual(db.execute("select value from records").fetchall(), [("original",), ("updated",)])
        with sqlite3.connect(self.backup / "database.sqlite") as db:
            self.assertEqual(db.execute("select value from records").fetchall(), [("original",)])

    def test_registry_progress_cannot_become_part_of_the_pinned_image_reference(self):
        digest = "sha256:" + "1" * 64
        stub = f'''docker() {{
  if [[ $1 == pull ]]; then printf 'Downloading layer progress\\n';
  else printf 'ghcr.io/mangyan1/npmplus@{digest}\\n'; fi
}}
'''
        result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + stub + PIN_IMAGE +
                                 '\nimage=$(pin_image ghcr.io/mangyan1/npmplus:develop)\nprintf "%s" "$image"\n'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ghcr.io/mangyan1/npmplus:develop@" + digest)
        self.assertIn("Downloading layer progress", result.stderr)

    def test_failed_pull_cannot_produce_a_pinned_image(self):
        result = subprocess.run(["bash", "-c", "set -euo pipefail\ndocker() { return 4; }\n" + PIN_IMAGE +
                                 '\nimage=$(pin_image ghcr.io/mangyan1/npmplus:develop)\nprintf "%s" "$image"\n'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
