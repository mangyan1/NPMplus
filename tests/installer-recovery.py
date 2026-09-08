"""Exercise installer recovery code in a temporary host layout with fake Docker.

Run with Python 3 on Linux (bash, tar and flock required). No daemon, root access,
network, or real /opt data is used. The shell fragments come from the installer.
"""

import os
from contextlib import closing
from pathlib import Path
import re
import sqlite3
import socket
import subprocess
import tarfile
import tempfile
import unittest


INSTALLER = (Path(__file__).resolve().parents[1] / "setup-npmplus.sh").read_text()
RESTORE = re.search(r"^run_restore\(\) \(\n.*?^\)\n", INSTALLER, re.M | re.S).group()
BACKUP = re.search(r"write_root_file /usr/local/bin/npmplus-backup 755 <<'EOF'\n(.*?)\nEOF", INSTALLER, re.S).group(1)
ENFORCEMENT = re.search(r"write_root_file /usr/local/bin/npmplus-collect-enforcement 755 <<'EOF'\n(.*?)\nEOF", INSTALLER, re.S).group(1)
HONEYPOT = re.search(r"write_root_file /usr/local/bin/anubis-honeypot-ban 755 <<'EOF'\n(.*?)\nEOF", INSTALLER, re.S).group(1)
ANUBIS = re.search(r"write_root_file /usr/local/bin/npmplus-collect-anubis 755 <<'EOF'\n(.*?)\nEOF", INSTALLER, re.S).group(1)


class RecoveryTests(unittest.TestCase):
    def test_honeypot_bridge_detects_reset_and_regrowth_beyond_old_cursor(self):
        directory = self.root / "opt/anubis-data/anubis"
        directory.mkdir(parents=True)
        log = directory / "honeypot.addrs"
        stub = 'docker() { echo "$*" >>"$FIXTURE_ROOT/ban.calls"; }\n'
        log.write_text("203.0.113.1\n")
        self.assertEqual(self.shell(stub + HONEYPOT).returncode, 0)
        log.write_text("2001:db8::1234\n")
        result = self.shell(stub + HONEYPOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2001:db8::1234", (self.root / "ban.calls").read_text())

    def test_anubis_metrics_are_bounded_private_and_preserved_after_failed_fetch(self):
        directory = self.root / "opt/anubis-data/anubis"
        directory.mkdir(parents=True)
        stub = '''
docker() { printf '172.21.0.8\\n'; }
curl() {
 printf '%s\\n' "$*" >"$FIXTURE_ROOT/curl.args"
 [[ "${FAIL_METRICS:-0}" == 0 ]] || return 22
 printf 'process_start_time_seconds 1000\\n'
}
'''
        result = self.shell(stub + ANUBIS)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = directory / "anubis-metrics.prom"
        self.assertIn("process_start_time_seconds", output.read_text())
        arguments = (self.root / "curl.args").read_text()
        self.assertIn("--max-filesize 524288", arguments)
        self.assertIn("http://172.21.0.8:9090/metrics", arguments)
        self.assertNotIn("127.0.0.1:9090:9090", INSTALLER)
        result = self.shell(stub + ANUBIS, FAIL_METRICS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("process_start_time_seconds", output.read_text())
        self.assertEqual(list(directory.glob("anubis-metrics.*")), [output])

    def test_honeypot_failures_retry_without_replaying_successful_prefix(self):
        import json
        directory = self.root / "opt/anubis-data/anubis"
        directory.mkdir(parents=True)
        log = directory / "honeypot.addrs"
        first = "203.0.113.1\n"
        log.write_text(first + "2001:db8::1\n")
        stub = '''
docker() {
 echo "$*" >>"$FIXTURE_ROOT/ban.calls"
 [[ "$*" != *2001:db8* || "${FAIL_BAN:-0}" == 0 ]]
}
'''
        failed = self.shell(stub + HONEYPOT, FAIL_BAN="1")
        self.assertNotEqual(failed.returncode, 0, failed.stderr)
        cursor = self.root / "opt/anubis-data/anubis-honeypot.pos"
        self.assertEqual(int(cursor.read_text()), len(first))
        status = json.loads((directory / "honeypot-bridge.json").read_text())
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["applied"], 1)
        self.assertEqual(status["failed"], 1)
        retried = self.shell(stub + HONEYPOT)
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertEqual(int(cursor.read_text()), log.stat().st_size)
        calls = (self.root / "ban.calls").read_text()
        self.assertEqual(calls.count("203.0.113.1"), 1)
        self.assertEqual(calls.count("2001:db8::1"), 2)
        journal = (directory / "honeypot-attempts.log").read_text()
        self.assertEqual(len(journal.splitlines()), 3)
        self.assertIn("failed 2001:db8::1", journal)
        self.assertIn("accepted 2001:db8::1", journal)

    def test_honeypot_keeps_partial_lines_pending_and_refuses_a_held_lock(self):
        directory = self.root / "opt/anubis-data/anubis"
        directory.mkdir(parents=True)
        log = directory / "honeypot.addrs"
        log.write_text("203.0.113.1")
        result = self.shell(HONEYPOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        cursor = self.root / "opt/anubis-data/anubis-honeypot.pos"
        self.assertEqual(int(cursor.read_text()), 0)
        log.write_text("203.0.113.1\n")
        locked = self.shell('exec 7>/run/lock/anubis-honeypot-ban.lock\nflock -n 7\n' + HONEYPOT)
        self.assertEqual(locked.returncode, 0, locked.stderr)
        self.assertEqual(int(cursor.read_text()), 0)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="npmplus-recovery-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "opt/npmplus"
        for item in ("npmplus", "access", "html", "tls", "nginx"):
            (self.data / item).mkdir(parents=True, exist_ok=True)
        for item in ("run/lock", "var/log", "var/backups/npmplus"):
            (self.root / item).mkdir(parents=True, exist_ok=True)
        (self.data / "compose.yaml").write_text("services:\n  npmplus:\n    image: test\n")
        self.database(self.data / "npmplus/database.sqlite", "original")
        (self.data / "access/1").write_text("original-auth")
        (self.data / "html/index.html").write_text("original-html")
        (self.data / "tls/certificate").write_text("original-cert")
        incoming = self.root / "incoming/opt/npmplus"
        for item in ("npmplus", "access", "html", "tls"):
            (incoming / item).mkdir(parents=True, exist_ok=True)
        self.database(incoming / "npmplus/database.backup.sqlite", "restored")
        (incoming / "access/1").write_text("restored-auth")
        (incoming / "html/index.html").write_text("restored-html")
        (incoming / "tls/certificate").write_text("restored-cert")
        self.archive = self.root / "backup.tar.gz"
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(incoming, arcname="opt/npmplus")

    @staticmethod
    def database(filename, value):
        with closing(sqlite3.connect(filename)) as db:
            db.execute("create table records (value text)")
            db.execute("insert into records values (?)", (value,))
            db.commit()

    def rows(self, filename=None):
        with closing(sqlite3.connect(filename or self.data / "npmplus/database.sqlite")) as db:
            return [row[0] for row in db.execute("select value from records")]

    def shell(self, code, **env):
        # Rewrite only absolute host paths; archive members remain opt/...
        code = re.sub(r"(?<![\w}$])/(opt|var|run|etc)/", lambda match: str(self.root) + match.group(), code)
        code = code.replace("-C / ", f"-C '{self.root}' ")
        stub = r'''
set -euo pipefail
say() { printf '%s\n' "$*"; }
ask() { echo restore; }
sleep() { :; }
docker() {
  echo "$*" >>"$FIXTURE_ROOT/docker.calls"
  case "$*" in
    *'config --services'*) echo npmplus ;;
    *'port npmplus 443'*) return 1 ;;
    *' stop'*) touch "$FIXTURE_ROOT/stopped" ;;
    *' up -d'*)
      if [[ -f "$FIXTURE_ROOT/fail-up-once" ]]; then
        rm "$FIXTURE_ROOT/fail-up-once"; return 1
      fi ;;
    inspect*) echo "${CONTAINER_HEALTH:-healthy}" ;;
    'exec npmplus curl'*) echo '{"status":"OK"}' ;;
    'exec npmplus node'*)
      [[ "${FAIL_ONLINE_BACKUP:-0}" == 0 ]] || return 1
      command cp "$FIXTURE_ROOT/opt/npmplus/npmplus/database.sqlite" "$FIXTURE_ROOT/opt/npmplus/npmplus/database.backup.sqlite" ;;
    *) return 1 ;;
  esac
}
cp() {
  if [[ "${FAIL_SNAPSHOT:-0}" == 1 && "$*" == *pre-restore-*/data/npmplus ]]; then return 1; fi
  if [[ "${FAIL_APPLY:-0}" == 1 && "$*" == *extract*database.backup.sqlite* ]]; then
    printf broken >"$FIXTURE_ROOT/opt/npmplus/npmplus/database.sqlite"; return 1
  fi
  # Quiescence must precede every pre-restore copy.
  if [[ "$*" == *pre-restore-* && "$*" != *extract* && ! -f "$FIXTURE_ROOT/stopped" ]]; then return 1; fi
  command cp "$@"
}
'''
        full = stub + code
        return subprocess.run(["bash", "-c", full], env={**os.environ, "FIXTURE_ROOT": str(self.root), **env}, text=True, capture_output=True, timeout=20)

    def restore(self, **env):
        return self.shell(RESTORE + '\nDATA_DIR="/opt/npmplus"\nCROWDSEC_DIR="/opt/crowdsec"\nCOMPOSE_FILE="$DATA_DIR/compose.yaml"\nrun_restore "$FIXTURE_ROOT/backup.tar.gz"\n', **env)

    def test_restore_recovers_database_access_files_html_and_certificates(self):
        result = self.restore()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.rows(), ["restored"])
        self.assertEqual((self.data / "access/1").read_text(), "restored-auth")
        self.assertEqual((self.data / "html/index.html").read_text(), "restored-html")
        self.assertEqual((self.data / "tls/certificate").read_text(), "restored-cert")
        snapshot = next((self.root / "var/backups/npmplus").glob("pre-restore-*/data/npmplus/database.sqlite"))
        self.assertEqual(self.rows(snapshot), ["original"])

    def test_snapshot_failure_does_not_replace_the_original_state(self):
        result = self.restore(FAIL_SNAPSHOT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rows(), ["original"])
        self.assertEqual((self.data / "access/1").read_text(), "original-auth")
        self.assertIn("up -d", (self.root / "docker.calls").read_text())

    def test_snapshot_preserves_commits_only_present_in_wal(self):
        # Simulate an uncleanly stopped SQLite writer: committed pages remain
        # in WAL rather than the main file. The snapshot must retain them.
        subprocess.run(["python3", "-c", "import os, sqlite3, sys; db=sqlite3.connect(sys.argv[1]); db.execute('pragma journal_mode=wal'); db.execute(\"insert into records values ('wal-commit')\"); db.commit(); os._exit(0)", str(self.data / "npmplus/database.sqlite")], check=True)
        self.assertTrue((self.data / "npmplus/database.sqlite-wal").exists())
        result = self.restore()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        snapshot = next((self.root / "var/backups/npmplus").glob("pre-restore-*/data/npmplus/database.sqlite"))
        self.assertEqual(self.rows(snapshot), ["original", "wal-commit"])

    def test_public_health_accepts_a_denying_listener_but_rejects_no_listener(self):
        probe = "timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/443'"
        self.assertEqual(INSTALLER.count(probe), 4)
        # A listener that never sends an HTTP success is a supported default
        # vhost policy. Admin API and packet-enforcement checks remain separate.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            code = probe.replace("/443", f"/{port}")
            self.assertEqual(self.shell(code).returncode, 0)
        self.assertNotEqual(self.shell(code).returncode, 0)

    def test_copy_failure_recovers_the_original_database(self):
        result = self.restore(FAIL_APPLY="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rows(), ["original"])

    def test_start_failure_recovers_all_replaced_payloads(self):
        (self.root / "fail-up-once").touch()
        result = self.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rows(), ["original"])
        self.assertEqual((self.data / "access/1").read_text(), "original-auth")
        self.assertEqual((self.data / "tls/certificate").read_text(), "original-cert")

    def test_running_but_unhealthy_container_does_not_complete_restore(self):
        result = self.restore(CONTAINER_HEALTH="unhealthy")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rows(), ["original"])

    def test_restore_refuses_an_existing_maintenance_lock(self):
        import fcntl
        with (self.root / "run/lock/npmplus-maintenance.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.restore()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another NPMplus maintenance job", result.stderr)
        self.assertFalse((self.root / "stopped").exists())

    def test_backup_succeeds_without_crowdsec(self):
        result = self.shell(BACKUP)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + (self.root / "var/log/npmplus-backup.log").read_text())
        archive = next((self.root / "var/backups/npmplus").glob("npmplus-*.tar.gz"))
        with tarfile.open(archive) as archive_file:
            self.assertIn("opt/npmplus/npmplus/database.backup.sqlite", archive_file.getnames())

    def test_firewall_helper_publishes_only_matching_ipv4_drop_counters(self):
        import json
        marker = self.root / "var/lib/npmplus/installed-firewall-bouncer"
        marker.parent.mkdir(parents=True)
        marker.touch()
        (self.data / "crowdsec").mkdir()
        stubs = '''
systemctl() { [[ "$1" != show ]] || echo abcdef; }
iptables-save() { cat <<'RULES'
[12:600] -A INPUT -m set --match-set crowdsec-blacklists src -j DROP
[23:1200] -A FORWARD -m set --match-set crowdsec-blacklists src -j DROP
[99:9999] -A INPUT -m set --match-set unrelated src -j DROP
[55:5500] -A INPUT -m set --match-set crowdsec-blacklists src -j ACCEPT
RULES
}
'''
        result = self.shell(stubs + ENFORCEMENT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads((self.data / "crowdsec/firewall-telemetry.json").read_text())
        self.assertEqual(data["counters"], {"input_packets": 12, "forward_packets": 23, "input_bytes": 600, "forward_bytes": 1200})
        self.assertTrue(data["input_rule"] and data["forward_rule"] and data["service_active"])

    def test_failed_online_backup_never_archives_a_stale_copy(self):
        (self.data / "npmplus/database.backup.sqlite").write_text("stale")
        result = self.shell(BACKUP, FAIL_ONLINE_BACKUP="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.data / "npmplus/database.backup.sqlite").exists())
        self.assertFalse(list((self.root / "var/backups/npmplus").glob("npmplus-*.tar.gz")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
