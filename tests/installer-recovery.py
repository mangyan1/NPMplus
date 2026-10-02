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
    def test_anubis_policy_uses_the_pinned_images_validated_source(self):
        metadata = re.search(r"^read_anubis_image_metadata\(\).*?^}\n", INSTALLER, re.M | re.S).group()
        policy = re.search(r"^anubis_policy\(\).*?^}\n", INSTALLER, re.M | re.S).group()
        stub = '''
docker() {
 case "$*" in
  *org.opencontainers.image.version*) printf '%s\\n' "$FIXTURE_VERSION" ;;
  *io.npmplus.upstream.revision*) printf '%s\\n' "$FIXTURE_REVISION" ;;
  *) return 1 ;;
 esac
}
fetch() {
 printf '%s\\n' "$1" >"$FIXTURE_ROOT/policy-url"
 printf 'bots: []\\nstatus_codes:\\n  CHALLENGE: 200\\n  DENY: 200\\nstore:\\n  backend: memory\\n  parameters: {}\\nhoneypot:\\n  implementation: naive\\n' >"$3"
}
'''
        code = stub + metadata + policy + '\nread_anubis_image_metadata fake@sha256:fixed\nanubis_policy "$ANUBIS_VERSION" n "$ANUBIS_SOURCE_REVISION"\n'
        valid = {"FIXTURE_VERSION": "v1.27.0-mangyan1.security.1", "FIXTURE_REVISION": "d39e26cedcc96bea5e4915297c756e7eec74aaf7"}
        result = self.shell(code, **valid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "policy-url").read_text().strip(), "https://raw.githubusercontent.com/TecharoHQ/anubis/" + valid["FIXTURE_REVISION"] + "/data/botPolicies.yaml")
        self.assertIn("CHALLENGE: 401", (self.root / "opt/anubis.yaml").read_text())
        self.assertIn("backend: bbolt", (self.root / "opt/anubis.yaml").read_text())
        for version, revision in [("v1.27.0", valid["FIXTURE_REVISION"]), ("v1.27.0-mangyan1.security.1", "main")]:
            with self.subTest(version=version, revision=revision):
                (self.root / "policy-url").unlink(missing_ok=True)
                result = self.shell(code, FIXTURE_VERSION=version, FIXTURE_REVISION=revision)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / "policy-url").exists())

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
    inspect*)
      if [[ "$*" == *'.Image'* ]]; then printf 'sha256:%064d\n' 0
      else echo "${CONTAINER_HEALTH:-healthy}"; fi ;;
    'exec npmplus curl'*) echo '{"status":"OK"}' ;;
    'exec npmplus node'*)
      [[ "${FAIL_ONLINE_BACKUP:-0}" == 0 ]] || return 1
      command cp "$FIXTURE_ROOT/opt/npmplus/npmplus/database.sqlite" "$FIXTURE_ROOT/opt/npmplus/npmplus/database.backup.sqlite" ;;
    run*)
      if [[ "$*" == *'dst=/backup.tar.gz,readonly'* ]]; then
        local archive="" mount
        for mount in "$@"; do
          if [[ "$mount" == type=bind,src=*,dst=/backup.tar.gz,readonly ]]; then archive="${mount#type=bind,src=}"; archive="${archive%,dst=/backup.tar.gz,readonly}"; fi
        done
        python3 - "$archive"
        return
      fi
      [[ "${FAIL_CROWDSEC_BACKUP:-0}" == 0 ]] || return 1
      local snapshot="" arg
      for arg in "$@"; do
        if [[ "$arg" == *'dst=/snapshot' ]]; then snapshot="${arg#type=bind,src=}"; snapshot="${snapshot%,dst=/snapshot}"; fi
      done
      [[ -n "$snapshot" ]] || return 1
      python3 - "$FIXTURE_ROOT/opt/crowdsec/data/crowdsec.db" "$snapshot/crowdsec.backup.db" <<'PYTHON'
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True)) as source:
    with closing(sqlite3.connect(sys.argv[2])) as destination:
        source.backup(destination)
        destination.execute('pragma journal_mode=delete')
PYTHON
      ;;
    *) return 1 ;;
  esac
}
cp() {
  if [[ "${FAIL_SNAPSHOT:-0}" == 1 && "$*" == *pre-restore-*/data/npmplus ]]; then return 1; fi
  if [[ "${FAIL_APPLY:-0}" == 1 && "$*" == *extract*database.backup.sqlite* ]]; then
    printf broken >"$FIXTURE_ROOT/opt/npmplus/npmplus/database.sqlite"; return 1
  fi
  # Quiescence must precede every pre-restore copy.
  if [[ "$*" == *pre-restore-* && "$*" != *extract* && "$*" != *archive.tar.gz* && ! -f "$FIXTURE_ROOT/stopped" ]]; then return 1; fi
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

    def test_restore_rejects_database_symlinks_before_stopping_or_chmod(self):
        external = self.root / "external.sqlite"
        self.database(external, "external")
        external.chmod(0o644)
        incoming = self.root / "incoming/opt/npmplus"
        database = incoming / "npmplus/database.backup.sqlite"
        database.unlink()
        database.symlink_to(external)
        with tarfile.open(self.archive, "w:gz", dereference=False) as archive:
            archive.add(incoming, arcname="opt/npmplus")
        result = self.restore()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "stopped").exists())
        self.assertEqual(external.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.rows(), ["original"])

    def test_restore_preserves_relative_certbot_links_with_regular_archive_targets(self):
        incoming = self.root / "incoming/opt/npmplus"
        archive_dir = incoming / "tls/certbot/archive/example.test"
        live_dir = incoming / "tls/certbot/live/example.test"
        archive_dir.mkdir(parents=True)
        live_dir.mkdir(parents=True)
        (archive_dir / "fullchain1.pem").write_text("certificate fixture")
        (live_dir / "fullchain.pem").symlink_to("../../archive/example.test/fullchain1.pem")
        with tarfile.open(self.archive, "w:gz", dereference=False) as archive:
            archive.add(incoming, arcname="opt/npmplus")
        result = self.restore()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        restored = self.data / "tls/certbot/live/example.test/fullchain.pem"
        self.assertTrue(restored.is_symlink())
        self.assertEqual(restored.read_text(), "certificate fixture")

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

    def test_restore_rejects_archive_members_outside_the_backup_layout(self):
        # A planted archive that carries valid-looking backup members plus a
        # traversal member must be refused BEFORE extraction: plain GNU tar
        # writes `..` paths outside the staging tree, and the restore runs as
        # root. The staging tree sits five levels below the fixture root.
        evil = self.root / "evil.tar.gz"
        database = self.root / "incoming/opt/npmplus/npmplus/database.backup.sqlite"
        with tarfile.open(evil, "w:gz") as archive:
            directory = tarfile.TarInfo("opt/npmplus")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            member = tarfile.TarInfo("opt/npmplus/npmplus/database.backup.sqlite")
            member.size = database.stat().st_size
            with database.open("rb") as payload:
                archive.addfile(member, payload)
            escape = tarfile.TarInfo("../../../../../pwned-marker")
            escape.size = 0
            archive.addfile(escape)
        result = self.shell(
            RESTORE
            + '\nDATA_DIR="/opt/npmplus"\nCROWDSEC_DIR="/opt/crowdsec"\nCOMPOSE_FILE="$DATA_DIR/compose.yaml"\n'
            + 'run_restore "$FIXTURE_ROOT/evil.tar.gz"\n'
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("refusing to extract", result.stderr)
        self.assertFalse((self.root / "pwned-marker").exists())

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

    def test_daily_backup_contains_a_consistent_crowdsec_snapshot_without_stopping_protection(self):
        directory = self.root / "opt/crowdsec/data"
        directory.mkdir(parents=True)
        self.database(directory / "crowdsec.db", "crowdsec-original")
        with closing(sqlite3.connect(directory / "crowdsec.db")) as writer:
            writer.execute("pragma journal_mode=wal")
            writer.execute("pragma wal_autocheckpoint=0")
            writer.execute("insert into records values ('committed-in-wal')")
            writer.commit()
            result = self.shell(BACKUP)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr + (self.root / "var/log/npmplus-backup.log").read_text())
            archive_path = next((self.root / "var/backups/npmplus").glob("npmplus-*.tar.gz"))
            with tarfile.open(archive_path) as archive:
                names = archive.getnames()
                self.assertIn("opt/crowdsec/data/crowdsec.backup.db", names)
                self.assertNotIn("opt/crowdsec/data/crowdsec.db", names)
                self.assertNotIn("opt/crowdsec/data/crowdsec.db-wal", names)
                self.assertNotIn("opt/crowdsec/data/crowdsec.db-shm", names)
                self.assertNotIn("opt/npmplus/npmplus/database.sqlite", names)
                self.assertIn("opt/npmplus/npmplus/database.backup.sqlite", names)
                destination = self.root / "copied-crowdsec.db"
                destination.write_bytes(archive.extractfile("opt/crowdsec/data/crowdsec.backup.db").read())
            self.assertEqual(self.rows(destination), ["crowdsec-original", "committed-in-wal"])
        calls = (self.root / "docker.calls").read_text()
        self.assertNotIn(" stop", calls)
        self.assertIn("--network none --read-only --cap-drop ALL", calls)
        self.assertIn("dst=/source,readonly", calls)
        self.assertEqual(archive_path.stat().st_mode & 0o777, 0o600)

    def test_failed_crowdsec_snapshot_preserves_previous_archives_and_cleans_staging(self):
        directory = self.root / "opt/crowdsec/data"
        directory.mkdir(parents=True)
        self.database(directory / "crowdsec.db", "original")
        previous = self.root / "var/backups/npmplus/npmplus-2000-01-01-000000.tar.gz"
        previous.write_bytes(b"previous archive")
        result = self.shell(BACKUP, FAIL_CROWDSEC_BACKUP="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(previous.read_bytes(), b"previous archive")
        self.assertEqual(list(previous.parent.glob("npmplus-*.tar.gz")), [previous])
        self.assertFalse(list(previous.parent.glob(".npmplus-backup-*")))
        self.assertFalse((self.data / "npmplus/database.backup.sqlite").exists())

    def test_failed_archive_creation_never_publishes_a_partial_backup(self):
        fail_tar = '''tar() { if [[ "$1" == -czf ]]; then printf partial >"$2"; return 1; fi; command tar "$@"; }\n'''
        result = self.shell(fail_tar + BACKUP)
        self.assertNotEqual(result.returncode, 0)
        directory = self.root / "var/backups/npmplus"
        self.assertFalse(list(directory.glob("npmplus-*.tar.gz")))
        self.assertFalse(list(directory.glob(".npmplus-backup-*")))

    def test_restore_prefers_consistent_crowdsec_snapshot_and_removes_stale_wal(self):
        incoming = self.root / "incoming/opt/crowdsec/data"
        incoming.mkdir(parents=True)
        self.database(incoming / "crowdsec.backup.db", "consistent-snapshot")
        self.database(incoming / "crowdsec.db", "stale-main")
        (incoming / "crowdsec.db-wal").write_bytes(b"stale-wal")
        (incoming / "crowdsec.db-shm").write_bytes(b"stale-shm")
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.root / "incoming/opt/npmplus", arcname="opt/npmplus")
            archive.add(incoming.parent, arcname="opt/crowdsec")
        services = '''docker() { if [[ "$*" == *'config --services'* ]]; then printf 'npmplus\\ncrowdsec\\n'; else fixture_docker "$@"; fi; }\n'''
        # Rename the fixture function while keeping all ordinary restore behavior.
        code = RESTORE + '\nDATA_DIR="/opt/npmplus"\nCROWDSEC_DIR="/opt/crowdsec"\nCOMPOSE_FILE="$DATA_DIR/compose.yaml"\neval "$(declare -f docker | sed \'1s/docker/fixture_docker/\')"\n' + services + 'run_restore "$FIXTURE_ROOT/backup.tar.gz"\n'
        result = self.shell(code)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        restored = self.root / "opt/crowdsec/data/crowdsec.db"
        self.assertEqual(self.rows(restored), ["consistent-snapshot"])
        self.assertFalse(Path(str(restored) + "-wal").exists())
        self.assertFalse(Path(str(restored) + "-shm").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
