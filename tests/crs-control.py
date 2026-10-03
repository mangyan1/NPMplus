"""Exercise the root helper with isolated paths and a fake Docker command."""
from pathlib import Path
import os
import fcntl
import re
import struct
import subprocess
import tempfile
import types
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'setup-npmplus.sh').read_text()
HELPER = re.search(r"write_root_file /usr/local/lib/npmplus-crs-control.py 0700 <<'PYTHON'\n(.*?)\nPYTHON", SOURCE, re.S).group(1)


class CrsControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='npmplus-crs-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = types.ModuleType('crs_control_fixture')
        exec(compile(HELPER, 'crs-control.py', 'exec'), self.module.__dict__)
        m = self.module
        m.CONF = self.root / 'crowdsec/conf'
        m.BOUNCER_DIR = self.root / 'npmplus/crowdsec'
        m.STATE = self.root / 'state/state.json'
        m.LOCK = self.root / 'maintenance.lock'
        for directory in [m.CONF / 'acquis.d', m.BOUNCER_DIR, m.STATE.parent]:
            directory.mkdir(parents=True)
        self.acquisition = m.CONF / 'acquis.d/npmplus.yaml'
        self.acquisition.write_text('appsec_configs:\n  - crowdsecurity/appsec-default\nsource: appsec\n')
        self.bouncer = m.BOUNCER_DIR / 'crowdsec.conf'
        self.bouncer.write_text('APPSEC_URL=http://private:7422\nAPI_KEY=fixture-key\n')
        m.healthy = lambda: None
        self.calls = []

        def command(*args):
            self.calls.append(args)
            if args[0] == '/bin/cp':
                subprocess.run(args, check=True)
            elif args[0] == '/bin/bash':
                self.acquisition.write_text(self.acquisition.read_text().replace('source:', '  - npmplus/crs-observe\nsource:'))
                policy = m.CONF / 'appsec-configs/npmplus-crs-observe.yaml'
                policy.parent.mkdir(exist_ok=True)
                policy.write_text('# NPMPLUS_CRS_OBSERVE_VERSION=1\n')
        m.command = command

    def test_activation_is_idempotent_bounded_and_does_not_execute_compose(self):
        control = self.module.Control()
        self.assertTrue(control.status()['eligible'])
        self.assertEqual(control.enable(), {'accepted': True, 'state': 'running'})
        control.worker.join(10)
        self.assertFalse(control.worker.is_alive())
        self.assertTrue(control.status()['enabled'])
        self.assertEqual(control.status()['state'], 'enabled')
        before = list(self.calls)
        self.assertEqual(control.enable(), {'accepted': True, 'state': 'enabled'})
        self.assertEqual(before, self.calls)
        self.assertIn('APPSEC_URL=http://private:7422', self.bouncer.read_text())
        self.assertIn('API_KEY=fixture-key', self.bouncer.read_text())
        self.assertEqual(self.bouncer.read_text().count('# NPMPLUS_CRS_MODE=observe'), 1)
        self.assertNotIn('compose', str(self.calls))

    def test_failure_restores_config_and_inode_and_preserves_cooldown_after_restart(self):
        original = self.acquisition.read_bytes()
        original_bouncer = self.bouncer.read_bytes()
        inode = self.module.CONF.stat().st_ino
        original_command = self.module.command

        def failed(*args):
            original_command(*args)
            if args[0] == '/bin/bash':
                raise RuntimeError('fixture failure')
        self.module.command = failed
        control = self.module.Control()
        control.enable()
        control.worker.join(10)
        self.assertEqual(control.status()['state'], 'failed')
        self.assertEqual(self.acquisition.read_bytes(), original)
        self.assertEqual(self.bouncer.read_bytes(), original_bouncer)
        self.assertEqual(self.module.CONF.stat().st_ino, inode)
        self.assertFalse((self.module.CONF / 'appsec-configs').exists())
        self.assertIn((self.module.DOCKER, 'restart', 'crowdsec'), self.calls)
        restarted = self.module.Control()
        self.assertEqual(restarted.enable(), {'accepted': False, 'reason': 'cooldown'})

    def test_recovery_failure_is_distinct(self):
        original_command = self.module.command
        def failed(*args):
            if args[0] == '/bin/cp':
                return original_command(*args)
            raise RuntimeError('fixture command failure')
        self.module.command = failed
        control = self.module.Control()
        control.enable()
        control.worker.join(10)
        self.assertEqual(control.status()['state'], 'rollback-failed')

    def test_custom_and_disabled_appsec_are_refused_without_starting_work(self):
        control = self.module.Control()
        for value in ['APPSEC_URL=\n', 'API_KEY=fixture-key\n']:
            self.bouncer.write_text(value)
            self.assertEqual(control.enable(), {'accepted': False, 'reason': 'unsupported'})
        self.bouncer.write_text('APPSEC_URL=http://private:7422\n')
        self.acquisition.write_text('appsec_configs:\n  - operator/custom\n')
        self.assertEqual(control.enable(), {'accepted': False, 'reason': 'unsupported'})
        self.assertEqual(self.calls, [])

    def test_symlinked_operator_configuration_is_not_modified(self):
        target = self.root / 'operator.yaml'
        target.write_bytes(self.acquisition.read_bytes())
        self.acquisition.unlink()
        self.acquisition.symlink_to(target)
        control = self.module.Control()
        self.assertEqual(control.enable(), {'accepted': False, 'reason': 'unsupported'})
        self.assertEqual(self.calls, [])

    def test_other_maintenance_prevents_any_configuration_change(self):
        with self.module.LOCK.open('a') as locked:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            control = self.module.Control()
            control.enable()
            control.worker.join(10)
            self.assertEqual(control.status()['state'], 'failed')
            self.assertFalse(control.status()['enabled'])
            self.assertEqual(self.calls, [])

    def test_unhealthy_baseline_and_concurrent_key_changes_are_not_overwritten(self):
        def unhealthy(): raise RuntimeError('fixture unhealthy')
        self.module.healthy = unhealthy
        control = self.module.Control()
        control.enable()
        control.worker.join(10)
        self.assertEqual(self.calls, [])
        self.assertEqual(control.status()['state'], 'failed')
        self.module.STATE.unlink()
        self.module.healthy = lambda: None
        original = self.module.command
        def key_change(*args):
            original(*args)
            if args[0] == '/bin/bash':
                self.bouncer.write_text(self.bouncer.read_text().replace('fixture-key', 'new-fixture-key'))
        self.module.command = key_change
        control = self.module.Control()
        control.enable()
        control.worker.join(10)
        self.assertEqual(control.status()['state'], 'failed')
        self.assertIn('new-fixture-key', self.bouncer.read_text())
        self.assertNotIn('NPMPLUS_CRS_MODE', self.bouncer.read_text())

    def test_socket_accepts_only_exact_verbs_and_known_peer_uids(self):
        class Connection:
            def __init__(self, data, uid=1000):
                self.data = data
                self.uid = uid
                self.reply = b''
            def settimeout(self, _): pass
            def getsockopt(self, *_): return struct.pack('3i', 10, self.uid, 1000)
            def recv(self, _):
                data, self.data = self.data, b''
                return data
            def sendall(self, reply): self.reply = reply
        control = self.module.Control()
        for data in [b'ENABLE;sh\n', b'ENABLE\nother', b'/bin/sh\n', b'ENABLE ']:
            connection = Connection(data)
            self.module.respond(connection, control)
            self.assertFalse(connection.reply and b'"accepted": true' in connection.reply)
        outsider = Connection(b'ENABLE\n', uid=1001)
        self.module.respond(outsider, control)
        self.assertEqual(outsider.reply, b'')
        status = Connection(b'STATUS\n')
        self.module.respond(status, control)
        self.assertIn(b'"available": true', status.reply)
        self.assertNotIn(b'fixture-key', status.reply)
        self.assertNotIn(b'/opt', status.reply)
        self.assertEqual(self.calls, [])

    def test_bouncer_symlinks_hardlinks_and_special_files_are_rejected(self):
        target = self.root / 'protected'
        protected = 'APPSEC_URL=http://private:7422\nAPI_KEY=protected-data\n'
        target.write_text(protected)
        self.bouncer.unlink()
        self.bouncer.symlink_to(target)
        with self.assertRaises((OSError, ValueError)):
            self.module.bouncer_fd()
        self.assertFalse(self.module.Control().status()['eligible'])
        self.bouncer.unlink()
        os.link(target, self.bouncer)
        with self.assertRaises((OSError, ValueError)):
            self.module.bouncer_fd()
        self.assertFalse(self.module.Control().status()['eligible'])
        self.bouncer.unlink()
        os.mkfifo(self.bouncer)
        with self.assertRaises((OSError, ValueError)):
            self.module.bouncer_fd()
        self.assertFalse(self.module.Control().status()['eligible'])
        self.assertEqual(target.read_text(), protected)

    def test_helper_generation_mount_rollback_and_uninstall_are_pinned(self):
        install = re.search(r'^install_crs_control\(\).*?^}\n', SOURCE, re.M | re.S).group()
        self.assertIn('declare -f write_root_file enable_crowdsec_crs_observation', install)
        self.assertIn('enable_crowdsec_crs_observation control', install)
        self.assertIn('NoNewPrivileges=true', install)
        self.assertIn('RestrictAddressFamilies=AF_UNIX', install)
        self.assertIn('/run/npmplus-crs-control:/run/npmplus-crs-control:ro', SOURCE)
        self.assertIn('etc/systemd/system/npmplus-crs-control.socket', SOURCE[SOURCE.index('host_security_paths=('):])
        self.assertIn('\tremove_crs_control\n', SOURCE)
        self.assertLess(SOURCE.index('remove_crs_control() {'), SOURCE.index('\tremove_crs_control\n'))
        function = re.search(r'^enable_crowdsec_crs_observation\(\).*?^}\n', SOURCE, re.M | re.S).group()
        branch = function[function.index('if [[ "$control" == "control"') : function.index('# A non-secret installer choice')]
        self.assertIn('docker restart crowdsec\n\t\treturn', branch)
        self.assertLess(branch.index('return'), branch.index('docker compose'))

        self.assertIn('timeout -s KILL 60 cscli appsec-rules install crowdsecurity/crs', branch)
        self.assertIn('timeout -s KILL 30 crowdsec -t', branch)

    def test_uninstall_dispatch_has_cleanup_loaded_and_removes_only_owned_files(self):
        prefix = SOURCE.split('# --uninstall is deliberately handled before dependency installation', 1)[0]
        # Evaluate only definitions and argument parsing, with no uninstall body.
        prefix = re.sub(r'^\[\[ \$EUID.*$', '', prefix, flags=re.M)
        result = subprocess.run(['bash', '-c', prefix + '\ndeclare -F remove_crs_control\n', 'fixture', '--uninstall', '--no-backup'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        cleanup = re.search(r'^remove_crs_control\(\).*?^}\n', SOURCE, re.M | re.S).group()
        paths = ['/etc/systemd/system', '/usr/local/lib', '/var/lib/npmplus/crs-control', '/run/npmplus-crs-control']
        for index, path in enumerate(paths):
            directory = self.root / ('cleanup-' + str(index))
            directory.mkdir()
            cleanup = cleanup.replace(path, str(directory))
        units = self.root / 'cleanup-0'
        tools = self.root / 'cleanup-1'
        for path in [units / 'npmplus-crs-control.socket', units / 'npmplus-crs-control.service', tools / 'npmplus-crs-control.py', tools / 'npmplus-crs-enable', self.root / 'cleanup-2/state.json']:
            path.write_text('owned fixture')
        unrelated = units / 'operator-owned.service'
        unrelated.write_text('keep')
        result = subprocess.run(['bash', '-c', 'set -euo pipefail\nsystemctl() { :; }\n' + cleanup + '\nremove_crs_control\n'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(unrelated.read_text(), 'keep')
        self.assertEqual(sorted(path.name for path in units.iterdir()), ['operator-owned.service'])
        self.assertEqual(list(tools.iterdir()), [])
        self.assertFalse((self.root / 'cleanup-2').exists())
        self.assertFalse((self.root / 'cleanup-3').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
