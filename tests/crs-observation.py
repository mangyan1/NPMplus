"""Exercise the real CRS installer fragment on disposable Linux paths."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "setup-npmplus.sh").read_text()
FUNCTION = re.search(r"^enable_crowdsec_crs_observation\(\).*?^}\n", SOURCE, re.M | re.S).group()


class CrsObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="npmplus-crs-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.conf = self.root / "conf"
        (self.conf / "acquis.d").mkdir(parents=True)
        (self.root / "data/crowdsec").mkdir(parents=True)
        self.acquisition = self.conf / "acquis.d/npmplus.yaml"
        self.acquisition.write_text("filenames:\n  - /logs/*.log\nlabels:\n  type: npmplus\n---\nappsec_configs:\n  - crowdsecurity/appsec-default\nname: appsec\nsource: appsec\n")
        self.bouncer = self.root / "data/crowdsec/crowdsec.conf"
        self.bouncer.write_text("APPSEC_FAILURE_ACTION=deny\nAPI_KEY=fixture-key\n")

    def enable(self, fail=False):
        code = '''set -euo pipefail
say() { :; }
write_root_file() { cat >"$1"; chmod "$2" "$1"; }
docker() { printf '%s\\n' "$*" >>"$FIXTURE_ROOT/calls"; [[ "${FAIL_INSTALL:-false}" != true ]]; }
CROWDSEC_DIR="$FIXTURE_ROOT"
DATA_DIR="$FIXTURE_ROOT/data"
COMPOSE_FILE="$DATA_DIR/compose.yaml"
''' + FUNCTION + "\nenable_crowdsec_crs_observation\n"
        return subprocess.run(["bash", "-c", code], env=dict(os.environ, FIXTURE_ROOT=str(self.root), FAIL_INSTALL=str(fail).lower()), capture_output=True, text=True)

    def test_observation_preserves_blocking_and_is_idempotent(self):
        for _ in range(2):
            result = self.enable()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        text = self.acquisition.read_text()
        self.assertEqual(text.count("  - npmplus/crs-observe"), 1)
        self.assertIn("  - crowdsecurity/appsec-default", text)
        self.assertIn("filenames:\n  - /logs/*.log", text)
        policy = (self.conf / "appsec-configs/npmplus-crs-observe.yaml").read_text()
        self.assertIn("default_remediation: ban", policy)
        self.assertIn("outofband_rules:\n  - crowdsecurity/crs", policy)
        self.assertIn('SetRemediation("allow")', policy)
        self.assertIn("CancelEvent()", policy)
        self.assertIn("IsOutBand == true", policy)
        self.assertIn("SendAlert()", policy)
        calls = (self.root / "calls").read_text()
        self.assertNotIn("collections install", calls)
        self.assertIn("appsec-rules install crowdsecurity/crs", calls)
        self.assertLess(calls.index("crowdsec -t"), calls.index("restart crowdsec"))
        self.assertEqual(self.bouncer.read_text().count("# NPMPLUS_CRS_MODE=observe"), 1)
        self.assertIn("APPSEC_FAILURE_ACTION=deny", self.bouncer.read_text())
        self.assertIn("API_KEY=fixture-key", self.bouncer.read_text())

    def test_custom_acquisition_is_rejected_without_rewriting_it(self):
        self.acquisition.write_text(self.acquisition.read_text().replace("crowdsecurity/appsec-default", "operator/custom"))
        before = self.acquisition.read_text()
        result = self.enable()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("custom AppSec configuration", result.stderr)
        self.assertEqual(self.acquisition.read_text(), before)
        self.assertNotIn("NPMPLUS_CRS_MODE", self.bouncer.read_text())

    def test_failed_rule_download_never_advertises_observation(self):
        result = self.enable(fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("npmplus/crs-observe", self.acquisition.read_text())
        self.assertNotIn("NPMPLUS_CRS_MODE", self.bouncer.read_text())

    def test_safe_update_snapshots_and_restores_the_bouncer_choice(self):
        wrapper = re.search(r"write_root_file /usr/local/bin/npmplus-safe-update \d+ <<'EOF'\n(.*?)\nEOF", SOURCE, re.S).group(1)
        self.assertIn('cp -a /opt/npmplus/crowdsec/crowdsec.conf "$BACKUP/crowdsec-bouncer.conf"', wrapper)
        self.assertIn('cp -a "$BACKUP/crowdsec-bouncer.conf" /opt/npmplus/crowdsec/crowdsec.conf', wrapper)
        self.assertLess(wrapper.index('"$BACKUP/crowdsec-bouncer.conf"'), wrapper.index("up -d --pull never"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
