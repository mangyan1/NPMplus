"""Destructive recovery drills, exclusively for the disposable GitHub smoke host."""

import hashlib
import os
from pathlib import Path
import re
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request


if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("NPMPLUS_CI_RECOVERY_DRILL") != "true":
    raise SystemExit("refusing destructive recovery drills outside the explicitly enabled disposable CI host")

COMPOSE = Path("/opt/npmplus/compose.yaml")
SETUP = Path("/opt/npmplus/setup-npmplus.sh")
WRAPPER = "/usr/local/bin/npmplus-safe-update"
BACKUP = Path("/var/backups/npmplus-last-good")
context = ssl._create_unverified_context()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))


def show_failure(kind, error, traceback):
    # Only disposable CI hosts can reach this driver. Retain the controller's
    # real error even when SIGHUP moved its output away from the original log.
    directories = sorted(Path("/var/log").glob("npmplus-update.*"), key=lambda p: p.stat().st_mtime)
    for directory in directories[-2:]:
        for name in ["progress.log", "controller.log", "recovery.log", "disconnected.log"]:
            path = directory / name
            if path.is_file():
                print(f"--- {path} ---\n{path.read_text(errors='replace')[-30000:]}", flush=True)
    subprocess.run(["systemctl", "list-jobs", "--no-pager"], check=False)
    subprocess.run(["journalctl", "-u", "npmplus-public.service", "-u", "crowdsec-firewall-bouncer.service",
                    "-u", "npmplus-cloudflare-origin-lock.service", "--since", "10 minutes ago", "-n", "120", "--no-pager"], check=False)
    sys.__excepthook__(kind, error, traceback)


sys.excepthook = show_failure


def run(*args):
    return subprocess.check_output(args, text=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def healthy():
    status = run("docker", "inspect", "npmplus", "--format", "{{.State.Health.Status}}").strip()
    assert status == "healthy", status
    with opener.open("https://127.0.0.1:81/api", timeout=10) as response:
        assert b'"OK"' in response.read()
    run("systemctl", "is-active", "--quiet", "crowdsec-firewall-bouncer.service")
    run("systemctl", "is-active", "--quiet", "npmplus-public.service")
    rules = run("iptables-save")
    for chain in ["INPUT", "FORWARD"]:
        assert any(line.startswith(f"-A {chain} ") and "--match-set crowdsec-blacklists src" in line for line in rules.splitlines())
    result = run("docker", "exec", "npmplus", "node", "-e",
                 "const d=require('better-sqlite3')('/data/npmplus/database.sqlite',{readonly:true});"
                 "console.log(d.pragma('integrity_check',{simple:true}));d.close()")
    assert result.strip() == "ok", result


# An unhealthy preflight must preserve every byte of the existing snapshot.
healthy()
before = {str(p.relative_to(BACKUP)): digest(p) for p in BACKUP.rglob("*") if p.is_file()}
run("docker", "stop", "npmplus")
refused = subprocess.run([WRAPPER], capture_output=True, text=True, timeout=90)
assert refused.returncode != 0, refused.stdout
after = {str(p.relative_to(BACKUP)): digest(p) for p in BACKUP.rglob("*") if p.is_file()}
assert before == after, "unhealthy preflight overwrote the last-good snapshot"
run("systemctl", "restart", "npmplus-public.service")
healthy()
print("PASS real unhealthy preflight preserves the complete previous snapshot", flush=True)

with tempfile.TemporaryDirectory(prefix="npmplus-recovery-drill-") as directory:
    root = Path(directory)
    for label, interrupt in [("ctrl-c", signal.SIGINT), ("disconnect", signal.SIGHUP), ("terminate", signal.SIGTERM), ("timeout", None)]:
        healthy()
        compose_before, setup_before = digest(COMPOSE), digest(SETUP)
        marker = root / f"{label}.started"
        candidate = root / f"{label}.sh"
        candidate.write_text(f'''#!/bin/bash
set -eu
printf '\\n# interrupted-deployment-fixture\\n' >>/opt/npmplus/compose.yaml
docker stop npmplus >/dev/null
printf 'intentionally-corrupt-database' >/opt/npmplus/npmplus/database.sqlite
touch '{marker}'
trap '' TERM
sleep 120
printf 'late-writer' >/opt/npmplus/npmplus/database.sqlite
''')
        candidate.chmod(0o700)
        env = {**os.environ, "NPMPLUS_SETUP_CANDIDATE": str(candidate), "NPMPLUS_UPDATE_TIMEOUT_SECONDS": "5" if label == "timeout" else "300"}
        log_path = Path(f"/tmp/npmplus-recovery-{label}.log")
        with log_path.open("w") as log:
            process = subprocess.Popen([WRAPPER], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 120
                while not marker.exists() and time.monotonic() < deadline:
                    assert process.poll() is None, log_path.read_text()
                    time.sleep(0.1)
                assert marker.exists(), log_path.read_text()
                if interrupt is not None:
                    os.kill(process.pid, interrupt)
                process.wait(timeout=300)
                assert process.returncode != 0
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
        output = log_path.read_text()
        diagnostics = re.search(r"diagnostics: (/var/log/npmplus-update\.[^\s]+)", output)
        assert diagnostics, output
        output += (Path(diagnostics.group(1)) / "progress.log").read_text()
        assert "reverted - failure diagnostics are in" in output, output
        assert "rollback FAILED" not in output, output
        assert digest(COMPOSE) == compose_before
        assert digest(SETUP) == setup_before
        healthy()
        print(f"PASS real {label} restores database, image/configuration and protected healthy services", flush=True)
