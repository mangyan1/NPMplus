"""Verify the real non-root Anubis image and its auth-request contracts."""

import json
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def request(base, path, agent="NPMplus-Allow"):
    req = urllib.request.Request(base + path, headers={
        "User-Agent": agent,
        "X-Real-Ip": "192.0.2.25",
        "X-Forwarded-Proto": "http",
        "X-Forwarded-Host": "example.test",
        "X-Forwarded-Uri": "/test",
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as response:
        return response.code, response.read(2 * 1024 * 1024)


def main():
    image = sys.argv[1]
    name = "npmplus-anubis-smoke-" + uuid.uuid4().hex[:12]
    volume = name + "-data"
    started = False
    policy = """bots:
  - name: smoke-deny
    user_agent_regex: '^NPMplus-Deny$'
    action: DENY
  - name: smoke-allow
    user_agent_regex: '^NPMplus-Allow$'
    action: ALLOW
  - name: smoke-challenge
    user_agent_regex: '.*'
    action: CHALLENGE
    challenge:
      algorithm: fast
      difficulty: 1
status_codes:
  CHALLENGE: 401
  DENY: 403
store:
  backend: bbolt
  parameters:
    path: /data/anubis.bdb
honeypot:
  enabled: true
  implementation: naive
  ip_log_file: /data/honeypot.addrs
"""
    with tempfile.TemporaryDirectory(prefix="npmplus-anubis-policy-") as temp:
        policy_path = pathlib.Path(temp) / "policy.yaml"
        policy_path.write_text(policy, encoding="utf-8")
        try:
            docker("volume", "create", volume)
            # The final image has no shell. Initialize only this test volume.
            docker("run", "--rm", "--user", "0", "--network", "none",
                   "--mount", f"type=volume,source={volume},target=/data",
                   "--entrypoint", "/bin/sh",
                   "alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6",
                   "-c", "chown 1000:1000 /data && chmod 0700 /data")
            docker("run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--tmpfs", "/tmp",
                   "--mount", f"type=volume,source={volume},target=/data",
                   "--mount", f"type=bind,source={policy_path.resolve()},target=/policy.yaml,readonly",
                   "-e", "HS512_SECRET=npmplus-synthetic-smoke-key-only-20261002",
                   "-e", "REDIRECT_DOMAINS=example.test",
                   "-p", "127.0.0.1::8923", "-p", "127.0.0.1::9090", image,
                   "--target=", "--policy-fname=/policy.yaml")
            started = True
            state = json.loads(docker("inspect", name))[0]
            assert state["Config"]["User"] == "1000", "non-root user changed"
            ports = state["NetworkSettings"]["Ports"]
            base = "http://127.0.0.1:" + ports["8923/tcp"][0]["HostPort"]
            metrics = "http://127.0.0.1:" + ports["9090/tcp"][0]["HostPort"]
            deadline = time.monotonic() + 45
            while True:
                try:
                    if request(metrics, "/healthz")[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise AssertionError("metrics health listener never became ready")
                time.sleep(0.5)
            check = "/.within.website/x/cmd/anubis/api/check"
            assert request(base, check)[0] == 200, "allow decision changed"
            assert request(base, check, "NPMplus-Deny")[0] == 403, "deny decision changed"
            assert request(base, check, "NPMplus-Challenge")[0] == 401, "challenge decision changed"
            status, html = request(base, "/", "NPMplus-Challenge")
            assert status == 401 and b"anubis" in html.lower(), "challenge page missing"
            status, asset = request(base, "/.within.website/x/cmd/anubis/static/js/main.mjs")
            assert status == 200 and asset, "embedded challenge JavaScript missing"
            assert request(metrics, "/metrics")[0] == 200, "Prometheus listener missing"
            print("PASS allow/deny/challenge, embedded assets, metrics", flush=True)
            assert request(base, "/.within.website/x/cmd/anubis/api/honeypot/smoke/init")[0] == 200
            deadline = time.monotonic() + 75
            while True:
                log = docker("run", "--rm", "--network", "none", "--read-only",
                             "--mount", f"type=volume,source={volume},target=/data,readonly",
                             "--entrypoint", "/bin/sh",
                             "alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6",
                             "-c", "cat /data/honeypot.addrs && test -s /data/anubis.bdb")
                if "192.0.2.25" in log.splitlines():
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError("honeypot did not persist the observed IP")
                time.sleep(2)
            docker("restart", name)
            ports = json.loads(docker("inspect", name))[0]["NetworkSettings"]["Ports"]
            base = "http://127.0.0.1:" + ports["8923/tcp"][0]["HostPort"]
            metrics = "http://127.0.0.1:" + ports["9090/tcp"][0]["HostPort"]
            deadline = time.monotonic() + 45
            while True:
                try:
                    if request(metrics, "/healthz")[0] == 200 and request(base, check)[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise AssertionError("bbolt-backed instance failed after restart")
                time.sleep(0.5)
            print("PASS non-root, read-only runtime, allow/deny/challenge, assets, metrics, honeypot, bbolt restart")
        finally:
            if started:
                if sys.exc_info()[0] is not None:
                    print(docker("logs", name), file=sys.stderr)
                docker("rm", "-f", name)
            docker("volume", "rm", volume)


if __name__ == "__main__":
    main()
