"""Exercise the actual CrowdSec entrypoint, LAPI credentials, AppSec and restart."""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def request(base, path, headers=None, method="GET"):
    req = urllib.request.Request(base + path, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as response:
        return response.code, response.read(2 * 1024 * 1024)


def main():
    image = sys.argv[1]
    name = "npmplus-crowdsec-smoke-" + uuid.uuid4().hex[:12]
    volumes = [name + "-config", name + "-data"]
    started = False
    mounts = ["--mount", f"type=volume,source={volumes[0]},target=/etc/crowdsec",
              "--mount", f"type=volume,source={volumes[1]},target=/var/lib/crowdsec/data"]
    try:
        for volume in volumes:
            docker("volume", "create", volume)
        # Materialize upstream staged data instead of symlinks into a read-only image.
        docker("run", "--rm", "--network", "none", *mounts, "--entrypoint", "/bin/sh", image,
               "-c", "cp -a /staging/etc/crowdsec/. /etc/crowdsec/ && "
               "cp -a /staging/var/lib/crowdsec/data/. /var/lib/crowdsec/data/ && "
               "printf '%s\\n' 'listen_addr: 0.0.0.0:7422' 'appsec_configs:' "
               "'  - crowdsecurity/appsec-default' 'name: appsec' 'source: appsec' "
               "'labels:' '  type: appsec' > /etc/crowdsec/acquis.d/npmplus.yaml")
        # Keep synthetic test decisions off CrowdSec's community API. Both the
        # detection agent and local API remain enabled with the real AppSec rules.
        docker("run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--tmpfs", "/tmp",
               *mounts, "-e", "DISABLE_ONLINE_API=true", "-e", "USE_WAL=true",
               "-e", "COLLECTIONS=ZoeyVid/npmplus crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules",
               "-e", "APPSEC_CONFIGS=crowdsecurity/appsec-default",
               "-p", "127.0.0.1::8080", "-p", "127.0.0.1::6060", "-p", "127.0.0.1::7422", image)
        started = True

        def endpoints():
            ports = json.loads(docker("inspect", name))[0]["NetworkSettings"]["Ports"]
            return ["http://127.0.0.1:" + ports[f"{port}/tcp"][0]["HostPort"] for port in (8080, 6060, 7422)]

        lapi, metrics, appsec = endpoints()
        deadline = time.monotonic() + 180
        while True:
            try:
                docker("exec", name, "cscli", "lapi", "status", "--error")
                if request(metrics, "/metrics")[0] == 200 and request(appsec, "/")[0] in (401, 403):
                    break
            except (OSError, urllib.error.URLError, subprocess.CalledProcessError):
                pass
            state = json.loads(docker("inspect", name))[0]["State"]
            assert state["Running"], "CrowdSec exited before becoming ready"
            if time.monotonic() >= deadline:
                raise AssertionError("LAPI, metrics or AppSec never became ready")
            time.sleep(2)

        key = docker("exec", name, "cscli", "bouncers", "add", "npmplus-smoke", "-o", "raw")
        assert key and "\n" not in key, "bouncer registration format changed"
        headers = {"X-Api-Key": key}
        assert request(lapi, "/v1/decisions")[0] in (401, 403), "anonymous LAPI access allowed"
        assert request(lapi, "/v1/decisions", headers)[0] == 200, "bouncer read rejected"
        assert request(lapi, "/v1/decisions?ip=192.0.2.55", headers, "DELETE")[0] in (401, 403), "bouncer can write"
        docker("exec", name, "cscli", "decisions", "add", "--ip", "192.0.2.55", "--duration", "10m", "--reason", "npmplus-smoke")
        status, body = request(lapi, "/v1/decisions?ip=192.0.2.55", headers)
        assert status == 200 and any(row["value"] == "192.0.2.55" for row in json.loads(body)), "machine decision write missing"
        waf_headers = {"X-Crowdsec-Appsec-Api-Key": key, "X-Crowdsec-Appsec-Ip": "192.0.2.25",
                       "X-Crowdsec-Appsec-Host": "example.test", "X-Crowdsec-Appsec-Verb": "GET",
                       "X-Crowdsec-Appsec-Uri": "/normal"}
        status, body = request(appsec, "/", waf_headers, "POST")
        assert status == 200 and json.loads(body)["action"] == "allow", "AppSec normal request rejected"
        # Upstream generic-wordpress-uploads-php explicitly blocks this path.
        waf_headers["X-Crowdsec-Appsec-Uri"] = "/wp-content/uploads/npmplus-smoke.php"
        status, body = request(appsec, "/", waf_headers, "POST")
        assert json.loads(body)["action"] == "ban", f"AppSec attack was not blocked: {status} {body!r}"
        print("PASS LAPI auth, bouncer read-only, machine write, metrics, AppSec allow/block", flush=True)
        docker("restart", name)
        lapi, metrics, appsec = endpoints()
        deadline = time.monotonic() + 120
        while True:
            try:
                status, body = request(lapi, "/v1/decisions?ip=192.0.2.55", headers)
                if status == 200 and any(row["value"] == "192.0.2.55" for row in json.loads(body)):
                    break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() >= deadline:
                raise AssertionError("key or SQLite decision lost after restart")
            time.sleep(2)
        docker("exec", name, "cscli", "decisions", "delete", "--ip", "192.0.2.55")
        assert json.loads(request(lapi, "/v1/decisions?ip=192.0.2.55", headers)[1]) in (None, []), "decision deletion failed"
        docker("exec", name, "cscli", "lapi", "status", "--error")
        assert request(metrics, "/metrics")[0] == 200, "metrics failed after restart"
        waf_headers["X-Crowdsec-Appsec-Uri"] = "/normal"
        assert request(appsec, "/", waf_headers, "POST")[0] == 200, "AppSec failed after restart"
        print("PASS read-only runtime, entrypoint, LAPI roles, AppSec, SQLite persistence and restart")
    finally:
        if started:
            if sys.exc_info()[0] is not None:
                print(docker("logs", name), file=sys.stderr)
            docker("rm", "-f", name)
        for volume in volumes:
            docker("volume", "rm", volume)


if __name__ == "__main__":
    main()
