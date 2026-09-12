#!/usr/bin/env python3
"""Exercise the forbidden route with real image Nginx/Lua and fake LAPI/AppSec.

Run: python3 tests/forbidden-protection.py [--expect-gap]
Requires Docker and a built NPMplus image (NPMPLUS_TEST_IMAGE overrides develop).
All published ports bind loopback; synthetic addresses and credentials only.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("NPMPLUS_TEST_IMAGE", "ghcr.io/mangyan1/npmplus:develop")

FIXTURE = r"""
server {
 listen 127.0.0.1:8081;
 access_by_lua_block { }
 location /v1/decisions {
  content_by_lua_block {
   local ip = ngx.req.get_uri_args().ip
   ngx.shared.fixture:incr("lapi", 1, 0)
   ngx.header.content_type = "application/json"
   if ip == "198.51.100.9" then
    ngx.say('[{"type":"ban","scope":"Ip","value":"198.51.100.9","duration":"1h","origin":"cscli"}]')
   else ngx.print('null') end
  }
 }
 location /appsec {
  content_by_lua_block {
   ngx.req.read_body()
   local h = ngx.req.get_headers()
   local body = ngx.req.get_body_data() or ""
   ngx.shared.fixture:incr("appsec", 1, 0)
   ngx.shared.fixture:set("last", require("cjson").encode({method=h["x-crowdsec-appsec-verb"], uri=h["x-crowdsec-appsec-uri"], host=h["x-crowdsec-appsec-host"], body=body}))
   ngx.header.content_type = "application/json"
   if body == "fixture-block" then
    ngx.status = 403
    ngx.say('{"action":"ban","http_status":451}')
   else ngx.say('{"action":"allow"}') end
  }
 }
}
"""


def run(expect_gap, disabled=False):
    template = (ROOT / "backend/templates/default.conf").read_text()
    block = re.search(r'{% if value == "forbidden" %}(.*?){% endif %}', template, re.S).group(1)
    bouncer = (ROOT / "rootfs/etc/crowdsec.conf.original").read_text()
    values = {"API_URL": "http://127.0.0.1:8081", "API_KEY": "synthetic-test-key", "APPSEC_URL": "http://127.0.0.1:8081/appsec", "BAN_TEMPLATE_PATH": "/tmp/fixture-ban.html"}
    for key, value in values.items():
        bouncer = re.sub(rf"^{key}=.*$", f"{key}={value}", bouncer, flags=re.M)
    hooks = (ROOT / "rootfs/usr/local/nginx/conf/conf.d/crowdsec.conf.disabled").read_text()
    hooks = hooks[:hooks.index("init_worker_by_lua_block")]
    if disabled:
        hooks = ""
    config = """worker_processes 1;
error_log /dev/stderr info;
pid /tmp/nginx-audit.pid;
events { worker_connections 128; }
http {
 include /usr/local/nginx/conf/mime.types;
 lua_shared_dict fixture 1m;
 lua_shared_dict npmplus_telemetry 2m;
 map $host $npmplus_proxy_host_id { default 0; }
 map $host $crowdsec_disable_appsec { default 0; }
""" + hooks + FIXTURE + """
server {
 listen 8080;
 server_name _;
 # Synthetic client addresses: only the isolated loopback-published test server.
 set_real_ip_from 0.0.0.0/0;
 real_ip_header X-Test-IP;
 location = /fixture-observations {
  access_by_lua_block { }
  content_by_lua_block {
   local d = ngx.shared.fixture
   ngx.say(require("cjson").encode({lapi=d:get("lapi") or 0, appsec=d:get("appsec") or 0, last=d:get("last")}))
  }
 }
""" + block + "\n}\n}\n"
    name = "npmplus-forbidden-" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="npmplus-forbidden-") as directory:
        temp = Path(directory)
        (temp / "nginx.conf").write_bytes(config.encode())
        (temp / "ban.html").write_text("CrowdSec fixture ban\n")
        (temp / "crowdsec.conf").write_bytes(bouncer.encode())
        args = ["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::8080", "--entrypoint", "nginx"]
        for source, target in [(temp / "ban.html", "/tmp/fixture-ban.html"), (temp / "nginx.conf", "/tmp/fixture-nginx.conf"), (temp / "crowdsec.conf", "/data/crowdsec/crowdsec.conf"), (ROOT / "rootfs/usr/local/nginx/html/forbidden.html", "/usr/local/nginx/html/forbidden.html")]:
            args += ["--mount", f"type=bind,source={source},target={target},readonly"]
        args += [IMAGE, "-c", "/tmp/fixture-nginx.conf", "-g", "daemon off;"]
        subprocess.run(args, check=True, capture_output=True)
        try:
            port = int(subprocess.check_output(["docker", "port", name, "8080"], text=True).strip().split(":")[-1])
            def request(method, uri, body=None, ip="198.51.100.8"):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                conn.request(method, uri, body=body, headers={"Host": "unknown.example", "X-Test-IP": ip, "Content-Type": "text/plain"})
                response = conn.getresponse()
                result = response.status, response.read()
                if b"Access forbidden" in result[1]:
                    assert response.getheader("X-Frame-Options") == "DENY"
                    assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy", "")
                    assert result[1] == (ROOT / "rootfs/usr/local/nginx/html/forbidden.html").read_bytes()
                conn.close()
                return result
            for attempt in range(5):
                try:
                    request("GET", "/fixture-observations")
                    break
                except (OSError, http.client.HTTPException):
                    if attempt == 4:
                        raise
                    time.sleep(0.2)
            def observations():
                return json.loads(request("GET", "/fixture-observations")[1])
            status, body = request("POST", "/probe?q=original", "original-body")
            observed = observations()
            if disabled:
                assert status == 403 and b"Access forbidden" in body
                assert observed["lapi"] == 0 and observed["appsec"] == 0, observed
                print("PASS forbidden page remains usable with CrowdSec disabled")
                return
            if expect_gap:
                assert status == 403 and observed["lapi"] == 0 and observed["appsec"] == 0, observed
                print("CONFIRMED: original return 403 skips LAPI and AppSec")
                return
            assert status == 403 and b"Access forbidden" in body, (status, body[:200])
            assert observed["lapi"] == 1 and observed["appsec"] == 1, observed
            assert json.loads(observed["last"]) == {"method": "POST", "uri": "/probe?q=original", "host": "unknown.example", "body": "original-body"}, observed
            print("PASS original method, URI, host and body reach AppSec exactly once")
            status, banned_body = request("GET", "/banned", ip="198.51.100.9")
            assert status == 403 and b"CrowdSec fixture ban" in banned_body, (status, banned_body[:200])
            assert observations()["appsec"] == 1
            print("PASS LAPI ban enforced before default page; AppSec skipped for banned IP")
            status, _ = request("POST", "/waf", "fixture-block", ip="198.51.100.10")
            assert status == 451, status
            assert observations()["appsec"] == 2
            print("PASS AppSec denial enforced before default page")
            for method in ["PUT", "PATCH", "DELETE"]:
                before = observations()["appsec"]
                status, _ = request(method, "/method?q=retained", "retained-body", ip="198.51.100.11")
                observed = observations()
                assert status == 403 and observed["appsec"] == before + 1
                assert json.loads(observed["last"]) == {"method": method, "uri": "/method?q=retained", "host": "unknown.example", "body": "retained-body"}
            print("PASS PUT, PATCH and DELETE retain their original request context")
        finally:
            logs = subprocess.check_output(["docker", "logs", name], stderr=subprocess.STDOUT, text=True)
            subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True)
            if "[emerg]" in logs or "stack traceback" in logs:
                print(logs[-6000:])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-gap", action="store_true")
    options = parser.parse_args()
    run(options.expect_gap)
    if not options.expect_gap:
        run(False, disabled=True)
