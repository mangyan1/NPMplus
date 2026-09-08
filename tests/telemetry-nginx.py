"""Run inside the NPMplus image: real nginx/bouncer and local fake services.

docker run --rm --network none --entrypoint python3 -v REPO:/repo:ro IMAGE /repo/tests/telemetry-nginx.py
No published ports, production data, or external traffic.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.server.server_port == 18090:
            result, status = None, 200
            if parse_qs(urlsplit(self.path).query).get("ip") == ["2001:db8::1234"]:
                result = [{"value": "2001:db8::1234", "scope": "Ip", "type": "ban", "origin": "crowdsec", "scenario": "fixture"}]
        elif self.server.server_port == 18091:
            uri = self.headers.get("x-crowdsec-appsec-uri", "")
            status = 403 if uri == "/deny" else 503 if uri == "/error" else 200
            result = {"action": "ban"} if status == 403 else {}
        else:
            status, result = (403 if self.path == "/upstream-deny" else 200), {}
        body = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class NginxTelemetryTests(unittest.TestCase):
    def test_actual_bouncer_observations(self):
        module = Path("/usr/local/share/lua/5.1/npmplus_telemetry.lua")
        shutil.copyfile(ROOT / "rootfs/usr/local/share/lua/5.1/npmplus_telemetry.lua", module)
        if 'require("npmplus_telemetry").response(' not in Path("/usr/local/share/lua/5.1/crowdsec.lua").read_text():
            subprocess.run(["python3", str(ROOT / "rootfs/usr/local/bin/instrument-crowdsec-telemetry.py")], check=True)
        services = []
        for port in (18089, 18090, 18091):
            service = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            threading.Thread(target=service.serve_forever, daemon=True).start()
            self.addCleanup(service.server_close)
            self.addCleanup(service.shutdown)
            services.append(service)
        with tempfile.TemporaryDirectory(prefix="npmplus-nginx-telemetry-") as folder:
            directory = Path(folder)
            (directory / "logs").mkdir()
            config = (ROOT / "rootfs/etc/crowdsec.conf.original").read_text().replace("${CROWDSEC_LAPI_URL}", "http://127.0.0.1:18090").replace("${API_KEY}", "fixture-key")
            config = config.replace("APPSEC_URL=\n", "APPSEC_URL=http://127.0.0.1:18091/\n").replace("/var/lib/crowdsec/lua/templates/ban.html", "/etc/ban.html.original").replace("/var/lib/crowdsec/lua/templates/captcha.html", "/etc/captcha.html.original")
            (directory / "bouncer.conf").write_text(config)
            (directory / "nginx.conf").write_text(f'''
worker_processes 1;
pid {directory}/nginx.pid;
error_log {directory}/error.log info;
events {{ worker_connections 64; }}
http {{
 lua_shared_dict crowdsec_cache 10m;
 include /repo/rootfs/usr/local/nginx/conf/conf.d/npmplus-telemetry.conf;
 init_by_lua_block {{ cs = require "crowdsec"; require("npmplus_telemetry").install(cs); assert(cs.init("{directory}/bouncer.conf", "fixture/v1")) }}
 server {{
  listen 127.0.0.1:18088;
  set $npmplus_proxy_host_id 42;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Fixture-IP;
  location / {{ access_by_lua_block {{ cs.Allow(ngx.var.remote_addr) }} proxy_pass http://127.0.0.1:18089; }}
  location /bypass {{ set $crowdsec_disable_appsec 1; access_by_lua_block {{ cs.Allow(ngx.var.remote_addr) }} proxy_pass http://127.0.0.1:18089; }}
  location = /telemetry {{ content_by_lua_block {{ require("npmplus_telemetry").render() }} }}
 }}
}}
''')
            process = subprocess.Popen(["nginx", "-p", folder, "-c", str(directory / "nginx.conf"), "-g", "daemon off;"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(50):
                    if process.poll() is not None:
                        self.fail(process.stderr.read().decode())
                    try:
                        initial = self.request("/telemetry")[1]
                        break
                    except OSError:
                        time.sleep(0.1)
                self.assertEqual(json.loads(initial)["hosts"], [])
                for route, status in (("/allow", 200), ("/deny", 403), ("/upstream-deny", 403), ("/bypass", 200), ("/error", 200)):
                    self.assertEqual(self.request(route)[0], status, route + "\n" + (directory / "error.log").read_text())
                data = json.loads(self.request("/telemetry")[1])
                counters = data["hosts"][0]["counters"]
                self.assertEqual(data["hosts"][0]["id"], 42)
                self.assertEqual(counters["checks"], 4)
                self.assertEqual(counters["inspected"], 3)
                self.assertEqual(counters["errors"], 1)
                self.assertEqual(counters["bans"], 1)
                self.assertEqual(counters["waf_bans"], 1)
                self.assertNotIn("127.0.0.1", json.dumps(data))
                self.assertNotIn("fixture-key", json.dumps(data))
                # The transport is IPv4; a trusted proxy reports the IPv6 visitor.
                self.assertEqual(self.request("/allow", {"X-Fixture-IP": "2001:db8::1234"})[0], 403)
                data = json.loads(self.request("/telemetry")[1])
                self.assertEqual(data["hosts"][0]["counters"]["bans"], 2)
                self.assertEqual(data["hosts"][0]["counters"]["waf_bans"], 1)
                connection = http.client.HTTPConnection("localhost", timeout=3)
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(3)
                connection.sock.connect("/run/npmplus-telemetry.sock")
                try:
                    connection.request("GET", "/")
                    private_response = connection.getresponse()
                    self.assertEqual(private_response.status, 200)
                    self.assertEqual(json.loads(private_response.read()), data)
                finally:
                    connection.close()
                # Shared memory survives reload, but disabling observation must
                # not make old counters look like a fresh active source.
                nginx_config = directory / "nginx.conf"
                nginx_config.write_text(nginx_config.read_text().replace('require("npmplus_telemetry").install(cs); ', ""))
                subprocess.run(["nginx", "-p", folder, "-c", str(nginx_config), "-s", "reload"], check=True)
                for _ in range(30):
                    status = self.request("/telemetry")[0]
                    if status == 503:
                        break
                    time.sleep(0.1)
                self.assertEqual(status, 503)
            finally:
                process.terminate()
                process.wait(timeout=10)
                process.stdout.close()
                process.stderr.close()
                if process.returncode not in (0, -15):
                    print((directory / "error.log").read_text())

    @staticmethod
    def request(route, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", 18088, timeout=3)
        connection.request("GET", route, headers=headers or {})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

if __name__ == "__main__":
    unittest.main(verbosity=2)
