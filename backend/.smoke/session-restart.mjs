// biome-ignore-all lint/suspicious/noMisplacedAssertion: standalone container smoke assertions
// Run only against the disposable container created by docker-security.mjs.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const base = process.env.SMOKE_BASE_URL;
const container = process.env.SMOKE_CONTAINER;
assert.ok(container?.startsWith("npmplus-security-"));
assert.ok(["127.0.0.1", "localhost"].includes(new URL(base).hostname));
const login = await fetch(`${base}/api/tokens`, {
	method: "POST",
	headers: { "content-type": "application/json" },
	body: JSON.stringify({ identity: process.env.SMOKE_ADMIN_EMAIL, secret: process.env.SMOKE_ADMIN_PASSWORD }),
	signal: AbortSignal.timeout(20000),
});
assert.equal(login.status, 200);
const cookie = login.headers
	.getSetCookie()
	.find((value) => value.startsWith("__Host-Http-token="))
	?.split(";")[0];
assert.ok(cookie);
const hostname = "startup-regeneration.example.test";
const create = await fetch(`${base}/api/nginx/proxy-hosts`, {
	method: "POST",
	headers: { "content-type": "application/json", cookie },
	body: JSON.stringify({
		domain_names: [hostname],
		forward_scheme: "http",
		forward_host: "127.0.0.1",
		forward_port: 81,
	}),
	signal: AbortSignal.timeout(20000),
});
assert.equal(create.status, 201);
const host = await create.json();
assert.equal(host.npmplus_nginx_online, true);
assert.ok(Number.isInteger(host.id));
const configPath = `/data/nginx/proxy_host/${host.id}.conf`;
// Model an existing deployment whose template/environment fingerprint changed.
// Remove its old config too, so serving stale files cannot make this test pass.
execFileSync("docker", ["exec", container, "rm", "-f", "/data/npmplus/env.sha512sum", configPath]);
execFileSync("docker", ["restart", container], { stdio: "pipe" });
let healthy = false;
let restartedBase = base;
for (let attempt = 0; attempt < 90; attempt++) {
	const state = JSON.parse(execFileSync("docker", ["inspect", container], { encoding: "utf8" }))[0];
	if (state.State.Health?.Status === "healthy") {
		healthy = true;
		// Docker Desktop can allocate a new ephemeral host port on restart.
		const address = new URL(base);
		address.port = state.NetworkSettings.Ports["81/tcp"][0].HostPort;
		restartedBase = address.origin;
		break;
	}
	if (!state.State.Running || state.State.Health?.Status === "unhealthy") break;
	await delay(1000);
}
assert.ok(healthy, "restarted container did not become healthy");
const me = await fetch(`${restartedBase}/api/users/me`, { headers: { cookie }, signal: AbortSignal.timeout(20000) });
assert.equal(me.status, 200, "the signed session and database session must survive a container restart");
const config = execFileSync("docker", ["exec", container, "cat", configPath], { encoding: "utf8" });
assert.ok(config.includes(hostname), "startup must regenerate the existing host configuration");
const restoredHost = await fetch(`${restartedBase}/api/nginx/proxy-hosts/${host.id}`, {
	headers: { cookie },
	signal: AbortSignal.timeout(20000),
});
assert.equal(restoredHost.status, 200);
assert.equal((await restoredHost.json()).npmplus_nginx_online, true);
const remove = await fetch(`${restartedBase}/api/nginx/proxy-hosts/${host.id}`, {
	method: "DELETE",
	headers: { cookie },
	signal: AbortSignal.timeout(20000),
});
assert.equal(remove.status, 200);
console.log("PASS existing proxy regenerates after a template/environment change and the API becomes healthy");
console.log("PASS signed and database-backed sessions survive a container restart");
