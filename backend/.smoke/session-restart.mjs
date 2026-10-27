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
console.log("PASS signed and database-backed sessions survive a container restart");
