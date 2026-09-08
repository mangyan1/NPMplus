import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import test from "node:test";
import { isolatedPath } from "./helpers/environment.js";

process.env.AUTH_REQUEST_ANUBIS_UPSTREAM = "http://anubis-fixture:8923";
process.env.CROWDSEC_LAPI_KEY_FILE = "/data/crowdsec/fixture.key";
process.env.ANUBIS_HONEYPOT_LOG_FILE = isolatedPath("/data/anubis/honeypot.addrs");
await mkdir("/data/crowdsec", { recursive: true });
await writeFile("/data/crowdsec/fixture.key", "fixture");
await mkdir("/data/anubis", { recursive: true });
const { readRecentHoneypotIps, readHoneypotBridge } = await import("../internal/crowdsec.js");
const { default: router } = await import("../routes/crowdsec.js");

test("honeypot log reports retained scope without accepting partial addresses", async () => {
	await writeFile("/data/anubis/honeypot.addrs", "203.0.113.1\n2001:db8::1\n203.0.113.1\n192.0.2.1");
	const result = await readRecentHoneypotIps();
	assert.deepEqual(result.items, ["203.0.113.1", "2001:db8::1", "203.0.113.1"]);
	assert.equal(result.log.entries, 3);
	assert.equal(result.log.uniqueIps, 2);
	assert.equal(result.log.truncated, false);
	assert.ok(result.log.modifiedAt);
});

test("bridge evidence validates counters and distinguishes stale from failed", async () => {
	const status = { checked_at: Date.now(), status: "failed", applied: 1, failed: 1, invalid: 0, pending_bytes: 12 };
	await writeFile("/data/anubis/honeypot-bridge.json", JSON.stringify(status));
	assert.equal((await readHoneypotBridge()).status, "failed");
	await writeFile(
		"/data/anubis/honeypot-bridge.json",
		JSON.stringify({ ...status, checked_at: Date.now() - 600_000 }),
	);
	assert.equal((await readHoneypotBridge()).status, "stale");
	await writeFile("/data/anubis/honeypot-bridge.json", JSON.stringify({ ...status, failed: -1 }));
	assert.equal((await readHoneypotBridge()).status, "unavailable");
	await writeFile("/data/anubis/honeypot-bridge.json", `${JSON.stringify(status)}${" ".repeat(4096)}`);
	assert.equal((await readHoneypotBridge()).status, "unavailable");
});

test("Anubis HTTP response headers prove reachability even when its body is oversized", async (t) => {
	t.mock.method(globalThis, "fetch", async (input) =>
		String(input).includes("anubis-fixture")
			? new Response("large challenge", { status: 403, headers: { "content-length": "9999999" } })
			: Response.json([]),
	);
	let body;
	const res = {
		locals: { access: { can: async () => true } },
		status() {
			return this;
		},
		send(value) {
			body = value;
		},
	};
	const handler = router.stack
		.find((layer) => layer.route?.path === "/anubis")
		.route.stack.find((layer) => layer.method === "get").handle;
	await handler({ query: {} }, res);
	assert.equal(body.container.up, true);
	assert.equal(body.container.httpStatus, 403);
	assert.equal(body.container.error, null);
});
