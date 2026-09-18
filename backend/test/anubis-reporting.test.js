import assert from "node:assert/strict";
import { mkdir, unlink, writeFile } from "node:fs/promises";
import test from "node:test";
import { isolatedPath } from "./helpers/environment.js";

process.env.AUTH_REQUEST_ANUBIS_UPSTREAM = "http://anubis-fixture:8923";
process.env.CROWDSEC_LAPI_KEY_FILE = "/data/crowdsec/fixture.key";
process.env.ANUBIS_HONEYPOT_LOG_FILE = isolatedPath("/data/anubis/honeypot.addrs");
await mkdir("/data/crowdsec", { recursive: true });
await writeFile("/data/crowdsec/fixture.key", "fixture");
await mkdir("/data/anubis", { recursive: true });
// every module that reaches the database or the config has to be imported after
// helpers/environment.js has pointed them at this worker's temp tree; a static
// import here is evaluated before it and opens the production path instead
const { migrateUp } = await import("../migrate.js");
await migrateUp();
const { readRecentHoneypotIps, readHoneypotBridge } = await import("../internal/crowdsec.js");
const { collectAnubis } = await import("../internal/anubis-reporting.js");
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

test("an unreadable bridge file is reported once per outage, not once per poll", async (t) => {
	const messages = [];
	t.mock.method(console, "log", (...args) => messages.push(args.join(" ")));
	const reported = () => messages.filter((line) => line.includes("honeypot bridge is unreadable")).length;
	const healthy = { checked_at: Date.now(), status: "idle", applied: 0, failed: 0, invalid: 0, pending_bytes: 0 };
	// a successful read clears the streak, so this stands alone whatever ran before
	await writeFile("/data/anubis/honeypot-bridge.json", JSON.stringify(healthy));
	await readHoneypotBridge();
	const before = reported();
	await writeFile("/data/anubis/honeypot-bridge.json", JSON.stringify({ ...healthy, failed: -1 }));
	for (let poll = 0; poll < 3; poll++) assert.equal((await readHoneypotBridge()).status, "unavailable");
	assert.equal(reported() - before, 1, "the same outage was logged on every poll");
	// recovery rearms the report, so an operator sees the next outage too
	await writeFile("/data/anubis/honeypot-bridge.json", JSON.stringify(healthy));
	await readHoneypotBridge();
	await writeFile("/data/anubis/honeypot-bridge.json", JSON.stringify({ ...healthy, failed: -1 }));
	await readHoneypotBridge();
	assert.equal(reported() - before, 2, "a recovered bridge did not rearm the report");
});

test("each Anubis source reports its absence once, and separately", async (t) => {
	const messages = [];
	t.mock.method(console, "log", (...args) => messages.push(args.join(" ")));
	const sources = ["anubis-metrics.prom", "honeypot.addrs", "honeypot-attempts.log"];
	// an installation without Anubis never grows these files
	for (const name of sources) await unlink(`/data/anubis/${name}`).catch(() => {});
	for (let tick = 0; tick < 3; tick++) await collectAnubis();
	const reported = messages.filter((line) => line.includes("Anubis reporting"));
	const count = (name) => reported.filter((line) => line.includes(name)).length;
	// one line per source rather than one per source per tick, and three separate
	// slots: a single shared one would let the first missing file silence the rest
	assert.deepEqual(
		sources.map(count),
		[1, 1, 1],
		`expected one report per source, got ${reported.length}: ${reported.join(" | ")}`,
	);
});

test("Anubis HTTP response headers prove reachability even when its body is oversized", async (t) => {
	t.mock.method(globalThis, "fetch", async (input) =>
		String(input).includes("anubis-fixture")
			? new Response("large challenge", { status: 403, headers: { "content-length": "9999999" } })
			: Response.json([]),
	);
	let body;
	const res = {
		locals: { access: { canAdmin: () => true } },
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
