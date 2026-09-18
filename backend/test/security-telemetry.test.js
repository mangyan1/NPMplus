import "./helpers/environment.js";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { beforeEach, test } from "node:test";
import db from "../db.js";
import { readTelemetry, recordSnapshot, refusalState } from "../internal/security-telemetry.js";
import { migrateUp } from "../migrate.js";

await migrateUp();
beforeEach(async () => {
	await db()("security_telemetry").delete();
});
const start = Date.UTC(2026, 8, 8, 12, 0);
const counters = (count) => ({
	checks: count,
	inspected: count,
	errors: 0,
	unreadable: 0,
	bans: count,
	waf_bans: count,
	challenges: 0,
});
const sample = (count, epoch = "one") => ({ epoch, overflow: 0, hosts: [{ id: 42, counters: counters(count) }] });

test("telemetry records per-host deltas once and survives persisted-baseline reuse", async () => {
	await recordSnapshot("nginx", sample(10), start);
	await recordSnapshot("nginx", sample(15), start + 60_000);
	await recordSnapshot("nginx", sample(15), start + 60_000);
	await recordSnapshot("nginx", sample(18), start + 120_000);
	const result = await readTelemetry(1, start + 300_000);
	assert.equal(result.nginx.totals.bans, 8);
	assert.equal(result.nginx.hosts[0].id, 42);
	assert.equal(result.nginx.hosts[0].counters.inspected, 8);
	assert.equal(result.nginx.covered_ms, 120_000);
	assert.equal(result.nginx.incomplete, true);
	assert.equal((await readTelemetry(1, start - 60_000)).nginx.status, "stale");
});
test("epochs, counter resets and collection gaps cannot inflate history", async () => {
	await recordSnapshot("nginx", sample(100), start);
	await recordSnapshot("nginx", sample(200, "two"), start + 60_000);
	await recordSnapshot("nginx", sample(1, "two"), start + 120_000);
	await recordSnapshot("nginx", sample(900, "two"), start + 600_000);
	const result = await readTelemetry(1, start + 900_000);
	assert.equal(result.nginx.totals.bans, 0);
	assert.equal(result.nginx.incomplete, true);
	assert.equal(result.nginx.status, "stale");
});
test("firewall samples are timestamped packet observations and stale repeats are rejected", async () => {
	const firewall = {
		epoch: "boot:service",
		collected_at: start,
		service_active: true,
		input_rule: true,
		forward_rule: false,
		counters: { input_packets: 10, forward_packets: 20, input_bytes: 500, forward_bytes: 1000 },
	};
	await recordSnapshot("firewall", firewall, start);
	await recordSnapshot(
		"firewall",
		{ ...firewall, collected_at: start + 60_000, counters: { ...firewall.counters, input_packets: 15 } },
		start + 60_000,
	);
	const result = await readTelemetry(1, start + 300_000);
	assert.equal(result.firewall.totals.input_packets, 5);
	assert.equal(result.nginx.totals.bans, 0);
	assert.equal(result.firewall.forward_rule, false);
	await assert.rejects(recordSnapshot("firewall", firewall, start + 600_000));
});
test("a refused reading is a state only for a code this reader knows", async () => {
	// the exporter's code and the one recognized here are one contract in two
	// languages; rewording either side alone would silently turn this into a fault
	const lua = await readFile(
		new URL("../../rootfs/usr/local/share/lua/5.1/npmplus_telemetry.lua", import.meta.url),
		"utf8",
	);
	assert.match(lua, /"reason":"bouncer-not-installed"/);
	assert.deepEqual(refusalState('{"error":"CrowdSec observation disabled","reason":"bouncer-not-installed"}'), {
		disabled: true,
	});
	assert.equal(refusalState('{"error":"CrowdSec observation disabled"}'), null);
	assert.equal(refusalState('{"reason":"bouncer-not-installed-anyway"}'), null);
	assert.equal(refusalState("telemetry unavailable"), null);
});
test("a switched-off bouncer is reported as disabled without fabricating observation", async () => {
	await recordSnapshot("nginx", { disabled: true }, start);
	const result = await readTelemetry(1, start + 60_000);
	assert.equal(result.nginx.status, "disabled");
	assert.equal(result.nginx.observed_at, null);
	assert.equal(result.nginx.covered_ms, 0);
	assert.deepEqual(result.nginx.hosts, []);
	// a marker the collector stopped refreshing describes the past, not the present
	assert.equal((await readTelemetry(1, start + 600_000)).nginx.status, "stale");
	// the next real reading replaces the marker rather than leaving nginx disabled
	await recordSnapshot("nginx", sample(10), start + 600_000);
	assert.equal((await readTelemetry(1, start + 660_000)).nginx.status, "observed");
});
test("a disabled marker keeps no counter baseline, so resuming cannot replay counters", async () => {
	await recordSnapshot("nginx", sample(100), start);
	await recordSnapshot("nginx", { disabled: true }, start + 60_000);
	await recordSnapshot("nginx", sample(600), start + 120_000);
	await recordSnapshot("nginx", sample(600), start + 240_000);
	const result = await readTelemetry(1, start + 300_000);
	// the 500 requests the bouncer counted while it was switched off are not
	// claimed as observed traffic, and the interrupted interval stays partial
	assert.equal(result.nginx.totals.bans, 0);
	assert.equal(result.nginx.covered_ms, 120_000);
	assert.equal(result.nginx.incomplete, true);
	assert.equal(result.nginx.status, "observed");
});
test("invalid/oversized host cardinality is rejected and old buckets are pruned", async () => {
	await assert.rejects(
		recordSnapshot(
			"nginx",
			{ ...sample(1), hosts: Array.from({ length: 201 }, (_, i) => ({ id: i + 1, counters: counters(1) })) },
			start,
		),
	);
	await db()("security_telemetry").insert({ source: "nginx", bucket: start - 8 * 86400_000, data: "{}" });
	await recordSnapshot("nginx", sample(1), start);
	assert.equal(
		await db()("security_telemetry")
			.where("bucket", ">=", 0)
			.where("bucket", "<", start - 86400_000)
			.first(),
		undefined,
	);
});
