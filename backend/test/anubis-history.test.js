import "./helpers/environment.js";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import db from "../db.js";
import {
	canonicalIp,
	hostCoverage,
	readReport,
	recordAddresses,
	recordAttempts,
	recordMetrics,
} from "../internal/anubis-reporting.js";
import { migrateUp } from "../migrate.js";
import ProxyHost from "../models/proxy_host.js";

await migrateUp();
beforeEach(async () => {
	await db()("anubis_sample").delete();
	await db()("anubis_event").delete();
	await db()("proxy_host").delete();
});
const start = Date.UTC(2026, 8, 8, 12);
const metrics = (count, epoch = 1000) =>
	`process_start_time_seconds ${epoch}\nanubis_challenges_issued{method="embedded",asn="1"} ${count}\nanubis_challenges_validated{method="pow"} ${count}\n`;

test("Anubis counter deltas survive persisted baselines and keep absent counters unknown", async () => {
	await recordMetrics(metrics(10), start, start);
	await recordMetrics(metrics(15), start + 60_000, start + 60_000);
	await recordMetrics(metrics(15), start + 60_000, start + 60_000);
	const result = await readReport(1, 1, 1, start + 300_000);
	assert.deepEqual(result.metrics.totals, { issued: 5, validated: 5, failed: null });
	assert.equal(result.metrics.partial, true);
	assert.equal(result.metrics.status, "stale");
	await assert.rejects(recordMetrics(metrics(20), start, start + 600_000), /Stale/);
});
test("Anubis restart, disappearing series, and gaps cannot manufacture outcomes", async () => {
	await recordMetrics(metrics(100), start, start);
	await recordMetrics(metrics(200, 1001), start + 60_000, start + 60_000);
	await recordMetrics(metrics(1, 1001), start + 120_000, start + 120_000);
	await recordMetrics(metrics(900, 1001), start + 600_000, start + 600_000);
	assert.deepEqual((await readReport(1, 1, 1, start + 900_000)).metrics.totals, {
		issued: null,
		validated: null,
		failed: null,
	});
});
test("honeypot history baselines old entries and records new complete IPv6 observations once", async () => {
	const original = "203.0.113.1\n";
	await recordAddresses(original, start);
	assert.equal((await readReport(1, 1, 1, start)).ledger.total, 0);
	const appended = `${original}2001:0db8::1\n192.0.2.`;
	await recordAddresses(appended, start + 60_000);
	await recordAddresses(appended, start + 120_000);
	const result = await readReport(1, 1, 1, start + 120_000);
	assert.equal(result.ledger.total, 1);
	assert.equal(result.ledger.items[0].ip, "2001:db8::1");
	assert.equal(result.ledger.items[0].time, new Date(start + 60_000).toISOString());
	assert.equal(canonicalIp("<script>"), null);
	assert.equal(canonicalIp("fe80::1%eth0"), null);
});
test("source reset and regrowth is detected by prefix fingerprint", async () => {
	await recordAddresses("203.0.113.1\n", start);
	await recordAddresses("2001:db8::1234\n", start + 60_000);
	const result = await readReport(1, 1, 1, start + 60_000);
	assert.equal(result.ledger.gap, true);
	assert.equal(result.ledger.items[0].ip, "2001:db8::1234");
});
test("command attempts deduplicate by identity, validate inputs, and paginate", async () => {
	const journal = Array.from(
		{ length: 30 },
		(_, i) =>
			`${start + i} ${i ? "accepted" : "failed"} 2001:db8::1 00000000-0000-4000-8000-${String(i).padStart(12, "0")}\n`,
	).join("");
	await recordAttempts(journal + `${start} failed <script> bad\n`, start + 60_000);
	await recordAttempts(journal, start + 60_000);
	const result = await readReport(1, 2, 1, start + 60_000);
	assert.equal(result.ledger.total, 30);
	assert.equal(result.ledger.items.length, 5);
	assert.equal(result.ledger.items.at(-1).kind, "failed");
});
test("host coverage follows location inheritance and omits deleted or disabled hosts", async () => {
	const host = {
		owner_user_id: 1,
		domain_names: ["example.test"],
		forward_host: "127.0.0.1",
		forward_port: 80,
		forward_scheme: "http",
		enabled: true,
		npmplus_auth_request: "anubis",
		locations: [
			{ path: "/inherit", npmplus_auth_request: "none" },
			{ path: "/api", npmplus_auth_request: "tinyauth" },
		],
	};
	await ProxyHost.query().insert(host);
	await ProxyHost.query().insert({ ...host, enabled: false });
	const result = await hostCoverage();
	assert.equal(result.total, 1);
	assert.equal(result.items[0].anubis, true);
	assert.deepEqual(
		result.items[0].locations.map((location) => location.anubis),
		[true, false],
	);
	assert.equal(JSON.stringify(result).includes("127.0.0.1"), false);
});
