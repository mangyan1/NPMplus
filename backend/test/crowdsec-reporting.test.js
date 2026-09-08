import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import test from "node:test";

process.env.CROWDSEC_LAPI_KEY_FILE = "/data/crowdsec/test.key";
process.env.CROWDSEC_LAPI_MACHINE_KEY_FILE = "/data/crowdsec/test.key";
process.env.HOME_LATITUDE = "0";
process.env.HOME_LONGITUDE = "0";
await mkdir("/data/crowdsec", { recursive: true });
await writeFile("/data/crowdsec/test.key", "reporting-fixture");
const { default: router } = await import("../routes/crowdsec.js");

const decision = (id, extra = {}) => ({
	id,
	value: `203.0.113.${id % 255}`,
	origin: "cscli",
	scope: "Ip",
	type: "ban",
	scenario: "detection",
	...extra,
});
const alert = (id, extra = {}) => ({
	id,
	scenario: "detection",
	created_at: new Date(Date.now() - 10_000 * id).toISOString(),
	...extra,
});
const request = async (path, query = {}) => {
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
		.find((layer) => layer.route?.path === path)
		.route.stack.find((layer) => layer.method === "get").handle;
	await handler({ query }, res);
	return body;
};
const fixture = (t, { decisions = [], alerts = [], fallback = false } = {}) => {
	t.mock.method(globalThis, "fetch", async (input) => {
		const url = new URL(input);
		if (url.pathname.endsWith("/login")) return Response.json({ token: "fixture" });
		const limit = Number(url.searchParams.get("limit"));
		if (url.pathname.endsWith("/alerts")) {
			if (fallback && limit > 25)
				return new Response("[]", { headers: { "content-length": String(13 * 1024 * 1024) } });
			const before = url.searchParams.get("created_before");
			const selected =
				before === null
					? alerts
					: alerts.filter((item) => Date.parse(item.created_at) <= Date.now() - Number.parseFloat(before));
			return Response.json(selected.slice(0, limit));
		}
		return Response.json(decisions.slice(0, limit));
	});
};

test("decision pagination reports the whole bounded match count without false truncation", async (t) => {
	fixture(t, { decisions: Array.from({ length: 60 }, (_, index) => decision(index + 1)) });
	for (const search of ["", "203.0.113."]) {
		const page = await request("/decisions", { page: "1", page_size: "25", search });
		assert.equal(page.items.length, 25);
		assert.equal(page.matched, 60);
		assert.equal(page.truncated, false);
		assert.equal(page.has_next, true);
	}
});

test("the decision cap never offers a next page that the API refuses", async (t) => {
	fixture(t, { decisions: Array.from({ length: 501 }, (_, index) => decision(index + 1)) });
	const page = await request("/decisions", { page: "20", page_size: "25" });
	assert.equal(page.items.length, 25);
	assert.equal(page.matched, 500);
	assert.equal(page.truncated, true);
	assert.equal(page.has_next, false);
});

test("bookkeeping alerts do not prematurely end attack-history pagination", async (t) => {
	fixture(t, {
		alerts: [
			...Array.from({ length: 30 }, (_, i) => alert(i + 1, { scenario: "update : +1/-0 IPs" })),
			...Array.from({ length: 60 }, (_, i) => alert(i + 31)),
		],
	});
	const page = await request("/history/alerts", { page: "1", page_size: "25" });
	assert.equal(page.items.length, 25);
	assert.equal(page.matched, 60);
	assert.equal(page.has_next, true);
	assert.equal(page.truncated, false);
});

test("fallback samples are always marked incomplete and cannot emit spike signals", async (t) => {
	fixture(t, { fallback: true, alerts: Array.from({ length: 25 }, (_, i) => alert(i + 1)) });
	const insights = await request("/insights", { window_hours: "6" });
	assert.equal(insights.sampled, true);
	assert.equal(
		insights.signals.some((signal) => signal.type === "attack-spike"),
		false,
	);
	const page = await request("/history/alerts", {});
	assert.equal(page.truncated, true);
});

test("rolling activity buckets include the oldest part of a one-hour window", async (t) => {
	fixture(t, {
		alerts: [
			alert(1, { created_at: new Date(Date.now() - 59 * 60_000).toISOString() }),
			alert(2),
			alert(3, { simulated: true }),
			alert(4, { scenario: "manual/web-ui" }),
		],
	});
	const insights = await request("/insights", { window_hours: "1" });
	assert.equal(insights.alert_count, 2);
	assert.equal(
		insights.activity.reduce((sum, bucket) => sum + bucket.count, 0),
		2,
	);
});

test("local and honeypot counts exclude simulations and surface count and row caps separately", async (t) => {
	fixture(t, {
		decisions: Array.from({ length: 60 }, (_, i) =>
			decision(i + 1, { scenario: "anubis-honeypot", simulated: i === 0 }),
		),
	});
	const anubis = await request("/anubis");
	assert.equal(anubis.honeypot.activeCount, 59);
	assert.equal(anubis.honeypot.truncated, false);
	assert.equal(anubis.honeypot.itemsTruncated, true);
	assert.equal(anubis.honeypot.items.length, 25);
	const insights = await request("/insights");
	assert.equal(insights.local_active_decisions, 0);
});

test("a successful HTTP response without CrowdSec metrics is unavailable, not healthy", async (t) => {
	t.mock.method(globalThis, "fetch", async () => new Response("<html>wrong endpoint</html>"));
	const metrics = await request("/metrics");
	assert.equal(metrics.available, false);
	assert.equal(metrics.error, "crowdsec.metrics-unavailable");
});

test("history and charts use the alert start time used by LAPI's since filter", async (t) => {
	fixture(t, { alerts: [alert(1, { start_at: new Date(Date.now() - 2 * 3600_000).toISOString() }), alert(2)] });
	const insights = await request("/insights", { window_hours: "1" });
	const history = await request("/history/alerts", { window_hours: "1" });
	assert.equal(insights.alert_count, 1);
	assert.equal(
		insights.activity.reduce((sum, bucket) => sum + bucket.count, 0),
		1,
	);
	assert.equal(history.matched, 1);
	assert.equal(history.items[0].id, 2);
});

test("cursor exploration reaches beyond 500 alerts without duplicates or growing request limits", async (t) => {
	const alerts = Array.from({ length: 650 }, (_, i) => alert(i + 1));
	fixture(t, { alerts });
	let cursor = "";
	const ids = [];
	for (let page = 1; page <= 40; page++) {
		const result = await request("/history/alerts", { cursor, page: String(page), window_hours: "24" });
		assert.equal(result.scan_mode, true);
		assert.ok(result.items.length <= 25);
		ids.push(...result.items.map((item) => item.id));
		if (!result.has_next) {
			assert.equal(result.truncated, false);
			break;
		}
		cursor = result.next_cursor;
	}
	assert.deepEqual(
		ids,
		alerts.map((item) => item.id),
	);
});

test("empty filtered batches keep their older cursor, including IPv6 offenders", async (t) => {
	const alerts = Array.from({ length: 35 }, (_, i) =>
		alert(i + 1, { source: { ip: i === 30 ? "2001:db8::1234" : "203.0.113.1" } }),
	);
	fixture(t, { alerts });
	const first = await request("/history/alerts", { cursor: "", search: "ip:2001:db8::1234" });
	assert.equal(first.items.length, 0);
	assert.equal(first.has_next, true);
	const next = await request("/history/alerts", { cursor: first.next_cursor, search: "ip:2001:db8::1234" });
	assert.equal(next.items[0].source.ip, "2001:db8::1234");
	await assert.rejects(
		request("/history/alerts", { cursor: first.next_cursor, search: "changed" }),
		/cursor-invalid/,
	);
	await assert.rejects(
		request("/history/alerts", { cursor: first.next_cursor + "x", search: "ip:2001:db8::1234" }),
		/cursor-invalid/,
	);
});

test("dense timestamp ties stop explicitly instead of skipping unseen alerts", async (t) => {
	const created_at = new Date(Date.now() - 60_000).toISOString();
	fixture(t, { alerts: Array.from({ length: 150 }, (_, i) => alert(150 - i, { created_at })) });
	let cursor = "";
	let stopped = false;
	const ids = [];
	for (let i = 0; i < 8; i++) {
		const result = await request("/history/alerts", { cursor });
		ids.push(...result.items.map((item) => item.id));
		if (!result.has_next) {
			assert.equal(result.truncated, true);
			stopped = true;
			break;
		}
		cursor = result.next_cursor;
	}
	assert.equal(stopped, true);
	assert.equal(ids.length, new Set(ids).size);
	assert.equal(ids.length, 101);
});

test("cursor fallback stays bounded and malformed recording times fail visibly", async (t) => {
	fixture(t, { alerts: Array.from({ length: 30 }, (_, i) => alert(i + 1)), fallback: true });
	const result = await request("/history/alerts", { cursor: "" });
	assert.equal(result.items.length, 25);
	assert.equal(result.has_next, true);
});

test("cursor preserves nanosecond recording order and expires after one hour", async (t) => {
	const base = new Date(Date.now() - 60_000).toISOString().slice(0, 19);
	const alerts = Array.from({ length: 30 }, (_, i) =>
		alert(i + 1, { created_at: base + "." + String(99999 - i).padStart(9, "0") + "Z" }),
	);
	fixture(t, { alerts });
	const first = await request("/history/alerts", { cursor: "" });
	const last = await request("/history/alerts", { cursor: first.next_cursor });
	assert.deepEqual(
		[...first.items, ...last.items].map((item) => item.id),
		alerts.map((item) => item.id),
	);
	const later = Date.now() + 3600_001;
	t.mock.method(Date, "now", () => later);
	await assert.rejects(request("/history/alerts", { cursor: first.next_cursor }), {
		message: "crowdsec.history.cursor-invalid",
	});
});

test("cursor rejects malformed recording times rather than inventing a boundary", async (t) => {
	fixture(t, { alerts: [alert(1, { created_at: "invalid" })] });
	// Preserve the malformed fixture through the fake upstream time filter.
	t.mock.method(globalThis, "fetch", async () => Response.json([alert(1, { created_at: "invalid" })]));
	await assert.rejects(request("/history/alerts", { cursor: "" }), { message: "crowdsec.invalid-response" });
});
