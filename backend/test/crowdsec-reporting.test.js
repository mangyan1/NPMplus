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
const request = async (path, query = {}, params = {}) => {
	let body;
	const res = {
		set() {
			return this;
		},
		locals: { access: { canAdmin: () => true } },
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
	await handler({ query, params }, res);
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

test("the per-address alert list admits when the cap hides older alerts", async (t) => {
	fixture(t, { alerts: Array.from({ length: 9 }, (_, index) => alert(index + 1)) });
	const page = await request("/alerts", { scope: "Ip", value: "203.0.113.7" });
	// the LAPI page has no total, so the sixth row is the only evidence that
	// this address has more alert history than the panel shows
	assert.equal(page.items.length, 5);
	assert.equal(page.limit, 5);
	assert.equal(page.truncated, true);
});

test("a per-address alert list shorter than the cap is reported as complete", async (t) => {
	fixture(t, { alerts: [alert(1), alert(2)] });
	const page = await request("/alerts", { scope: "Ip", value: "203.0.113.7" });
	assert.equal(page.items.length, 2);
	assert.equal(page.limit, 5);
	assert.equal(page.truncated, false);
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
		request("/history/alerts", { cursor: `${first.next_cursor}x`, search: "ip:2001:db8::1234" }),
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
		alert(i + 1, { created_at: `${base}.${String(99999 - i).padStart(9, "0")}Z` }),
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

test("attacker timeline requests one IP and rejects unrelated or community decisions", async (t) => {
	const calls = [];
	t.mock.method(globalThis, "fetch", async (input) => {
		const url = new URL(input);
		calls.push(url);
		if (url.pathname.endsWith("/login")) return Response.json({ token: "fixture" });
		if (url.pathname.endsWith("/alerts"))
			return Response.json([
				alert(1, { source: { ip: "192.0.2.1" } }),
				alert(2, { source: { ip: "192.0.2.10" } }),
				alert(3, { source: { ip: "192.0.2.1" }, simulated: true }),
			]);
		return Response.json([
			decision(1, { value: "192.0.2.1" }),
			decision(2, { value: "192.0.2.10" }),
			decision(3, { value: "192.0.2.1", origin: "capi" }),
		]);
	});
	const result = await request("/attackers/timeline", { ip: "192.0.2.1" });
	assert.deepEqual(
		result.items.map((item) => item.id),
		[1],
	);
	assert.deepEqual(
		result.decisions.map((item) => item.id),
		[1],
	);
	assert.equal(result.decisions_available, true);
	assert.equal(calls.find((url) => url.pathname.endsWith("/alerts")).searchParams.get("value"), "192.0.2.1");
	assert.equal(calls.find((url) => url.pathname.endsWith("/decisions")).searchParams.get("ip"), "192.0.2.1");
});

test("attacker events paginate retained sanitized evidence and flag missing records", async (t) => {
	t.mock.method(globalThis, "fetch", async (input) => {
		if (new URL(input).pathname.endsWith("/login")) return Response.json({ token: "fixture" });
		return Response.json(
			alert(1, {
				events_count: 50,
				events: Array.from({ length: 30 }, (_, i) => ({
					timestamp: String(i),
					meta: [{ key: "uri", value: `/path-${i}?secret=hidden` }],
				})),
			}),
		);
	});
	const result = await request("/attackers/events/:id", { page: "2" }, { id: "1" });
	assert.equal(result.retained, 30);
	assert.equal(result.truncated, true);
	assert.equal(result.has_next, false);
	assert.equal(result.alert.events.length, 5);
	assert.equal(result.alert.events[0].meta[0].value, "/path-25");
});

test("cursor rejects malformed recording times rather than inventing a boundary", async (t) => {
	fixture(t, { alerts: [alert(1, { created_at: "invalid" })] });
	// Preserve the malformed fixture through the fake upstream time filter.
	t.mock.method(globalThis, "fetch", async () => Response.json([alert(1, { created_at: "invalid" })]));
	await assert.rejects(request("/history/alerts", { cursor: "" }), { message: "crowdsec.invalid-response" });
});
