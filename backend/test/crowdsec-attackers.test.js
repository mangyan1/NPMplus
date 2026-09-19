import "./helpers/environment.js";
import assert from "node:assert/strict";
import { test } from "node:test";
import { createAttackerCatalog } from "../internal/crowdsec-attackers.js";
import { isAttackAlert, normalizeCrowdsecAlerts } from "../lib/crowdsec-contract.js";

const alert = (id, ip, observedAt) => ({
	id,
	source: { ip, country: "CA", as_name: "Example network", as_number: "64500" },
	start_at: observedAt,
	events_count: 3,
	scenario: "crowdsecurity/http-probing",
	events: [{ meta: [{ key: "target_host", value: "example.test" }] }],
});
const time = "2026-09-19T12:00:00Z";
test("upstream alert kinds exclude custom-reason manual bans and remote intelligence", () => {
	for (const kind of ["cscli", "capi", "papi"]) {
		const [item] = normalizeCrowdsecAlerts([{ id: 1, kind, scenario: "custom reason" }]);
		assert.equal(isAttackAlert(item), false);
	}
	assert.equal(isAttackAlert({ scenario: "anubis-honeypot", kind: "cscli" }), true);
	assert.equal(isAttackAlert({ scenario: "manual 'ban' from 'localhost'" }), false);
	assert.equal(isAttackAlert({ scenario: "crowdsecurity/http-probing", kind: "crowdsec" }), true);
});
test("attacker snapshots group canonical IPs across older batches without duplicate counts", async () => {
	let calls = 0;
	const read = createAttackerCatalog(async () => {
		calls++;
		return {
			items: [alert(calls, calls % 2 ? "2001:db8::1" : "2001:0db8:0:0:0:0:0:1", time)],
			scanned: 1,
			start: time,
			end: time,
			has_next: calls < 5,
			next_cursor: String(calls),
			truncated: false,
		};
	});
	const first = await read({ advance: "-" });
	assert.equal(first.items.length, 1);
	assert.equal(first.items[0].alerts, 4);
	assert.equal(first.complete, false);
	const next = await read({ session: first.session, advance: first.revision });
	assert.equal(next.items[0].alerts, 5);
	assert.equal(next.complete, true);
	await read({ session: first.session, advance: first.revision });
	assert.equal(calls, 5);
	assert.equal((await read({ session: first.session, search: "missing" })).matched, 0);
	assert.equal((await read({ session: first.session, search: "example.test" })).matched, 1);
	await assert.rejects(read({ session: first.session, windowHours: 1 }), /expired/);
	await assert.rejects(read({ session: "unknown" }), /expired/);
});
test("attacker pagination and truncation never claim a complete inventory", async () => {
	const read = createAttackerCatalog(async () => ({
		items: Array.from({ length: 30 }, (_, i) => alert(i + 1, `192.0.2.${i + 1}`, time)),
		scanned: 30,
		start: time,
		end: time,
		has_next: false,
		next_cursor: null,
		truncated: true,
	}));
	const first = await read({});
	assert.equal(first.items.length, 25);
	assert.equal(first.has_next, true);
	assert.equal(first.complete, false);
	assert.equal(first.truncated, true);
	const next = await read({ session: first.session, page: 2 });
	assert.equal(next.items.length, 5);
	assert.equal(new Set([...first.items, ...next.items].map((item) => item.ip)).size, 30);
});
test("on-demand event pages retain sanitization beyond the ten-event summary", () => {
	const raw = {
		id: 1,
		events_count: 30,
		events: Array.from({ length: 30 }, (_, i) => ({
			timestamp: String(i),
			meta: [
				{ key: "uri", value: `/path-${i}?token=secret#fragment` },
				{ key: "authorization", value: "secret" },
			],
		})),
	};
	const [page] = normalizeCrowdsecAlerts([raw], { eventOffset: 25, eventLimit: 25 });
	assert.equal(page.events.length, 5);
	assert.deepEqual(page.events[0].meta, [{ key: "uri", value: "/path-25" }]);
	assert.equal(normalizeCrowdsecAlerts([raw])[0].events.length, 10);
});
