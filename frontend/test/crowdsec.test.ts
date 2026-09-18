// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import assert from "node:assert/strict";
// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import { readFileSync } from "node:fs";
// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import test from "node:test";
import type { CrowdsecDecision, CrowdsecMetrics } from "../src/api/backend/getCrowdsecDecisions.ts";
import { midTruncate, presentScenarioId, scenarioCategory, scenarioLabel } from "../src/pages/Crowdsec/scenarios.ts";
import { appsecStatus, appsecTrafficAvailable, boundedCount, notificationPlan } from "../src/pages/Crowdsec/shared.ts";
import { attackMixSegments, decisionTarget } from "../src/pages/Crowdsec/utils.ts";

const decision = (id: number, value: string, scenario = "http-probing"): CrowdsecDecision => ({
	id,
	uuid: `uuid-${id}`,
	scope: "Ip",
	value,
	type: "ban",
	origin: "crowdsec",
	scenario,
	duration: "4h",
	createdAt: "",
	until: "",
	simulated: false,
});

test("attack mix segments group scenarios by attack type and add a residual other slice", () => {
	assert.deepEqual(attackMixSegments([{ name: "crowdsecurity/http-probing", count: 6 }], 10), [
		{ name: "probing", count: 6, share: 0.6, color: 0 },
		{ name: "", count: 4, share: 0.4, color: -1 },
	]);
});

test("attack mix shares sum to one, merge same-type scenarios, and skip empty entries", () => {
	const segments = attackMixSegments(
		[
			{ name: "crowdsecurity/http-probing", count: 1 },
			{ name: "", count: 5 },
			{ name: "crowdsecurity/ssh-bf", count: 1 },
			{ name: "crowdsecurity/vpatch-cve-2024-1234", count: 2 },
		],
		4,
	);
	assert.equal(
		segments.reduce((sum, item) => sum + item.share, 0),
		1,
	);
	assert.deepEqual(
		segments.map(({ name }) => name),
		["waf", "brute-force", "probing"],
	);
	assert.deepEqual(attackMixSegments([{ name: "crowdsecurity/http-probing", count: 3 }], 0), []);
});

test("decision target includes non-IP scopes", () => {
	assert.equal(decisionTarget({ ...decision(1, "US"), scope: "Country" }), "Country: US");
	assert.equal(decisionTarget(decision(2, "192.0.2.2")), "192.0.2.2");
});

test("known scenario families get readable labels and categories", () => {
	assert.deepEqual(presentScenarioId("crowdsecurity/http-probing"), {
		raw: "crowdsecurity/http-probing",
		label: "HTTP probing",
		category: "probing",
	});
	assert.equal(scenarioLabel("crowdsecurity/ssh-bf"), "SSH brute force");
	assert.equal(scenarioCategory("crowdsecurity/http-generic-bf"), "brute-force");
	assert.equal(scenarioLabel("crowdsecurity/vpatch-cve-2024-1234"), "vPatch CVE 2024 1234");
	assert.equal(scenarioCategory("crowdsecurity/vpatch-cve-2024-1234"), "waf");
	assert.equal(scenarioCategory("crowdsecurity/http-sqli-probing"), "injection");
	assert.equal(scenarioCategory("crowdsecurity/http-bad-user-agent"), "suspicious-client");
	assert.equal(scenarioLabel("manual/web-ui"), "Manual ban");
	assert.equal(scenarioCategory("anubis-honeypot"), "honeypot");
	assert.equal(scenarioLabel("anubis-honeypot"), "Anubis honeypot");
	assert.equal(scenarioCategory("update : +15000/-0 IPs"), "sync");
	assert.equal(scenarioLabel("update : +15000/-0 IPs"), "Community blocklist sync");
});

test("unknown scenarios keep their identifier instead of a wrong guess", () => {
	assert.equal(scenarioLabel("crowdsecurity/some-new-scenario"), "Some new scenario");
	assert.equal(scenarioCategory("crowdsecurity/some-new-scenario"), "other");
	assert.equal(scenarioLabel("http-probing"), "HTTP probing");
});

test("mid truncation keeps both ends of a long name", () => {
	assert.equal(midTruncate("short"), "short");
	assert.equal(midTruncate("crowdsecurity/http-crawl-non-statics"), "crowdsecurit…non-statics");
	const long = "crowdsecurity/http-crawl-non-statics-on-wordpress-sites";
	const truncated = midTruncate(long, 40);
	assert.equal(truncated.length, 40);
	assert.equal(truncated.startsWith("crowdsecurit"), true);
	assert.equal(long.endsWith(truncated.slice(-12)), true);
});

test("bounded and missing counts remain distinguishable from exact zero", () => {
	assert.equal(boundedCount(null), "—");
	assert.equal(boundedCount(0), 0);
	assert.equal(boundedCount(500, true), "500+");
});

test("WAF status distinguishes missing, stale, disabled and exposed metrics", () => {
	const metrics = {
		available: true,
		appsecConfigured: true,
		appsecMetricsPresent: true,
		appsecRequests: 0,
		appsecBlocked: 0,
		appsecPassed: 0,
	} as CrowdsecMetrics;
	assert.equal(appsecTrafficAvailable(metrics), true);
	assert.equal(appsecTrafficAvailable({ ...metrics, appsecRequests: null }), false);
	assert.equal(appsecTrafficAvailable({ ...metrics, available: false }), false);
	assert.equal(appsecStatus(metrics, true).tone, "orange");
	assert.equal(appsecStatus({ ...metrics, available: false }).label, "crowdsec.appsec.status-monitoring-unavailable");
	assert.equal(appsecStatus({ ...metrics, appsecConfigured: false }).label, "crowdsec.appsec.status-disabled");
	assert.equal(appsecStatus(metrics).label, "crowdsec.appsec.status-active");
});

test("an ongoing ban signal is announced once, however much its count moves", () => {
	// the dedupe marker is per type; keying it on the count (bans-3, bans-4)
	// re-notified the operator on every poll that saw a different number
	const seen = new Set<string>();
	const first = notificationPlan([{ type: "active-bans", count: 3 }], false, (type) => seen.has(type));
	assert.deepEqual(first, { announce: "active-bans", forget: [] });
	seen.add(first.announce as string);
	assert.equal(notificationPlan([{ type: "active-bans", count: 4 }], false, (type) => seen.has(type)).announce, null);
	assert.equal(
		notificationPlan([{ type: "active-bans", count: 99 }], false, (type) => seen.has(type)).announce,
		null,
	);
});

test("a signal that clears is forgotten, so a recurrence notifies again", () => {
	const seenType = notificationPlan([], false, (type) => type === "active-bans");
	assert.deepEqual(seenType, { announce: null, forget: ["active-bans"] });
	// after the marker is dropped the same condition announces again
	assert.equal(notificationPlan([{ type: "active-bans" }], false, () => false).announce, "active-bans");
});

test("an outage announces itself and leaves the other markers untouched", () => {
	// the insight signals are unknown during an outage, so forgetting them would
	// re-notify a ban wave the operator was already told about
	assert.deepEqual(
		notificationPlan(undefined, true, () => false),
		{ announce: "lapi", forget: [] },
	);
	assert.deepEqual(
		notificationPlan(undefined, true, (type) => type === "lapi"),
		{ announce: null, forget: [] },
	);
	// recovery forgets the outage marker so the next one is announced
	assert.deepEqual(
		notificationPlan([], false, (type) => type === "lapi"),
		{ announce: null, forget: ["lapi"] },
	);
});

test("every telemetry status the API can report has an English label", () => {
	// EnforcementTelemetry builds its label id from the status string, so an
	// unlabelled status renders the raw id. Keep this list in step with the
	// Layer union in src/api/backend/getSecurityTelemetry.ts.
	const file = new URL("../translations/ui/en.json", import.meta.url);
	const messages = JSON.parse(readFileSync(file, "utf8")) as Record<string, string>;
	for (const status of ["observed", "stale", "unavailable", "disabled"])
		assert.ok(messages[`crowdsec.telemetry.${status}`], `crowdsec.telemetry.${status} has no English label`);
});

test("a spike outranks an ongoing ban count", () => {
	const both = notificationPlan([{ type: "active-bans" }, { type: "attack-spike" }], false, () => false);
	assert.equal(both.announce, "attack-spike");
});
