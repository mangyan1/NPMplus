// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import assert from "node:assert/strict";
// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import test from "node:test";
import type { CrowdsecDecision } from "../src/api/backend/getCrowdsecDecisions.ts";
import { midTruncate, presentScenarioId, scenarioCategory, scenarioLabel } from "../src/pages/Crowdsec/scenarios.ts";
import {
	attackMixSegments,
	decisionTarget,
	filterCrowdsecDecisions,
	sortCrowdsecDecisions,
} from "../src/pages/Crowdsec/utils.ts";

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

test("filter searches target and decision context case-insensitively", () => {
	const decisions = [decision(1, "192.0.2.1"), decision(2, "198.51.100.2", "ssh-bruteforce")];
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "SSH").map(({ id }) => id),
		[2],
	);
});

test("origin filter separates this instance's bans from community blocklist entries", () => {
	const decisions = [
		decision(1, "192.0.2.1"),
		{ ...decision(2, "198.51.100.2"), origin: "CAPI" },
		{ ...decision(3, "203.0.113.3"), origin: "cscli", scenario: "anubis-honeypot" },
	];
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "", "local").map(({ id }) => id),
		[1, 3],
	);
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "", "community").map(({ id }) => id),
		[2],
	);
	assert.equal(filterCrowdsecDecisions(decisions, "", "all").length, 3);
});

test("sorting keeps separate decisions for the same target", () => {
	const decisions = [decision(10, "192.0.2.1"), decision(11, "192.0.2.1")];
	assert.deepEqual(
		sortCrowdsecDecisions(decisions, "id", "desc").map(({ id }) => id),
		[11, 10],
	);
});

test("structured field tokens narrow the named field", () => {
	const decisions = [
		decision(1, "192.0.2.1"),
		decision(2, "198.51.100.2", "ssh-bruteforce"),
		{ ...decision(3, "203.0.113.3"), origin: "CAPI" },
	];
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "scenario:ssh").map(({ id }) => id),
		[2],
	);
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "origin:capi").map(({ id }) => id),
		[3],
	);
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "ip:198.51.").map(({ id }) => id),
		[2],
	);
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "type:ban").map(({ id }) => id),
		[1, 2, 3],
	);
});

test("field tokens combine with free-text words as an AND match", () => {
	const decisions = [
		decision(1, "192.0.2.1", "http-probing"),
		decision(2, "192.0.2.9", "ssh-bruteforce"),
		decision(3, "198.51.100.2", "ssh-bruteforce"),
	];
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "scenario:ssh 192.0.2.").map(({ id }) => id),
		[2],
	);
});

test("quoted field token values strip their quotes", () => {
	const decisions = [decision(1, "192.0.2.1"), decision(2, "198.51.100.2", "ssh-bruteforce")];
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, 'scenario:"ssh-bruteforce"').map(({ id }) => id),
		[2],
	);
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "scenario:'ssh-bruteforce'").map(({ id }) => id),
		[2],
	);
});

test("empty field token value is treated as free text", () => {
	const decisions = [decision(1, "192.0.2.1"), decision(2, "198.51.100.2")];
	assert.deepEqual(
		filterCrowdsecDecisions(decisions, "origin: 198").map(({ id }) => id),
		[2],
	);
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
