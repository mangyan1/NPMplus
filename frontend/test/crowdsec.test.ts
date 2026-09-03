// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import assert from "node:assert/strict";
// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import test from "node:test";
import type { CrowdsecDecision } from "../src/api/backend/getCrowdsecDecisions.ts";
import { decisionTarget, filterCrowdsecDecisions, sortCrowdsecDecisions } from "../src/pages/Crowdsec/utils.ts";

const decision = (id: number, value: string, scenario = "http-probing"): CrowdsecDecision => ({
	id,
	uuid: `uuid-${id}`,
	scope: "Ip",
	value,
	type: "ban",
	origin: "crowdsec",
	scenario,
	duration: "4h",
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
