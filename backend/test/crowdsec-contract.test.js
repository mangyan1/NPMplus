import assert from "node:assert/strict";
import test from "node:test";
import {
	hasCrowdsecAdminAccess,
	normalizeCrowdsecAlerts,
	normalizeCrowdsecDecisions,
	parseCrowdsecDecisionId,
} from "../lib/crowdsec-contract.js";

const notArrayPattern = /not an array/;
const missingIdPattern = /missing its id/;

test("CrowdSec decisions are reduced to the stable public contract", () => {
	const decisions = normalizeCrowdsecDecisions([
		{
			id: 42,
			uuid: "uuid-42",
			scope: "Ip",
			value: "192.0.2.42",
			type: "ban",
			origin: "crowdsec",
			scenario: "http-probing",
			duration: "3h59m",
			until: "should-not-leak",
			simulated: true,
		},
	]);

	assert.deepEqual(decisions, [
		{
			id: 42,
			uuid: "uuid-42",
			scope: "Ip",
			value: "192.0.2.42",
			type: "ban",
			origin: "crowdsec",
			scenario: "http-probing",
			duration: "3h59m",
		},
	]);
});

test("CrowdSec alert timestamps are retained while event payloads are stripped", () => {
	const alerts = normalizeCrowdsecAlerts([
		{
			id: 9,
			scenario: "http-bad-user-agent",
			message: "blocked",
			start_at: "2026-09-03T00:00:00Z",
			stop_at: "2026-09-03T00:01:00Z",
			events_count: 4,
			events: [{ meta: { secret: "not-for-the-browser" } }],
			meta: [{ key: "sensitive", value: "not-for-the-browser" }],
			source: { ip: "192.0.2.9" },
		},
	]);

	assert.deepEqual(alerts, [
		{
			id: 9,
			scenario: "http-bad-user-agent",
			message: "blocked",
			start_at: "2026-09-03T00:00:00Z",
			stop_at: "2026-09-03T00:01:00Z",
			events_count: 4,
		},
	]);
});

test("CrowdSec payload validation rejects malformed upstream responses", () => {
	assert.deepEqual(normalizeCrowdsecDecisions(null), []);
	assert.deepEqual(normalizeCrowdsecAlerts(null), []);
	assert.throws(() => normalizeCrowdsecDecisions({ items: [] }), notArrayPattern);
	assert.throws(() => normalizeCrowdsecAlerts([{ id: 0 }]), missingIdPattern);
});

test("CrowdSec decision IDs must be positive safe integers", () => {
	assert.equal(parseCrowdsecDecisionId(7), 7);
	assert.equal(parseCrowdsecDecisionId("8"), 8);
	assert.equal(parseCrowdsecDecisionId("8.5"), null);
	assert.equal(parseCrowdsecDecisionId(0), null);
	assert.equal(parseCrowdsecDecisionId("not-a-number"), null);
});

test("CrowdSec endpoints require a positive admin permission result", () => {
	assert.equal(hasCrowdsecAdminAccess({ granted: true }), true);
	assert.equal(hasCrowdsecAdminAccess(null), false);
	assert.equal(hasCrowdsecAdminAccess(false), false);
});
