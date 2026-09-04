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

test("CrowdSec alerts keep attacker details while stripping sensitive payloads", () => {
	const alerts = normalizeCrowdsecAlerts([
		{
			id: 9,
			scenario: "http-bad-user-agent",
			message: "blocked",
			start_at: "2026-09-03T00:00:00Z",
			stop_at: "2026-09-03T00:01:00Z",
			events_count: 2,
			events: [
				{
					timestamp: "2026-09-03T00:00:01Z",
					meta: [
						{ key: "source_ip", value: "203.0.113.50" },
						{ key: "method", value: "GET" },
						{ key: "target_uri", value: "/wp-login.php" },
						{ key: "http_user_agent", value: "curl/8.0" },
						// unknown or sensitive keys must be stripped
						{ key: "raw_request", value: "GET /wp-login.php HTTP/1.1" },
						{ key: "password", value: "hunter2" },
					],
				},
				{
					timestamp: "2026-09-03T00:00:02Z",
					meta: [{ key: "service", value: "http" }],
				},
			],
			// alert-level meta is context summaries; not attacker detail - dropped
			meta: [{ key: "sensitive", value: "not-for-the-browser" }],
			source: {
				ip: "203.0.113.50",
				cn: "DE",
				as_number: "64496",
				as_name: "Example ASN",
				range: "203.0.113.0/24",
				rdns: "host.example.com",
			},
		},
	]);

	assert.deepEqual(alerts, [
		{
			id: 9,
			scenario: "http-bad-user-agent",
			message: "blocked",
			start_at: "2026-09-03T00:00:00Z",
			stop_at: "2026-09-03T00:01:00Z",
			events_count: 2,
			source: {
				country: "DE",
				as_number: "64496",
				as_name: "Example ASN",
				range: "203.0.113.0/24",
				rdns: "host.example.com",
			},
			events: [
				{
					timestamp: "2026-09-03T00:00:01Z",
					meta: [
						{ key: "source_ip", value: "203.0.113.50" },
						{ key: "method", value: "GET" },
						{ key: "target_uri", value: "/wp-login.php" },
						{ key: "http_user_agent", value: "curl/8.0" },
					],
				},
				{
					timestamp: "2026-09-03T00:00:02Z",
					meta: [{ key: "service", value: "http" }],
				},
			],
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
