import assert from "node:assert/strict";
import test from "node:test";
import {
	crowdsecAlertTarget,
	filterCrowdsecAlerts,
	hasCrowdsecAdminAccess,
	isBlocklistSyncAlert,
	normalizeCrowdsecAlerts,
	normalizeCrowdsecDecisions,
	parseCrowdsecDecisionId,
	parsePrometheusText,
	summarizeAppsecRules,
	summarizeCrowdsecMetrics,
	validateManualBan,
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
			created_at: "2026-09-03T00:00:00Z",
			until: "2026-09-03T04:00:00Z",
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
			created_at: "2026-09-03T00:00:00Z",
			until: "2026-09-03T04:00:00Z",
			simulated: true,
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
			created_at: "2026-09-03T00:01:01Z",
			machine_id: "npmplus",
			simulated: false,
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
				scope: "Ip",
				value: "203.0.113.50",
				cn: "DE",
				as_number: "64496",
				as_name: "Example ASN",
				range: "203.0.113.0/24",
				rdns: "host.example.com",
				latitude: 51.16,
				longitude: 10.45,
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
			created_at: "2026-09-03T00:01:01Z",
			machine_id: "npmplus",
			simulated: false,
			events_count: 2,
			source: {
				ip: "203.0.113.50",
				scope: "Ip",
				value: "203.0.113.50",
				country: "DE",
				as_number: "64496",
				as_name: "Example ASN",
				range: "203.0.113.0/24",
				rdns: "host.example.com",
				latitude: 51.16,
				longitude: 10.45,
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

test("CrowdSec alert history can be searched and filtered without exposing raw events", () => {
	const alerts = normalizeCrowdsecAlerts([
		{
			id: 1,
			scenario: "crowdsecurity/http-probing",
			message: "scan",
			source: { ip: "203.0.113.8", cn: "CA" },
			events: [{ meta: [{ key: "target_host", value: "admin.example.test" }] }],
		},
		{ id: 2, scenario: "crowdsecurity/ssh-bf", source: { ip: "198.51.100.9", cn: "US" } },
	]);
	assert.equal(crowdsecAlertTarget(alerts[0]), "admin.example.test");
	assert.deepEqual(
		filterCrowdsecAlerts(alerts, { country: "ca" }).map(({ id }) => id),
		[1],
	);
	assert.deepEqual(
		filterCrowdsecAlerts(alerts, { scenario: "crowdsecurity/ssh-bf" }).map(({ id }) => id),
		[2],
	);
	assert.deepEqual(
		filterCrowdsecAlerts(alerts, { search: "admin.example" }).map(({ id }) => id),
		[1],
	);
	assert.deepEqual(
		filterCrowdsecAlerts(alerts, { search: "country:ca target:admin.example" }).map(({ id }) => id),
		[1],
	);
	assert.deepEqual(
		filterCrowdsecAlerts(alerts, { search: "scenario:ssh ip:198.51" }).map(({ id }) => id),
		[2],
	);
});

test("Prometheus metrics are parsed and summarized", () => {
	const samples = parsePrometheusText(`
# HELP cs_parser_hits_total parser hits
cs_parser_hits_total{source="nginx"} 10
cs_parser_hits_ok_total{source="nginx"} 8
cs_appsec_reqs_total 12
cs_appsec_block_total 3
cs_lapi_request_duration_seconds_sum 1.5
cs_lapi_request_duration_seconds_count 3
cs_lapi_bouncer_requests_total{bouncer="npmplus"} 4
cs_lapi_decisions_ok_total 3
cs_active_decisions{origin="crowdsec",action="ban"} 2
cs_active_decisions{origin="cscli",action="ban"} 1
cs_active_decisions{origin="CAPI",action="ban"} 50000
cs_active_decisions{origin="lists",action="ban"} 100
not valid
`);
	assert.equal(samples.length, 12);
	assert.deepEqual(samples[0].labels, { source: "nginx" });
	assert.deepEqual(summarizeCrowdsecMetrics(samples), {
		active_decisions: 50103,
		local_active_decisions: 3,
		community_active_decisions: 50100,
		decision_origins: [
			{ name: "capi", count: 50000 },
			{ name: "lists", count: 100 },
			{ name: "crowdsec", count: 2 },
			{ name: "cscli", count: 1 },
		],
		alerts: null,
		appsec_metrics_present: true,
		appsec_requests: 12,
		appsec_blocked: 3,
		appsec_passed: 9,
		appsec_block_rate: 0.25,
		bouncer_requests: 4,
		bouncer_decision_hits: 3,
		machine_requests: null,
		parser_hits: 10,
		parser_metric_scope: "events",
		parser_success_rate: 0.8,
		whitelist_hits: null,
		average_lapi_ms: 500,
		average_parsing_ms: null,
	});
});

test("parser node counters are used when source-level parser metrics are absent", () => {
	const summary = summarizeCrowdsecMetrics(
		parsePrometheusText(`
cs_node_hits_total{type="parser",name="crowdsecurity/nginx-logs"} 10
cs_node_hits_ok_total{type="parser",name="crowdsecurity/nginx-logs"} 8
`),
	);
	assert.equal(summary.parser_hits, 10);
	assert.equal(summary.parser_success_rate, 0.8);
});

test("decision origin totals degrade safely when an older metric has no origin label", () => {
	const summary = summarizeCrowdsecMetrics(parsePrometheusText("cs_active_decisions 7"));
	assert.equal(summary.active_decisions, 7);
	assert.equal(summary.local_active_decisions, null);
	assert.equal(summary.community_active_decisions, null);
});

test("community blocklist sync alerts are separated from attacker alerts", () => {
	const alerts = normalizeCrowdsecAlerts([
		{ id: 1, scenario: "crowdsecurity/http-probing", source: { ip: "192.0.2.10" } },
		{ id: 2, scenario: "update : +15000/-0 IPs", source: {} },
		{ id: 3, scenario: "update : +512/-0 IPs", source: {} },
		{ id: 4, scenario: "crowdsecurity/vpatch-CVE-2024-1234", source: { ip: "192.0.2.11" } },
	]);
	const attacks = normalizeCrowdsecAlerts(alerts).filter((alert) => !isBlocklistSyncAlert(alert));
	assert.deepEqual(
		attacks.map(({ id }) => id),
		[1, 4],
	);
	// the sync scenario string comes from capi; anything else is an attack
	assert.equal(isBlocklistSyncAlert(normalizeCrowdsecAlerts([{ id: 5, scenario: "update : +1/-0 IPs" }])[0]), true);
	assert.equal(
		isBlocklistSyncAlert(normalizeCrowdsecAlerts([{ id: 6, scenario: "crowdsecurity/http-bf" }])[0]),
		false,
	);
	assert.equal(isBlocklistSyncAlert(normalizeCrowdsecAlerts([{ id: 7, scenario: "" }])[0]), false);
});

test("appsec rule hits are grouped per rule name and ranked", () => {
	const summary = summarizeAppsecRules(
		parsePrometheusText(`
cs_appsec_rule_hits{rule_name="crowdsecurity/vpatch-CVE-2017-9841",type="inband",appsec_engine="default",source="npmplus"} 38
cs_appsec_rule_hits{rule_name="crowdsecurity/http-sqli-probing",type="inband",appsec_engine="default",source="npmplus"} 12
cs_appsec_rule_hits{rule_name="crowdsecurity/vpatch-CVE-2017-9841",type="outband",appsec_engine="default",source="npmplus"} 4
cs_appsec_rule_hits{rule_name="crowdsecurity/vpatch-CVE-2021-9999",type="inband",appsec_engine="default",source="npmplus"} 1
cs_parser_hits_total{source="nginx"} 10
`),
	);
	assert.deepEqual(summary, [
		{ name: "crowdsecurity/vpatch-CVE-2017-9841", count: 42 },
		{ name: "crowdsecurity/http-sqli-probing", count: 12 },
		{ name: "crowdsecurity/vpatch-CVE-2021-9999", count: 1 },
	]);
});

test("appsec rule summary is empty without rule hits", () => {
	assert.deepEqual(summarizeAppsecRules(parsePrometheusText("cs_appsec_reqs_total 12")), []);
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

test("manual ban input accepts ips, cidr ranges, and valid durations", () => {
	assert.deepEqual(validateManualBan({ value: "192.0.2.10", duration: "4h" }), []);
	assert.deepEqual(validateManualBan({ value: "2001:db8::1", duration: "1h" }), []);
	assert.deepEqual(validateManualBan({ value: "192.0.2.0/24", duration: "7d" }), []);
	assert.deepEqual(validateManualBan({ value: "192.0.2.10", duration: "4h", type: "captcha", reason: "abuse" }), []);
	// reason is optional
	assert.deepEqual(validateManualBan({ value: "192.0.2.10", duration: "4h", reason: "" }), []);
});

test("manual ban input rejects hostile or malformed values", () => {
	for (const value of [
		"999.999.999.999",
		"192.0.2.1/99",
		"2001:db8::1/999",
		"192.0.2.1/33",
		"2001:db8::1/129",
		"fe80::1%eth0",
		"192.0.2.1/",
		"192.0.2.1/24/1",
		"::::",
		"[2001:db8::1]",
	]) {
		assert.deepEqual(validateManualBan({ value, duration: "1h" }), ["value"], value);
	}
	for (const value of ["0.0.0.0/0", "192.0.2.1/32", "::/0", "2001:db8::1/128", "::ffff:192.0.2.1"]) {
		assert.deepEqual(validateManualBan({ value, duration: "30d" }), [], value);
	}
	assert.deepEqual(validateManualBan({ value: "192.0.2.1", duration: "9999999999999999999d" }), ["duration"]);
	assert.deepEqual(validateManualBan({ value: "not an ip", duration: "4h" }), ["value"]);
	assert.deepEqual(validateManualBan({ value: "192.0.2.10", duration: "forever" }), ["duration"]);
	assert.deepEqual(validateManualBan({ value: "192.0.2.10", duration: "4h", type: "delete" }), ["type"]);
	assert.deepEqual(validateManualBan({ value: "192.0.2.10", duration: "4h", reason: "' OR 1=1 --" }), ["reason"]);
	assert.deepEqual(validateManualBan({ value: "http://example.com/", duration: "4h" }), ["value"]);
	// every invalid field is reported together
	assert.deepEqual(validateManualBan({ value: null, duration: "0h", type: "nope" }), ["value", "duration", "type"]);
});

test("missing telemetry remains unknown and explicit zeros stay zero", () => {
	const absent = summarizeCrowdsecMetrics([]);
	assert.equal(absent.active_decisions, null);
	assert.equal(absent.appsec_requests, null);
	assert.equal(absent.appsec_passed, null);
	assert.equal(absent.bouncer_requests, null);
	const zero = summarizeCrowdsecMetrics(
		parsePrometheusText("cs_appsec_reqs_total 0\ncs_node_wl_hits_ok_total 0\ncs_node_wl_hits_total 40"),
	);
	assert.equal(zero.appsec_requests, 0);
	assert.equal(zero.appsec_blocked, 0);
	assert.equal(zero.whitelist_hits, 0);
	assert.equal(summarizeCrowdsecMetrics(parsePrometheusText("cs_node_wl_hits_total 40")).whitelist_hits, null);
});

test("parser families are neither mixed nor double counted", () => {
	const result = summarizeCrowdsecMetrics(
		parsePrometheusText(
			"cs_parser_hits_total 10\ncs_parser_hits_ok_total 0\ncs_node_hits_total 30\ncs_node_hits_ok_total 25",
		),
	);
	assert.equal(result.parser_hits, 10);
	assert.equal(result.parser_success_rate, 0);
	assert.equal(result.parser_metric_scope, "events");
});

test("out-of-range alert coordinates are not plotted", () => {
	const [alert] = normalizeCrowdsecAlerts([{ id: 1, source: { latitude: 91, longitude: -181 } }]);
	assert.equal(alert.source.latitude, null);
	assert.equal(alert.source.longitude, null);
});

test("target grouping prefers hosts over URI metadata and ASN search matches numbers", () => {
	const alerts = normalizeCrowdsecAlerts([
		{
			id: 1,
			source: { as_name: "Example Network", as_number: "64500" },
			events: [
				{
					meta: [
						{ key: "target_uri", value: "/.env" },
						{ key: "target_host", value: "app.example.com" },
					],
				},
			],
		},
	]);
	assert.equal(crowdsecAlertTarget(alerts[0]), "app.example.com");
	assert.equal(filterCrowdsecAlerts(alerts, { search: "asn:64500" }).length, 1);
	assert.equal(filterCrowdsecAlerts(alerts, { search: "64500" }).length, 1);
});

test("preserves bounded AppSec rule evidence without query credentials or payloads", () => {
	const [alert] = normalizeCrowdsecAlerts([
		{
			id: 1,
			events: [
				{
					meta: [
						{ key: "rule_name", value: "crowdsecurity/vpatch-env-access" },
						{ key: "uri", value: "/.env?token=secret#private" },
						{ key: "target_uri", value: "/login?password=secret" },
						{ key: "http_user_agent", value: "sqlmap/1.8" },
						{ key: "data", value: "payload-secret" },
						{ key: "authorization", value: "credential-secret" },
						{ key: "cookie", value: "session-secret" },
					],
				},
			],
		},
	]);
	assert.deepEqual(alert.events[0].meta, [
		{ key: "rule_name", value: "crowdsecurity/vpatch-env-access" },
		{ key: "uri", value: "/.env" },
		{ key: "target_uri", value: "/login" },
		{ key: "http_user_agent", value: "sqlmap/1.8" },
	]);
	const [bounded] = normalizeCrowdsecAlerts([
		{
			id: 2,
			events: Array.from({ length: 20 }, () => ({
				meta: Array.from({ length: 100 }, () => ({ key: "rule_name", value: "a".repeat(1000) })),
			})),
		},
	]);
	assert.equal(bounded.events.length, 10);
	assert.equal(bounded.events[0].meta.length, 32);
	assert.equal(bounded.events[0].meta[0].value.length, 512);
});
