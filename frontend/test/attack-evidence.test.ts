// biome-ignore lint/correctness/noNodejsModules: Node test runner.
import assert from "node:assert/strict";
// biome-ignore lint/correctness/noNodejsModules: Node test runner.
import test from "node:test";
import { attackType, toolHints } from "../src/pages/Crowdsec/attackEvidence.ts";

test("classifies detector claims without guessing from unknown rules or manual reasons", () => {
	assert.equal(attackType("crowdsecurity/http-sqli-probing"), "sql");
	assert.equal(attackType("crowdsecurity/vpatch-CVE-2024-1234"), "cve");
	assert.equal(attackType("crowdsecurity/vpatch-env-access"), "exposure");
	assert.equal(attackType("crowdsecurity/http-bf"), "brute");
	assert.equal(attackType("manual/sqlmap"), "manual");
	assert.equal(attackType("native_rule:942100"), "unknown");
	assert.equal(attackType("new-custom-rule"), "unknown");
});

test("tool hints require an explicit bounded User-Agent claim", () => {
	assert.deepEqual(toolHints("sqlmap/1.8"), ["sqlmap"]);
	assert.deepEqual(toolHints("Mozilla/5.0 (compatible; Nmap Scripting Engine)"), ["Nmap"]);
	assert.deepEqual(toolHints("curl/8.0"), ["curl"]);
	assert.deepEqual(toolHints("Mozilla/5.0"), []);
	assert.deepEqual(toolHints("notnuclei/1.0"), []);
	assert.deepEqual(toolHints(""), []);
	assert.deepEqual(toolHints(`${"x".repeat(512)} sqlmap/1.8`), []);
});
