import assert from "node:assert/strict";
import { test } from "node:test";
import { issuedAfter } from "../lib/token-time.js";

test("token issuance rechecks the clock when a timer wakes before the boundary", async (t) => {
	const times = [1999, 1999, 2000];
	let reads = 0;
	t.mock.method(Date, "now", () => times[Math.min(reads++, times.length - 1)]);
	assert.equal(await issuedAfter(1), 2);
	assert.equal(reads, 3, "an early wake must cause another wait");
});

test("token issuance uses the current second once the cutoff is past", async (t) => {
	t.mock.method(Date, "now", () => 3500);
	assert.equal(await issuedAfter(1), 3);
	assert.equal(await issuedAfter(undefined), 3);
});
