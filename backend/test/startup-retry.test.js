import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

function startup(failures) {
	const result = spawnSync(
		process.execPath,
		[
			"--experimental-vm-modules",
			fileURLToPath(new URL("./helpers/startup-probe.mjs", import.meta.url)),
			JSON.stringify(failures),
		],
		{ encoding: "utf8", timeout: 10_000 },
	);
	if (result.status !== 0) throw new Error(result.stderr || "Startup probe failed");
	return JSON.parse(result.stdout);
}

test("failed nginx reloads do not start renewal timers before startup recovers", () => {
	const { counts, failedAttempts } = startup({ reload: 3, listen: 0 });
	assert.equal(failedAttempts.length, 3);
	for (const attempt of failedAttempts) assert.equal(attempt.timers, 0);
	assert.deepEqual(counts, { reload: 4, listen: 1, timers: 1, telemetry: 1 });
});

test("failed socket setup does not accumulate renewal timers across retries", () => {
	const { counts, failedAttempts } = startup({ reload: 0, listen: 2 });
	assert.equal(failedAttempts.length, 2);
	for (const attempt of failedAttempts) assert.equal(attempt.timers, 0);
	assert.deepEqual(counts, { reload: 3, listen: 3, timers: 1, telemetry: 1 });
});

test("successful startup initializes certificate renewal and telemetry once", () => {
	const { counts, failedAttempts } = startup({ reload: 0, listen: 0 });
	assert.deepEqual(failedAttempts, []);
	assert.deepEqual(counts, { reload: 1, listen: 1, timers: 1, telemetry: 1 });
});
