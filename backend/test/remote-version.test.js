import assert from "node:assert/strict";
import test from "node:test";
import remoteVersion, { isCommitUpdateAvailable } from "../internal/remote-version.js";

const USER_AGENT_PATTERN = /^NPMplus\//;

test("commit update comparison accepts short and full matching revisions", () => {
	assert.equal(isCommitUpdateAvailable("53e524b", "53e524b"), false);
	assert.equal(isCommitUpdateAvailable("a".repeat(40), "aaaaaaa"), false);
});

test("commit update comparison detects a different fork revision", () => {
	assert.equal(isCommitUpdateAvailable("53e524b", "6454c6d"), true);
});

test("release and unknown strings do not produce false update notices", () => {
	assert.equal(isCommitUpdateAvailable("1.2.3", "53e524b"), false);
	assert.equal(isCommitUpdateAvailable("53e524b", "unknown"), false);
});

test("the remote check reads this fork's develop commit with a bounded request", async () => {
	const originalFetch = globalThis.fetch;
	try {
		globalThis.fetch = (url, options) => {
			assert.equal(url, "https://api.github.com/repos/mangyan1/NPMplus/commits/develop");
			assert.match(options.headers["User-Agent"], USER_AGENT_PATTERN);
			assert.ok(options.signal instanceof AbortSignal);
			return new Response(JSON.stringify({ sha: `6454c6d${"1".repeat(33)}` }), {
				status: 200,
				headers: { "content-type": "application/json" },
			});
		};
		remoteVersion.last_result = null;
		remoteVersion.last_fetch_time = null;

		const result = await remoteVersion.get();
		assert.equal(result.latest, "6454c6d");
	} finally {
		globalThis.fetch = originalFetch;
		remoteVersion.last_result = null;
		remoteVersion.last_fetch_time = null;
	}
});
