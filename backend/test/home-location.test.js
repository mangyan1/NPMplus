// Unit tests for the attack map's home-location helper: env override, live
// lookup, and the failure backoff. Each test loads a fresh module instance so
// the module-level cache cannot leak between cases.
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

// each case needs its own module instance: the cache and failure backoff are
// module state, and node caches a dynamic import by URL, so a query param
// busts it
let loadCount = 0;
const loadModule = () => import(`../internal/home-location.js?case=${(loadCount += 1)}`);

afterEach(() => {
	delete process.env.HOME_LATITUDE;
	delete process.env.HOME_LONGITUDE;
});

test("HOME_LATITUDE and HOME_LONGITUDE take precedence over any lookup", async () => {
	process.env.HOME_LATITUDE = "52.1";
	process.env.HOME_LONGITUDE = "5.3";
	const { getHomeLocation } = await loadModule();
	assert.deepEqual(await getHomeLocation(), { latitude: 52.1, longitude: 5.3 });
});

test("a malformed env pair is ignored rather than trusted", async (t) => {
	process.env.HOME_LATITUDE = "not-a-number";
	process.env.HOME_LONGITUDE = "5.3";
	t.mock.method(globalThis, "fetch", () => {
		throw new Error("lookup must not run when the env pair is malformed");
	});
	const { getHomeLocation } = await loadModule();
	assert.equal(await getHomeLocation(), null);
});

test("geolocates the instance's public IP through ipwho.is", async (t) => {
	t.mock.method(
		globalThis,
		"fetch",
		async () => new Response(JSON.stringify({ success: true, latitude: 48.85, longitude: 2.35 }), { status: 200 }),
	);
	const { getHomeLocation } = await loadModule();
	assert.deepEqual(await getHomeLocation(), { latitude: 48.85, longitude: 2.35 });
});

test("a failed lookup returns null and backs off so polling does not hammer the service", async (t) => {
	let calls = 0;
	t.mock.method(globalThis, "fetch", async () => {
		calls += 1;
		return new Response("nope", { status: 500 });
	});
	const { getHomeLocation } = await loadModule();
	assert.equal(await getHomeLocation(), null);
	assert.equal(await getHomeLocation(), null);
	assert.equal(calls, 1, "the second call must be served by the failure backoff");
});

test("an out-of-range coordinate from the service is rejected", async (t) => {
	t.mock.method(
		globalThis,
		"fetch",
		async () => new Response(JSON.stringify({ success: true, latitude: 999, longitude: 2.35 }), { status: 200 }),
	);
	const { getHomeLocation } = await loadModule();
	assert.equal(await getHomeLocation(), null);
});
