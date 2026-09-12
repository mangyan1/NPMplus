import assert from "node:assert/strict";
import { test } from "node:test";

const fresh = async () => (await import(`../internal/home-location.js?test=${Math.random()}`)).getHomeLocation;

test("home lookup bounds streaming bodies and shares concurrent requests", async (t) => {
	delete process.env.HOME_LATITUDE;
	delete process.env.HOME_LONGITUDE;
	delete process.env.HOME_GEOLOCATION;
	let calls = 0;
	t.mock.method(globalThis, "fetch", () => {
		calls++;
		return Promise.resolve(new Response("x".repeat(16 * 1024 + 1)));
	});
	const lookup = await fresh();
	assert.deepEqual(await Promise.all([lookup(), lookup(), lookup()]), [null, null, null]);
	assert.equal(calls, 1);
	assert.equal(await lookup(), null);
	assert.equal(calls, 1, "failed lookup backs off");
});

test("explicit coordinates and disabled geolocation never contact the provider", async (t) => {
	t.mock.method(globalThis, "fetch", () => {
		throw new Error("unexpected external request");
	});
	process.env.HOME_GEOLOCATION = "false";
	process.env.HOME_LATITUDE = "";
	process.env.HOME_LONGITUDE = "";
	const lookup = await fresh();
	assert.equal(await lookup(), null);
	process.env.HOME_LATITUDE = "0";
	process.env.HOME_LONGITUDE = "0";
	assert.deepEqual(await lookup(), { latitude: 0, longitude: 0 });
});

test("valid home locations are cached and null coordinates are rejected", async (t) => {
	delete process.env.HOME_LATITUDE;
	delete process.env.HOME_LONGITUDE;
	delete process.env.HOME_GEOLOCATION;
	let calls = 0;
	t.mock.method(globalThis, "fetch", () => {
		calls++;
		return Promise.resolve(Response.json({ latitude: 51, longitude: -114 }));
	});
	const lookup = await fresh();
	assert.deepEqual(await lookup(), { latitude: 51, longitude: -114 });
	await lookup();
	assert.equal(calls, 1);
	t.mock.method(globalThis, "fetch", () => Promise.resolve(Response.json({ latitude: null, longitude: null })));
	assert.equal(await (await fresh())(), null);
});
