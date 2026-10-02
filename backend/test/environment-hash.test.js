import "./helpers/environment.js";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import utils from "../lib/utils.js";

const run = promisify(execFile);
const digest = async (changes) => {
	const saved = Object.fromEntries(Object.keys(changes).map((name) => [name, process.env[name]]));
	try {
		Object.assign(process.env, changes);
		await utils.writeHash();
		return await readFile("/data/npmplus/env.sha512sum", "utf8");
	} finally {
		for (const [name, value] of Object.entries(saved)) {
			if (value === undefined) delete process.env[name];
			else process.env[name] = value;
		}
	}
};

test("environment fingerprint distinguishes valid ports with identical value concatenation", async () => {
	assert.notEqual(
		await digest({ HTTPS_PORT: "443", HTTP_PORT: "80" }),
		await digest({ HTTPS_PORT: "44", HTTP_PORT: "380" }),
	);
});

test("moving an optional upstream between authentication providers changes the fingerprint", async () => {
	const upstream = "http://auth.example.test:8923";
	assert.notEqual(
		await digest({ AUTH_REQUEST_AUTHELIA_UPSTREAM: upstream, AUTH_REQUEST_AUTHENTIK_UPSTREAM: "" }),
		await digest({ AUTH_REQUEST_AUTHELIA_UPSTREAM: "", AUTH_REQUEST_AUTHENTIK_UPSTREAM: upstream }),
	);
});

test("new fingerprint format forces a one-time regeneration from legacy digests", async () => {
	assert.ok((await digest({ TV: "21" })).startsWith("v2:"));
});

test("template version changes the hash but unreferenced environment values do not", async () => {
	const first = await digest({ TV: "21", NPMPLUS_TEST_UNUSED: "first" });
	assert.equal(first, await digest({ TV: "21", NPMPLUS_TEST_UNUSED: "second" }));
	assert.notEqual(first, await digest({ TV: "22", NPMPLUS_TEST_UNUSED: "first" }));
});

test("startup CLI and backend writer agree on the exact versioned fingerprint", async () => {
	await utils.writeHash();
	const persisted = await readFile("/data/npmplus/env.sha512sum", "utf8");
	const { stdout } = await run(process.execPath, [
		fileURLToPath(new URL("../lib/environment-hash.js", import.meta.url)),
	]);
	assert.equal(stdout.trim(), persisted);
});
