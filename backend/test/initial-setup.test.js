import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { after, test } from "node:test";

process.env.INITIAL_SETUP_TOKEN = "isolated-initial-setup-token-for-tests-only";
const { default: app } = await import("../app.js");
const { migrateUp } = await import("../migrate.js");
const { getCompiledSchema } = await import("../schema/index.js");
const { default: user } = await import("../internal/user.js");
await migrateUp();
await getCompiledSchema();
mkdirSync("/data/npmplus/gravatar", { recursive: true });
const server = app.listen(0, "127.0.0.1");
await new Promise((resolve) => server.once("listening", resolve));
after(async () => {
	server.closeAllConnections();
	await new Promise((resolve) => server.close(resolve));
});

test("first-admin setup accepts the current schema and remains token-protected and one-time", async (t) => {
	t.mock.method(user, "fetchGravatar", async () => "");
	const create = (token) =>
		fetch(`http://127.0.0.1:${server.address().port}/api/users`, {
			method: "POST",
			headers: { "content-type": "application/json", ...(token ? { "x-npmplus-setup-token": token } : {}) },
			body: JSON.stringify({
				name: "First administrator",
				email: "setup@example.test",
				roles: [],
				auth: { type: "password", secret: "Setup-Fixture-Password-1" },
			}),
		});
	assert.equal((await create()).status, 400);
	const created = await create(process.env.INITIAL_SETUP_TOKEN);
	assert.equal(created.status, 201, await created.clone().text());
	assert.deepEqual((await created.json()).roles, ["admin"]);
	assert.equal((await create(process.env.INITIAL_SETUP_TOKEN)).status, 403);
});
