import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { after, test } from "node:test";

process.env.INITIAL_SETUP_TOKEN = "isolated-initial-setup-token-for-tests-only";
const { default: app } = await import("../app.js");
const { migrateUp } = await import("../migrate.js");
const { getCompiledSchema } = await import("../schema/index.js");
const { default: user } = await import("../internal/user.js");
const { default: db } = await import("../db.js");
const { isSetup } = await import("../setup.js");
process.env.DISABLE_GRAVATAR = "true";
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
	assert.equal((await create()).status, 403);
	for (const table of ["auth", "user_permission", "audit_log"]) {
		await db().raw(
			`CREATE TRIGGER fail_setup_write BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT, 'injected setup failure'); END`,
		);
		try {
			const failed = await create(process.env.INITIAL_SETUP_TOKEN);
			assert.equal(failed.status, 500);
			await failed.arrayBuffer();
			assert.equal(await isSetup(), false, `failed ${table} write must leave setup retryable`);
			for (const name of ["user", "auth", "user_permission", "audit_log"]) {
				assert.equal(
					await db()(name)
						.count("* as n")
						.first()
						.then((row) => row.n),
					0,
				);
			}
		} finally {
			await db().raw("DROP TRIGGER fail_setup_write");
		}
	}
	const created = await create(process.env.INITIAL_SETUP_TOKEN);
	assert.equal(created.status, 201, await created.clone().text());
	assert.deepEqual((await created.json()).roles, ["admin"]);
	const login = await fetch(`http://127.0.0.1:${server.address().port}/api/tokens`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ identity: "setup@example.test", secret: "Setup-Fixture-Password-1" }),
	});
	assert.equal(login.status, 200, await login.clone().text());
	await login.arrayBuffer();
	assert.equal((await create(process.env.INITIAL_SETUP_TOKEN)).status, 403);
});

test("avatar failure after account creation still returns a complete usable account", async (t) => {
	t.mock.method(user, "fetchGravatar", async () => {
		throw new Error("injected avatar failure");
	});
	const access = { canAdmin() {}, canUser() {}, token: { getUserId: () => 1 } };
	const created = await user.create(access, {
		name: "Avatar fallback",
		email: "avatar-fallback@example.test",
		roles: [],
		auth: { type: "password", secret: "Avatar-Fixture-Password-1" },
	});
	assert.equal(created.avatar, "/images/default-avatar.jpg");
	assert.ok(await db()("auth").where({ user_id: created.id, type: "password" }).first());
	assert.equal((await db()("user_permission").where({ user_id: created.id }).first()).visibility, "user");
	assert.ok(await db()("audit_log").where({ object_type: "user", object_id: created.id, action: "created" }).first());
});
