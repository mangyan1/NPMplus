import "./helpers/environment.js";
import assert from "node:assert/strict";
import test from "node:test";
import bcrypt from "bcryptjs";
import { hash, verify } from "../lib/argon2.js";
import { migrateUp } from "../migrate.js";
import Auth from "../models/auth.js";

await migrateUp();

test("Argon2 passwords verify, reject wrong secrets, and use distinct salts", async () => {
	const first = await hash("migration fixture");
	const second = await hash("migration fixture");
	assert.notEqual(first, second);
	assert.equal(await verify("migration fixture", first), true);
	assert.equal(await verify("wrong", first), false);
	assert.equal(await verify("wrong", "malformed"), false);
});

test("legacy bcrypt migrates only after successful password verification", async () => {
	const legacy = await bcrypt.hash("legacy fixture", 4);
	const [id] = await Auth.knex()("auth").insert({
		user_id: 1,
		type: "password",
		secret: legacy,
		meta: "{}",
		created_on: new Date().toISOString(),
		modified_on: new Date().toISOString(),
	});
	const auth = await Auth.query().findById(id);
	assert.equal(await auth.verifyPassword("wrong"), false);
	assert.equal((await Auth.query().findById(id)).secret, legacy);
	assert.equal(await auth.verifyPassword("legacy fixture"), true);
	const migrated = await Auth.query().findById(id);
	assert.equal(migrated.secret.startsWith("$2"), false);
	assert.equal(await migrated.verifyPassword("legacy fixture"), true);
});

test("a stale legacy login cannot overwrite a password reset", async () => {
	const legacy = await bcrypt.hash("old fixture", 4);
	const [id] = await Auth.knex()("auth").insert({
		user_id: 2,
		type: "password",
		secret: legacy,
		meta: "{}",
		created_on: new Date().toISOString(),
		modified_on: new Date().toISOString(),
	});
	const stale = await Auth.query().findById(id);
	await Auth.query().findById(id).patch({ type: "password", secret: "new fixture" });
	assert.equal(await stale.verifyPassword("old fixture"), false);
	const current = await Auth.query().findById(id);
	assert.equal(await current.verifyPassword("new fixture"), true);
	assert.equal(await current.verifyPassword("old fixture"), false);
});
