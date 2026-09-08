import "./helpers/environment.js";
import assert from "node:assert/strict";
import test from "node:test";
import bcrypt from "bcryptjs";
import mfa from "../internal/mfa.js";
import { migrateUp } from "../migrate.js";
import authModel from "../models/auth.js";

await migrateUp();

test("a recovery code is accepted by only one concurrent request", async () => {
	const hash = await bcrypt.hash("ABCDEF12", 10);
	await authModel
		.query()
		.insert({ user_id: 1, type: "password", secret: "unused", meta: { backup_codes: [hash], totp_enabled: true } });
	const results = await Promise.all([mfa.verifyForLogin(1, "ABCDEF12"), mfa.verifyForLogin(1, "ABCDEF12")]);
	assert.deepEqual(results.sort(), [false, true]);
	assert.equal(await mfa.verifyForLogin(1, "ABCDEF12"), false);
	const auth = await authModel.getPasswordAuth(1);
	assert.deepEqual(auth.meta.backup_codes, []);
	assert.equal(auth.meta.totp_enabled, true);
});

test("using a recovery code does not consume other recovery codes", async () => {
	const hashes = await Promise.all([bcrypt.hash("11111111", 10), bcrypt.hash("22222222", 10)]);
	await authModel.query().insert({ user_id: 2, type: "password", secret: "unused", meta: { backup_codes: hashes } });
	assert.equal(await mfa.verifyForLogin(2, "invalid!"), false);
	assert.equal(await mfa.verifyForLogin(2, "11111111"), true);
	assert.equal(await mfa.verifyForLogin(2, "22222222"), true);
});
