import "./helpers/environment.js";
import assert from "node:assert/strict";
import test from "node:test";
import bcrypt from "bcryptjs";
import mfa from "../internal/mfa.js";
import { hash } from "../lib/argon2.js";
import { migrateUp } from "../migrate.js";
import authModel from "../models/auth.js";

await migrateUp();

test("a recovery code is accepted by only one concurrent request", async () => {
	const recoveryHash = await bcrypt.hash("ABCDEF12", 10);
	await authModel.query().insert({ user_id: 1, type: "password", secret: "unused", meta: {} });
	await authModel.query().insert({ user_id: 1, type: "totp", secret: "JBSWY3DPEHPK3PXP", meta: {} });
	await authModel.query().insert({ user_id: 1, type: "backup_code", secret: recoveryHash, meta: {} });
	const results = await Promise.all([mfa.verifyForLogin(1, "ABCDEF12"), mfa.verifyForLogin(1, "ABCDEF12")]);
	assert.deepEqual(results.sort(), [false, true]);
	assert.equal(await mfa.verifyForLogin(1, "ABCDEF12"), false);
	// the consumed code's row is gone, the other factor is untouched
	assert.equal(await authModel.query().where("user_id", 1).andWhere("type", "backup_code").resultSize(), 0);
	assert.equal(await authModel.query().where("user_id", 1).andWhere("type", "totp").resultSize(), 1);
});

test("using a recovery code does not consume other recovery codes", async () => {
	const hashes = await Promise.all([bcrypt.hash("11111111", 10), bcrypt.hash("22222222", 10)]);
	await authModel.query().insert({ user_id: 2, type: "password", secret: "unused", meta: {} });
	for (const secret of hashes) {
		await authModel.query().insert({ user_id: 2, type: "backup_code", secret, meta: {} });
	}
	assert.equal(await mfa.verifyForLogin(2, "invalid!"), false);
	assert.equal(await mfa.verifyForLogin(2, "11111111"), true);
	assert.equal(await mfa.verifyForLogin(2, "22222222"), true);
});

test("Argon2 recovery codes remain single-use under concurrent requests", async () => {
	const codeHash = await hash("AABBCCDD", true);
	await authModel.query().insert({ user_id: 3, type: "password", secret: "unused", meta: {} });
	await authModel.query().insert({ user_id: 3, type: "backup_code", secret: codeHash, meta: {} });
	const results = await Promise.all([mfa.verifyForLogin(3, "aabbccdd"), mfa.verifyForLogin(3, "AABBCCDD")]);
	assert.deepEqual(results.sort(), [false, true]);
	assert.equal(await mfa.verifyForLogin(3, "AABBCCDD"), false);
});
