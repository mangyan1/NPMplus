import "./helpers/environment.js";
import assert from "node:assert/strict";
import test from "node:test";
import db from "../db.js";
import backupCodes from "../internal/backup-codes.js";
import mfa from "../internal/mfa.js";
import totp from "../internal/totp.js";
import internalUser from "../internal/user.js";
import { hash } from "../lib/argon2.js";
import { migrateUp } from "../migrate.js";
import Auth from "../models/auth.js";
import User from "../models/user.js";

await migrateUp();
const codePattern = /^[0-9A-HJKMNP-TV-Z]{8}$/;

for (const acceptedInserts of [0, 2]) {
	test(`recovery-code replacement preserves old codes after ${acceptedInserts} successful inserts`, async () => {
		const userId = 80 + acceptedInserts;
		const oldHash = await hash("AABBCCDD", true);
		await Auth.query().insert({ user_id: userId, type: "backup_code", secret: oldHash, meta: {} });
		await db().raw(
			`CREATE TRIGGER reject_backup_codes BEFORE INSERT ON auth WHEN NEW.user_id=${userId} AND NEW.type='backup_code' AND (SELECT COUNT(*) FROM auth WHERE user_id=${userId} AND type='backup_code') >= ${acceptedInserts} BEGIN SELECT RAISE(ABORT, 'rejected recovery insert'); END`,
		);
		try {
			await assert.rejects(backupCodes.create(userId), /rejected recovery insert/);
			assert.equal(await backupCodes.count(userId), 1);
			assert.equal((await Auth.query().where({ user_id: userId, type: "backup_code" }).first()).secret, oldHash);
			assert.equal(await backupCodes.verify(userId, "AABBCCDD"), true);
		} finally {
			await db().raw("DROP TRIGGER reject_backup_codes");
		}
	});
}

test("successful replacement returns exactly eight usable codes and invalidates the old code", async () => {
	await Auth.query().insert({ user_id: 83, type: "backup_code", secret: await hash("AABBCCDD", true), meta: {} });
	const plain = await backupCodes.create(83);
	assert.equal(plain.length, 8);
	assert.equal(new Set(plain).size, 8);
	assert.ok(plain.every((code) => codePattern.test(code)));
	assert.equal(await backupCodes.count(83), 8);
	assert.equal(await backupCodes.verify(83, "AABBCCDD"), false);
	assert.equal(await backupCodes.verify(83, plain[0]), true);
	assert.equal(await backupCodes.verify(83, plain[0]), false);
});

test("concurrent replacements leave one complete set rather than mixing both sets", async () => {
	await Promise.all([backupCodes.create(84), backupCodes.create(84)]);
	assert.equal(await backupCodes.count(84), 8);
});

for (const failedTable of ["user", "audit_log"]) {
	test(`MFA regeneration rolls back recovery codes and token cutoff when ${failedTable} fails`, async (t) => {
		const userId = failedTable === "user" ? 91 : 92;
		const user = await User.query().insertAndFetch({
			id: userId,
			email: `recovery-${userId}@example.com`,
			name: "Recovery",
			nickname: "Recovery",
			avatar: "",
			roles: ["admin"],
			npmplus_token_valid_after: 0,
		});
		const oldHash = await hash("AABBCCDD", true);
		await Auth.query().insert({ user_id: userId, type: "backup_code", secret: oldHash, meta: {} });
		t.mock.method(internalUser, "get", async () => user);
		t.mock.method(totp, "isEnabled", async () => true);
		t.mock.method(totp, "verifyCode", async () => true);
		const action = failedTable === "user" ? "UPDATE" : "INSERT";
		await db().raw(
			`CREATE TRIGGER reject_regeneration BEFORE ${action} ON ${failedTable} BEGIN SELECT RAISE(ABORT, 'rejected regeneration'); END`,
		);
		try {
			await assert.rejects(
				mfa.regenerateBackupCodes({ token: { getUserId: () => userId } }, userId, "123456"),
				/rejected regeneration/,
			);
			assert.equal((await User.query().findById(userId)).npmplus_token_valid_after, 0);
			assert.equal(await backupCodes.count(userId), 1);
			assert.equal((await Auth.query().where({ user_id: userId, type: "backup_code" }).first()).secret, oldHash);
			assert.equal(await backupCodes.verify(userId, "AABBCCDD"), true);
		} finally {
			await db().raw("DROP TRIGGER reject_regeneration");
		}
	});
}

test("MFA regeneration commits codes, session cutoff and a single audit event together", async (t) => {
	const userId = 93;
	const user = await User.query().insertAndFetch({
		id: userId,
		email: "recovery-success@example.com",
		name: "Recovery",
		nickname: "Recovery",
		avatar: "",
		roles: ["admin"],
		npmplus_token_valid_after: 0,
	});
	t.mock.method(internalUser, "get", async () => user);
	t.mock.method(totp, "isEnabled", async () => true);
	t.mock.method(totp, "verifyCode", async () => true);
	const result = await mfa.regenerateBackupCodes({ token: { getUserId: () => userId } }, userId, "123456");
	assert.equal(result.backup_codes.length, 8);
	assert.equal(await backupCodes.count(userId), 8);
	assert.ok((await User.query().findById(userId)).npmplus_token_valid_after > 0);
	assert.equal(
		(
			await db()("audit_log")
				.where({ user_id: userId, object_type: "user", object_id: userId })
				.count("id as count")
				.first()
		).count,
		1,
	);
});
