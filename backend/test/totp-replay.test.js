import "./helpers/environment.js";
import assert from "node:assert/strict";
import test from "node:test";
import { generate, generateSecret } from "otplib";
import internalToken from "../internal/token.js";
import { assertTokenSession, issueSessionToken } from "../internal/token-session.js";
import totp from "../internal/totp.js";
import { migrateUp } from "../migrate.js";
import Auth from "../models/auth.js";
import Token from "../models/token.js";
import User from "../models/user.js";

await migrateUp();
let serial = 0;
const fixture = async () => {
	const user = await User.query().insertAndFetch({
		email: `totp-${serial++}@example.com`,
		name: "TOTP fixture",
		avatar: "",
		nickname: "fixture",
		roles: [],
		npmplus_token_valid_after: 0,
	});
	const secret = generateSecret();
	await Auth.query().insert({
		user_id: user.id,
		type: "password",
		secret: "Replay-Fixture-1",
		meta: { totp_enabled: true, totp_secret: secret },
	});
	return { user, secret };
};

test("TOTP is single-use across sequential and concurrent attempts, then accepts the next step", async (t) => {
	let epoch = 1900000000;
	t.mock.method(Date, "now", () => epoch * 1000);
	const { user, secret } = await fixture();
	const code = await generate({ secret });
	const results = await Promise.all([totp.verifyCode(user.id, code), totp.verifyCode(user.id, code)]);
	assert.deepEqual(results.sort(), [false, true]);
	assert.equal(await totp.verifyCode(user.id, code), false);
	// A metadata update (e.g. recovery-code regeneration) cannot erase replay state.
	const auth = await Auth.getPasswordAuth(user.id);
	await Auth.query()
		.findById(auth.id)
		.patch({ meta: { ...auth.meta, backup_codes: [] } });
	assert.equal(await totp.verifyCode(user.id, code), false);
	epoch += 30;
	assert.equal(await totp.verifyCode(user.id, await generate({ secret })), true);
	assert.equal(await totp.verifyCode(user.id, code), false);
});

test("enrollment consumes its code and re-enrollment resets the replay counter", async (t) => {
	t.mock.method(Date, "now", () => 1900000000000);
	const { user } = await fixture();
	const access = { token: { getUserId: () => user.id }, canUser: () => true };
	await totp.disable(access, user.id, false);
	assert.equal((await Auth.getPasswordAuth(user.id)).npmplus_totp_last_used_step, null);
	const setup = await totp.startSetup(access, user.id);
	const code = await generate({ secret: setup.secret });
	await totp.enable(access, user.id, code);
	assert.equal(await totp.verifyCode(user.id, code), false);
});

test("a stale enrollment read cannot authenticate after the secret is replaced", async (t) => {
	const { user, secret } = await fixture();
	const stale = await Auth.getPasswordAuthSnapshot(user.id);
	await Auth.query()
		.findById(stale.id)
		.patch({ meta: { ...stale.meta, totp_secret: generateSecret() } });
	t.mock.method(Auth, "getPasswordAuthSnapshot", async () => stale);
	assert.equal(await totp.verifyCode(user.id, await generate({ secret })), false);
});

test("MFA challenge completion creates a new session and rejects replay across challenges", async (t) => {
	let epoch = 1900000000;
	t.mock.method(Date, "now", () => epoch * 1000);
	const { user, secret } = await fixture();
	const challenge = await internalToken.getTokenFromEmail({ identity: user.email, secret: "Replay-Fixture-1" });
	const other = await internalToken.getTokenFromEmail({ identity: user.email, secret: "Replay-Fixture-1" });
	const code = await generate({ secret });
	const completed = await internalToken.verifyTotp(challenge.token, code);
	const original = await Token().load(challenge.token);
	const full = await Token().load(completed.token);
	assert.notEqual(full.sid, original.sid);
	await assert.rejects(assertTokenSession(original.sid));
	await assertTokenSession(full.sid);
	await assert.rejects(internalToken.verifyTotp(challenge.token, code));
	await assert.rejects(internalToken.verifyTotp(other.token, code));
	await assert.rejects(internalToken.getTokenFromEmail({ identity: user.email, secret: "Replay-Fixture-1", code }));
	epoch += 30;
	assert.ok((await internalToken.verifyTotp(other.token, await generate({ secret }))).token);
});

test("a concurrent challenge exchange has exactly one winner even with separate valid factors", async (t) => {
	const { default: mfa } = await import("../internal/mfa.js");
	const { user } = await fixture();
	const challenge = await issueSessionToken(Token(), {
		iss: "api",
		attrs: { id: user.id },
		scope: ["mfa-challenge"],
		expiresIn: "3m",
	});
	// Isolate challenge consumption from the independent atomic OTP claim.
	t.mock.method(mfa, "verifyForLogin", async () => true);
	const results = await Promise.allSettled([
		internalToken.verifyTotp(challenge.token, "factor-one"),
		internalToken.verifyTotp(challenge.token, "factor-two"),
	]);
	assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
	assert.equal(results.filter((result) => result.status === "rejected").length, 1);
});
