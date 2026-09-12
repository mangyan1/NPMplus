import "./helpers/environment.js";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { after, test } from "node:test";

process.env.COOKIE_SECRET = "logout-test-cookie-secret";
const { default: app } = await import("../app.js");
const { migrateUp } = await import("../migrate.js");
const { default: User } = await import("../models/user.js");
const { default: Token } = await import("../models/token.js");
const { default: certificate } = await import("../internal/certificate.js");
const { default: errs } = await import("../lib/error.js");
const { issueSessionToken, assertTokenSession } = await import("../internal/token-session.js");
await migrateUp();
const user = await User.query().insertAndFetch({
	email: "logout@example.com",
	name: "Logout fixture",
	nickname: "fixture",
	avatar: "",
	roles: ["admin"],
	npmplus_token_valid_after: 0,
});
const server = app.listen(0, "127.0.0.1");
await new Promise((resolve) => server.once("listening", resolve));
after(async () => {
	server.closeAllConnections();
	await new Promise((resolve) => server.close(resolve));
});
const paddingPattern = /[=]+$/;
const cookieFor = (value, name = "__Host-Http-token") => {
	const mac = crypto
		.createHmac("sha256", process.env.COOKIE_SECRET)
		.update(value)
		.digest("base64")
		.replace(paddingPattern, "");
	return `${name}=${encodeURIComponent(`s:${value}.${mac}`)}`;
};
const request = (method, path, cookie) =>
	fetch(`http://127.0.0.1:${server.address().port}${path}`, {
		method,
		headers: cookie ? { cookie } : {},
	});
const payload = (scope = "user") => ({
	iss: "api",
	attrs: { id: user.id },
	scope: [scope],
	expiresIn: scope === "user" ? "1h" : "3m",
});
const newSession = async () => cookieFor((await issueSessionToken(Token(), payload())).token);

test("logout revokes original and refreshed cookies but preserves another device", async () => {
	const original = await newSession();
	const otherDevice = await newSession();
	const refresh = await request("GET", "/api/tokens", original);
	assert.equal(refresh.status, 200);
	const refreshed = refresh.headers
		.getSetCookie()
		.find((value) => value.startsWith("__Host-Http-token="))
		.split(";")[0];
	assert.equal((await request("DELETE", "/api/tokens", refreshed)).status, 200);
	for (const cookie of [original, refreshed]) {
		assert.equal((await request("GET", "/api/auth", cookie)).status, 401);
		assert.equal((await request("GET", "/api/tokens", cookie)).status, 401);
	}
	assert.equal((await request("GET", "/api/auth", otherDevice)).status, 200);
	assert.equal((await request("DELETE", "/api/tokens", refreshed)).status, 200);
	assert.equal((await request("DELETE", "/api/tokens")).status, 200);
});

test("logout invalidates an MFA challenge and clears its cookies", async () => {
	const challenge = await issueSessionToken(Token(), payload("mfa-challenge"));
	const response = await request("DELETE", "/api/tokens", cookieFor(challenge.token, "__Host-Http-challenge_token"));
	assert.equal(response.status, 200);
	await assert.rejects(assertTokenSession(challenge.payload.sid));
	assert.ok(response.headers.getSetCookie().some((value) => value.startsWith("__Host-Http-challenge_token=;")));
});

test("a refresh already signing when logout runs cannot recreate its session", async () => {
	const original = await issueSessionToken(Token(), payload());
	let release;
	let started;
	const waiting = new Promise((resolve) => {
		release = resolve;
	});
	const signing = new Promise((resolve) => {
		started = resolve;
	});
	const token = Token();
	const refresh = issueSessionToken(
		{
			create: async (data) => {
				started();
				await waiting;
				return token.create(data);
			},
		},
		payload(),
		original.payload.sid,
	);
	await signing;
	assert.equal((await request("DELETE", "/api/tokens", cookieFor(original.token))).status, 200);
	release();
	await assert.rejects(refresh);
	await assert.rejects(assertTokenSession(original.payload.sid));
});

test("tokens from before session tracking require a fresh login", async () => {
	const legacy = await Token().create(payload());
	assert.equal((await request("GET", "/api/auth", cookieFor(legacy.token))).status, 401);
});

test("HTTP command failures expose only the generic message and correlation ID", async (t) => {
	t.mock.method(certificate, "renew", () => {
		throw new errs.CommandError("synthetic private stderr", 1, {
			stderr: "synthetic private stderr",
			cmd: "private command",
		});
	});
	const response = await request("POST", "/api/nginx/certificates/1/renew", await newSession());
	assert.equal(response.status, 500);
	const body = await response.json();
	assert.deepEqual(Object.keys(body), ["error"]);
	assert.equal(body.error.message, "Internal Error");
	assert.ok(body.error.request_id);
	assert.ok(!JSON.stringify(body).includes("private"));
});
