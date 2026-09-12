import "./helpers/environment.js";
import assert from "node:assert/strict";
import { after, test } from "node:test";

process.env.COOKIE_SECRET = "rate-limit-test-cookie-secret";
const { default: app } = await import("../app.js");
const { migrateUp } = await import("../migrate.js");
const { getCompiledSchema } = await import("../schema/index.js");
const { default: User } = await import("../models/user.js");
const { default: UserPermission } = await import("../models/user_permission.js");
const { default: Auth } = await import("../models/auth.js");
await migrateUp();
await getCompiledSchema();
const user = await User.query().insertAndFetch({
	email: "limits@example.com",
	name: "Limits fixture",
	nickname: "fixture",
	avatar: "/images/default-avatar.jpg",
	roles: ["admin"],
});
await UserPermission.query().insert({
	user_id: user.id,
	visibility: "all",
	proxy_hosts: "manage",
	redirection_hosts: "manage",
	dead_hosts: "manage",
	streams: "manage",
	access_lists: "manage",
	certificates: "manage",
});
await Auth.query().insert({ user_id: user.id, type: "password", secret: "Fixture-Password-123", meta: {} });
const server = app.listen(0, "127.0.0.1");
await new Promise((resolve) => server.once("listening", resolve));
after(async () => {
	server.closeAllConnections();
	await new Promise((resolve) => server.close(resolve));
});
const request = (method, path, body, cookie) =>
	fetch(`http://127.0.0.1:${server.address().port}/api${path}`, {
		method,
		headers: { "Content-Type": "application/json", ...(cookie ? { cookie } : {}) },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
const credentials = { identity: "limits@example.com", secret: "Fixture-Password-123" };
let cookie;

test("logged-out session checks do not consume the password failure allowance", async () => {
	for (let i = 0; i < 8; i++) assert.equal((await request("GET", "/tokens")).status, 401);
	const login = await request("POST", "/tokens", credentials);
	assert.equal(login.status, 200);
	cookie = login.headers
		.getSetCookie()
		.find((value) => value.startsWith("__Host-Http-token="))
		.split(";")[0];
	assert.equal((await request("GET", "/users/me?expand=permissions", undefined, cookie)).status, 200);
});

test("account mutation throttling cannot hide a valid user's profile", async () => {
	for (let i = 0; i < 5; i++)
		assert.equal(
			(
				await request(
					"PUT",
					`/users/${user.id}/auth`,
					{ type: "password", secret: "New-Fixture-Password" },
					cookie,
				)
			).status,
			400,
		);
	assert.equal(
		(await request("PUT", `/users/${user.id}/auth`, { type: "password", secret: "New-Fixture-Password" }, cookie))
			.status,
		429,
	);
	assert.equal((await request("GET", "/users/me?expand=permissions", undefined, cookie)).status, 200);
});

test("five invalid passwords still throttle login while refresh and logout remain available", async () => {
	for (let i = 0; i < 5; i++)
		assert.equal(
			(await request("POST", "/tokens", { ...credentials, secret: "Wrong-Fixture-Password" })).status,
			400,
		);
	assert.equal((await request("POST", "/tokens", credentials)).status, 429);
	assert.equal((await request("GET", "/tokens", undefined, cookie)).status, 200);
	assert.equal((await request("DELETE", "/tokens", undefined, cookie)).status, 200);
});

test("session and account reads retain independent request limits", async () => {
	let refresh;
	let profile;
	for (let i = 0; i < 61; i++) {
		refresh = await request("GET", "/tokens");
		profile = await request("GET", "/users/me");
	}
	assert.equal(refresh.status, 429);
	assert.equal(profile.status, 429);
	assert.ok(refresh.headers.has("retry-after"));
	assert.ok(profile.headers.has("retry-after"));
});
