// HTTP-level test for the CRS disable verb. This lives in its own process on
// purpose: both control verbs share one rate-limit bucket, and api.test.js
// consumes its enable bucket on a fixed schedule — disable requests must not
// shift that boundary.
import "./helpers/environment.js";
import process from "node:process";

process.env.COOKIE_SECRET ||= "api-test-cookie-secret";

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync } from "node:fs";
import { after, test } from "node:test";
import internalAuditLog from "../internal/audit-log.js";
import crsControl from "../internal/crs-control.js";

// the container image creates these before the app boots; the nginx config
// generation and access-list handling expect them to exist
for (const dir of [
	"/data/npmplus",
	"/data/npmplus/gravatar",
	"/data/nginx",
	"/data/nginx/proxy_host",
	"/data/nginx/redirection_host",
	"/data/nginx/dead_host",
	"/data/nginx/stream",
	"/data/nginx/default",
	"/data/access",
	"/data/access/temp",
	"/data/html",
	"/usr/local/nginx/conf/conf.d",
]) {
	mkdirSync(dir, { recursive: true });
}

const { default: app } = await import("../app.js");
const { migrateUp } = await import("../migrate.js");
// index.js compiles the api schemas at boot; without it every apiValidator
// call 400s with "Schema is undefined"
const { getCompiledSchema } = await import("../schema/index.js");
await getCompiledSchema();
// reload() talks to the nginx control-API unix socket in the container, which
// does not exist here; stub it the same way api.test.js does.
const internalNginx = await import("../internal/nginx.js");
internalNginx.default.reload = async () => {};
const authModel = (await import("../models/auth.js")).default;
const userModel = (await import("../models/user.js")).default;
const userPermissionModel = (await import("../models/user_permission.js")).default;

await migrateUp();

const ADMIN_EMAIL = "admin@example.com";
const ADMIN_PASSWORD = "Correct-Horse-1";
const PEON_EMAIL = "peon@example.com";
const PEON_PASSWORD = "Peon-Pass-1";

const insertUser = async ({ email, password, roles }) => {
	const user = await userModel.query().insertAndFetch({ email, name: "Test", nickname: "tester", avatar: "", roles });
	// models/auth.js hashes the secret on insert, so pass it in plain
	await authModel.query().insert({ user_id: user.id, type: "password", secret: password, meta: {} });
	const isAdmin = roles.includes("admin");
	await userPermissionModel.query().insert({
		user_id: user.id,
		visibility: isAdmin ? "all" : "user",
		proxy_hosts: isAdmin ? "manage" : "view",
		redirection_hosts: isAdmin ? "manage" : "view",
		dead_hosts: isAdmin ? "manage" : "view",
		streams: isAdmin ? "manage" : "view",
		access_lists: isAdmin ? "manage" : "view",
		certificates: isAdmin ? "manage" : "view",
	});
};

await insertUser({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD, roles: ["admin"] });
await insertUser({ email: PEON_EMAIL, password: PEON_PASSWORD, roles: [] });

const server = app.listen(0, "127.0.0.1");
const listening = new Promise((resolve, reject) => {
	server.on("listening", resolve);
	server.on("error", reject);
});

const api = async (method, path, { body, cookie, headers = {} } = {}) => {
	await listening;
	const res = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
		signal: AbortSignal.timeout(15_000),
		method,
		headers: {
			...(body === undefined ? {} : { "content-type": "application/json" }),
			...(cookie ? { cookie } : {}),
			...headers,
		},
		body: body === undefined ? undefined : JSON.stringify(body),
	});
	const text = await res.text();
	let json = null;
	try {
		json = JSON.parse(text);
	} catch {
		// non-json response body is fine
	}
	return { status: res.status, body: json, text, setCookie: res.headers.getSetCookie() };
};

const sessionCookieOf = (res) => {
	const raw = res.setCookie.find((c) => c.startsWith("__Host-Http-token="));
	return raw ? raw.split(";")[0] : null;
};

const login = async (email, secret) => {
	const res = await api("POST", "/api/tokens", { body: { identity: email, secret } });
	if (res.status !== 200) throw new Error(`login failed: ${res.text}`);
	const cookie = sessionCookieOf(res);
	if (!cookie) throw new Error("no __Host-Http-token cookie was set");
	return cookie;
};

const adminCookie = await login(ADMIN_EMAIL, ADMIN_PASSWORD);
const peonCookie = await login(PEON_EMAIL, PEON_PASSWORD);

after(async () => {
	await new Promise((resolve) => server.close(resolve));
});

test("CRS disable requires admin, audits before acting, and shares the control cooldown", async () => {
	const originalDisable = crsControl.disable;
	const originalAudit = internalAuditLog.add;
	let calls = 0;
	crsControl.disable = async () => {
		calls += 1;
		return { accepted: true, state: "running" };
	};
	try {
		for (const cookie of [undefined, peonCookie]) {
			assert.equal((await api("GET", "/api/crowdsec/crs", { cookie })).status, 403);
			assert.equal((await api("DELETE", "/api/crowdsec/crs", { cookie })).status, 403);
		}
		const invalidMac = crypto
			.createHmac("sha256", "api-test-cookie-secret")
			.update("invalid")
			.digest("base64")
			.replace(/[=]+$/, "");
		assert.equal(
			(await api("DELETE", "/api/crowdsec/crs", { cookie: `__Host-Http-token=s:invalid.${invalidMac}` })).status,
			401,
		);
		assert.equal(
			(
				await api("DELETE", "/api/crowdsec/crs", {
					cookie: adminCookie,
					headers: { origin: "https://attacker.example" },
				})
			).status,
			403,
		);
		assert.equal(calls, 0);
		const accepted = await api("DELETE", "/api/crowdsec/crs", { cookie: adminCookie });
		assert.equal(accepted.status, 202);
		assert.equal(calls, 1);
		const logs = await api("GET", "/api/audit-log", { cookie: adminCookie });
		assert.ok(
			logs.body.some((entry) => entry.object_type === "crowdsec-crs" && entry.action === "disable-requested"),
		);
		// an audit failure must never reach the host
		internalAuditLog.add = async () => {
			throw new Error("fixture audit failure");
		};
		assert.equal((await api("DELETE", "/api/crowdsec/crs", { cookie: adminCookie })).status, 500);
		assert.equal(calls, 1);
		internalAuditLog.add = originalAudit;
		// the shared five-minute bucket runs dry: three more accepted requests
		// reach the limit of five, then the cooldown answers
		for (let index = 0; index < 3; index += 1)
			assert.equal((await api("DELETE", "/api/crowdsec/crs", { cookie: adminCookie })).status, 202);
		assert.equal(calls, 4);
		assert.equal((await api("DELETE", "/api/crowdsec/crs", { cookie: adminCookie })).status, 429);
		assert.equal(calls, 4);
	} finally {
		crsControl.disable = originalDisable;
		internalAuditLog.add = originalAudit;
	}
});
