// HTTP-level characterization tests: boot the real express app against a real
// (temporary) sqlite database and pin the auth, permission and CRUD contract.
// The nginx binary is mocked; everything else is the genuine article.
import "./helpers/environment.js";
import process from "node:process";

process.env.COOKIE_SECRET ||= "api-test-cookie-secret";

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync } from "node:fs";
import net from "node:net";
import { after, test } from "node:test";

// the container image creates these before the app boots; the nginx config
// generation and access-list handling expect them to exist
for (const dir of [
	"/data/npmplus",
	// the container image pre-creates the gravatar cache; user.js writes into
	// it directly, so the create/update contract tests need it present
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

const { default: getInstance } = await import("../db.js");
const { migrateUp } = await import("../migrate.js");
const { default: app } = await import("../app.js");
// index.js compiles the api schemas at boot; without it every apiValidator
// call 400s with "Schema is undefined"
const { getCompiledSchema } = await import("../schema/index.js");
await getCompiledSchema();
const utils = (await import("../lib/utils.js")).default;
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
	await authModel
		.query()
		// models/auth.js hashes the secret on insert, so pass it in plain
		.insert({ user_id: user.id, type: "password", secret: password, meta: {} });
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
	return user;
};

await insertUser({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD, roles: ["admin"] });

// setup.js seeds this row for real installations; the api settings test needs it
await getInstance()("setting").insert({
	id: "default-site",
	name: "Default Site",
	description: "The default site served for unknown hosts",
	value: "congratulations",
	meta: {},
});

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

// jwt iat stamps are whole seconds and revocation rejects iat <= the
// user's token_valid_after stamp, so a login issued in the same second as a
// revoke is born dead (the app's self-service refreshes add iat+1 for this).
// Tests that revoke and then re-login must cross the second boundary first.
const nextSecond = async () => {
	const now = Math.floor(Date.now() / 1000);
	for (let i = 0; i < 50; i++) {
		if (Math.floor(Date.now() / 1000) > now) return;
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
};

// express clears a cookie by emitting the name with an empty value
const CLEARED_SESSION_COOKIE_RE = /^__Host-Http-token=;/;
const OIDC_NO_REDIRECT_PREFIX = "__Host-npmplus_oidc_no_redirect=true";
const OIDC_NO_REDIRECT_EXPIRY_RE = /Max-Age=3600|Expires=/;

let adminCookie = null;
let peonCookie = null;
// numeric ids for the session-revocation tests (captured at login/creation)
let adminId = null;
let peonId = null;

// the server already started listening at module load, so there is no
// listening event left to await here; closeAllConnections is required because
// undici keeps keep-alive sockets open and server.close would wait forever,
// and the knex pool must be torn down or the process never exits
after(async () => {
	server.closeAllConnections();
	await new Promise((resolve) => server.close(resolve));
	await getInstance().destroy();
});

// a missing token yields an anonymous access object whose permission check
// 403s; a *present but invalid* token is what produces a 401
test("a missing session is refused (403)", async () => {
	const res = await api("GET", "/api/settings");
	assert.equal(res.status, 403);
});

// an unsigned garbage cookie is dropped by cookie-parser and looks like "no
// session" (403); a *signed* cookie carrying a bogus jwt is what reaches the
// token verification failure and 401s
test("an invalid session token is an authentication failure (401)", async () => {
	// cookie-signature 1.0.6 wire format: val + '.' + b64(hmac-sha256(secret, val)).replace(/=+$/,'')
	const mac = crypto
		.createHmac("sha256", "api-test-cookie-secret")
		.update("not-a-real-token")
		.digest("base64")
		.replace(/[=]+$/, "");
	const res = await api("GET", "/api/settings", { cookie: `__Host-Http-token=s:not-a-real-token.${mac}` });
	assert.equal(res.status, 401);
});

test("a cross-origin request is rejected before auth (403)", async () => {
	const res = await api("GET", "/api/settings", { headers: { origin: "http://evil.example" } });
	assert.equal(res.status, 403);
	assert.equal(res.body.error.message, "Rejected Origin.");
});

test("a cross-site fetch-metadata request is rejected (403)", async () => {
	const res = await api("GET", "/api/settings", { headers: { "sec-fetch-site": "cross-site" } });
	assert.equal(res.status, 403);
	assert.equal(res.body.error.message, "Rejected Sec-Fetch-Site Value.");
});

// AuthError carries status 400 in this codebase, so rejected logins are 400
test("wrong credentials are rejected", async () => {
	const res = await api("POST", "/api/tokens", { body: { identity: ADMIN_EMAIL, secret: "wrong-password" } });
	assert.equal(res.status, 400);
});

test("good credentials issue a signed session cookie", async () => {
	const res = await api("POST", "/api/tokens", { body: { identity: ADMIN_EMAIL, secret: ADMIN_PASSWORD } });
	assert.equal(res.status, 200);
	const cookie = sessionCookieOf(res);
	assert.ok(cookie, "no __Host-Http-token cookie was set");
	// cookie-parser signed cookies carry the s: signature prefix (express
	// percent-encodes the colon on the wire)
	assert.ok(decodeURIComponent(cookie).startsWith("__Host-Http-token=s:"), "cookie is not signed");
	adminCookie = cookie;
	// expose the numeric id for the session-revocation tests
	const me = await api("GET", "/api/users/me", { cookie: adminCookie });
	assert.equal(me.status, 200, me.text);
	adminId = me.body.id;
});

test("an existing session can refresh its token", async () => {
	const res = await api("GET", "/api/tokens", { cookie: adminCookie });
	assert.equal(res.status, 200);
	const refreshed = sessionCookieOf(res);
	assert.ok(refreshed, "refresh did not set a new cookie");
	adminCookie = refreshed;
});

test("admin reads the settings list", async () => {
	const res = await api("GET", "/api/settings", { cookie: adminCookie });
	assert.equal(res.status, 200);
	assert.ok(Array.isArray(res.body));
});

test("admin updates a setting and reads it back", async (t) => {
	// updating default-site regenerates the nginx default config and reloads
	t.mock.method(utils, "execFile", async () => ({ stdout: "ok" }));
	const put = await api("PUT", "/api/settings/default-site", {
		cookie: adminCookie,
		body: { value: "congratulations" },
	});
	assert.equal(put.status, 200, put.text);
	const read = await api("GET", "/api/settings/default-site", { cookie: adminCookie });
	assert.equal(read.status, 200);
	assert.equal(read.body.value, "congratulations");
});

test("admin creates a user with password auth", async () => {
	const res = await api("POST", "/api/users", {
		cookie: adminCookie,
		body: { name: "Peon", nickname: "peon", email: PEON_EMAIL, auth: { type: "password", secret: PEON_PASSWORD } },
	});
	assert.equal(res.status, 201);
	assert.ok(res.body.id > 0);
});

test("the new user can log in and hits the permission wall on admin routes", async () => {
	const login = await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: PEON_PASSWORD } });
	assert.equal(login.status, 200);
	peonCookie = sessionCookieOf(login);
	assert.ok(peonCookie, "peon login did not set a cookie");

	// the session-revocation tests below address this user by numeric id
	const me = await api("GET", "/api/users/me", { cookie: peonCookie });
	assert.equal(me.status, 200, me.text);
	peonId = me.body.id;

	const res = await api("GET", "/api/users", { cookie: peonCookie });
	assert.equal(res.status, 403);
});

test("peon can still read proxy hosts (view permission)", async () => {
	const res = await api("GET", "/api/nginx/proxy-hosts", { cookie: peonCookie });
	assert.equal(res.status, 200);
	assert.deepEqual(res.body, []);
});

test("proxy host CRUD round-trips through nginx config generation", async (t) => {
	t.mock.method(utils, "execFile", async () => ({ stdout: "ok" }));

	const created = await api("POST", "/api/nginx/proxy-hosts", {
		cookie: adminCookie,
		body: {
			domain_names: ["crud.example.com"],
			forward_scheme: "http",
			forward_host: "127.0.0.1",
			forward_port: 8080,
		},
	});
	assert.equal(created.status, 201, created.text);
	const hostId = created.body.id;
	assert.deepEqual(created.body.domain_names, ["crud.example.com"]);

	const list = await api("GET", "/api/nginx/proxy-hosts", { cookie: adminCookie });
	assert.equal(list.status, 200);
	assert.ok(list.body.some((row) => row.id === hostId));

	const updated = await api("PUT", `/api/nginx/proxy-hosts/${hostId}`, {
		cookie: adminCookie,
		body: { forward_port: 9090 },
	});
	assert.equal(updated.status, 200, updated.text);
	assert.equal(updated.body.forward_port, 9090);

	const removed = await api("DELETE", `/api/nginx/proxy-hosts/${hostId}`, { cookie: adminCookie });
	assert.equal(removed.status, 200, removed.text);

	const cleared = await api("GET", "/api/nginx/proxy-hosts", { cookie: adminCookie });
	assert.ok(!cleared.body.some((row) => row.id === hostId));
});

// --- proxy host forward-destination reachability probe ---

// a real listening socket on an ephemeral port, so the tcp probe has a
// genuine destination to succeed against
const listenOnEphemeralPort = () =>
	new Promise((resolve, reject) => {
		const srv = net.createServer(() => {});
		srv.once("error", reject);
		srv.listen(0, "127.0.0.1", () => resolve({ srv, port: srv.address().port }));
	});

test("proxy host create probes the forward destination and reports it reachable", async (t) => {
	t.mock.method(utils, "execFile", async () => ({ stdout: "ok" }));
	const { srv, port } = await listenOnEphemeralPort();
	try {
		const created = await api("POST", "/api/nginx/proxy-hosts", {
			cookie: adminCookie,
			body: {
				domain_names: ["reach-ok.example.com"],
				forward_scheme: "http",
				forward_host: "127.0.0.1",
				forward_port: port,
			},
		});
		assert.equal(created.status, 201, created.text);
		assert.equal(created.body.meta.reach_ok, true, created.text);
		assert.equal(created.body.meta.reach_err, null, created.text);

		const fetched = await api("GET", `/api/nginx/proxy-hosts/${created.body.id}`, { cookie: adminCookie });
		assert.equal(fetched.body.meta.reach_ok, true, fetched.text);
	} finally {
		srv.close();
	}
});

test("proxy host create reports an unreachable forward destination", async (t) => {
	t.mock.method(utils, "execFile", async () => ({ stdout: "ok" }));
	// grab an ephemeral port and then let go of it, so nothing is listening
	const { srv, port } = await listenOnEphemeralPort();
	await new Promise((resolve) => srv.close(resolve));

	const created = await api("POST", "/api/nginx/proxy-hosts", {
		cookie: adminCookie,
		body: {
			domain_names: ["reach-dead.example.com"],
			forward_scheme: "http",
			forward_host: "127.0.0.1",
			forward_port: port,
		},
	});
	assert.equal(created.status, 201, created.text);
	assert.equal(created.body.meta.reach_ok, false, created.text);
	assert.ok(created.body.meta.reach_err, "no reach error message stored");
});

test("proxy host without a tcp destination skips the reachability probe", async (t) => {
	t.mock.method(utils, "execFile", async () => ({ stdout: "ok" }));

	const created = await api("POST", "/api/nginx/proxy-hosts", {
		cookie: adminCookie,
		body: {
			domain_names: ["reach-path.example.com"],
			forward_scheme: "path",
			forward_host: "/data/html",
			forward_port: 80,
		},
	});
	assert.equal(created.status, 201, created.text);
	assert.equal("reach_ok" in created.body.meta, false, created.text);
});

// CrowdSec routes: no LAPI is wired in the test environment, so these pin the
// permission wall and the input-validation guards that fire before the LAPI
// is ever contacted
test("peon is refused on crowdsec routes", async () => {
	const res = await api("GET", "/api/crowdsec/decisions", { cookie: peonCookie });
	assert.equal(res.status, 403);
	assert.equal(res.body.error.message, "access.denied");
});

test("crowdsec pagination guard fires before the LAPI is contacted", async () => {
	const res = await api("GET", "/api/crowdsec/decisions?page=10&page_size=100", { cookie: adminCookie });
	assert.equal(res.status, 400);
	assert.equal(res.body.error.message, "crowdsec.page-too-deep");
});

test("crowdsec manual-ban validation fires before the LAPI is contacted", async () => {
	const res = await api("POST", "/api/crowdsec/decisions", { cookie: adminCookie, body: { value: "" } });
	assert.equal(res.status, 400);
	assert.equal(res.body.error.message, "crowdsec.invalid-ban-input");
});

test("Anubis reporting retains admin authorization and unknown metrics before collection", async () => {
	assert.equal((await api("GET", "/api/crowdsec/anubis-report")).status, 403);
	assert.equal((await api("GET", "/api/crowdsec/anubis-report", { cookie: peonCookie })).status, 403);
	const report = await api("GET", "/api/crowdsec/anubis-report?window=1", { cookie: adminCookie });
	assert.equal(report.status, 200, report.text);
	assert.equal(report.body.metrics.status, "unavailable");
	assert.equal(report.body.metrics.totals.issued, null);
	assert.equal(report.body.ledger.total, 0);
});

test("crowdsec reads degrade to a stable not-wired error without a LAPI key", async () => {
	// key-auth reads and machine-token reads report distinct wiring states,
	// while the anubis view degrades per-probe instead of failing
	const expectations = [
		["/api/crowdsec/decisions", 503, "crowdsec.not-wired"],
		["/api/crowdsec/insights", 503, "crowdsec.not-wired-machine"],
	];
	for (const [path, status, expected] of expectations) {
		const res = await api("GET", path, { cookie: adminCookie });
		assert.equal(res.status, status, `${path}: ${res.text}`);
		assert.equal(res.body.error.message, expected, `${path}: ${res.text}`);
	}
	const anubis = await api("GET", "/api/crowdsec/anubis", { cookie: adminCookie });
	assert.equal(anubis.status, 200, anubis.text);
	assert.equal(anubis.body.configured, false);
	assert.equal(anubis.body.honeypot.decisionsAvailable, false);
	assert.equal(anubis.body.honeypot.status, "disabled");
});

// --- gravatar avatar contract ---

// a fake but structurally valid png: user.js switches on content-type and
// stores whatever bytes arrived, so only the header matters to the contract
const gravatarPng = Buffer.from("89504e470d0a1a0a00000000", "hex");
const gravatarHashOf = (email) => crypto.createHash("sha256").update(email.toLowerCase().trim()).digest("hex");

// gravatar.com must never be contacted for real in tests; everything else
// (the api helper itself) goes through the untouched original fetch
const mockGravatarFetch = (t, respond) => {
	const realFetch = globalThis.fetch;
	t.mock.method(globalThis, "fetch", (url, options) => {
		// match the parsed hostname only, so a "gravatar.com" string inside a
		// path or query cannot trigger the mock
		let hostname = "";
		try {
			hostname = new URL(String(url)).hostname;
		} catch {
			// not a parseable URL, let the original fetch handle it
		}
		if (hostname === "www.gravatar.com" || hostname === "gravatar.com") return respond(url);
		return realFetch(url, options);
	});
};

test("user creation downloads and stores the gravatar for the email", async (t) => {
	mockGravatarFetch(t, () => new Response(gravatarPng, { status: 200, headers: { "content-type": "image/png" } }));
	const { readFile } = await import("node:fs/promises");
	const res = await api("POST", "/api/users", {
		cookie: adminCookie,
		body: { name: "Grav Atar", nickname: "grav", email: "gravatar-user@example.com" },
	});
	assert.equal(res.status, 201, res.text);
	const hash = gravatarHashOf("gravatar-user@example.com");
	assert.equal(res.body.avatar, `/images/gravatar/${hash}.png`);
	const stored = await readFile(`/data/npmplus/gravatar/${hash}.png`);
	assert.equal(stored.subarray(0, 4).toString("hex"), "89504e47");
});

test("a failed gravatar download falls back to the default avatar", async (t) => {
	mockGravatarFetch(t, () => new Response("nope", { status: 500 }));
	const res = await api("POST", "/api/users", {
		cookie: adminCookie,
		body: {
			name: "Grav Fail",
			nickname: "gravfail",
			email: "gravatar-fail@example.com",
			auth: { type: "password", secret: "Grav-Fail-1" },
		},
	});
	assert.equal(res.status, 201, res.text);
	assert.equal(res.body.avatar, "/images/default-avatar.jpg");
});

test("a custom local avatar survives a user update", async (t) => {
	const user = await insertUser({ email: "local-avatar@example.com", password: "Local-Avatar-1", roles: ["user"] });
	await userModel.query().patchAndFetchById(user.id, { avatar: "/images/avatar/local.jpg" });
	const res = await api("PUT", `/api/users/${user.id}`, {
		cookie: adminCookie,
		body: { name: "Renamed", nickname: "renamed", email: "local-avatar@example.com" },
	});
	assert.equal(res.status, 200, res.text);
	assert.equal(res.body.avatar, "/images/avatar/local.jpg");
});

test("login backfills the avatar of a user whose row has none", async (t) => {
	// this mimics the installer seed path, which inserts the user directly
	// with an empty avatar and never runs the gravatar download
	const seeded = await insertUser({ email: "backfill@example.com", password: "Backfill-1", roles: ["admin"] });
	assert.equal(seeded.avatar, "");

	mockGravatarFetch(t, () => new Response(gravatarPng, { status: 200, headers: { "content-type": "image/png" } }));
	const login = await api("POST", "/api/tokens", {
		body: { identity: "backfill@example.com", secret: "Backfill-1" },
	});
	assert.equal(login.status, 200, login.text);

	// the backfill runs in the background so it cannot slow the login down
	const hash = gravatarHashOf("backfill@example.com");
	for (let waited = 0; waited < 5000; waited += 100) {
		const row = await userModel.query().findById(seeded.id);
		if (row.avatar === `/images/gravatar/${hash}.png`) return;
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
	assert.fail("login did not backfill the missing gravatar avatar");
});

test("a failed backfill leaves the avatar empty for the next login to retry", async (t) => {
	const seeded = await insertUser({ email: "backfill-fail@example.com", password: "Backfill-2", roles: ["admin"] });
	mockGravatarFetch(t, () => new Response("nope", { status: 500 }));
	const login = await api("POST", "/api/tokens", {
		body: { identity: "backfill-fail@example.com", secret: "Backfill-2" },
	});
	assert.equal(login.status, 200, login.text);
	await new Promise((resolve) => setTimeout(resolve, 300));
	const row = await userModel.query().findById(seeded.id);
	assert.equal(row.avatar, "");
});

test("security telemetry requires admin access and represents an empty collector honestly", async () => {
	assert.equal((await api("GET", "/api/crowdsec/telemetry")).status, 403);
	assert.equal((await api("GET", "/api/crowdsec/telemetry", { cookie: peonCookie })).status, 403);
	const result = await api("GET", "/api/crowdsec/telemetry?window_hours=1", { cookie: adminCookie });
	assert.equal(result.status, 200);
	assert.equal(result.body.window_hours, 1);
	assert.equal(result.body.nginx.status, "unavailable");
	assert.equal(result.body.nginx.incomplete, true);
	assert.deepEqual(result.body.nginx.hosts, []);
});

test("extended alert history retains the admin gate", async () => {
	assert.equal((await api("GET", "/api/crowdsec/history/alerts?cursor=")).status, 403);
	assert.equal((await api("GET", "/api/crowdsec/history/alerts?cursor=", { cookie: peonCookie })).status, 403);
});

// ---------------------------------------------------------------------------
// Upstream merge (4952ce4b): session-revocation semantics. A password change,
// MFA change, or session revoke stamps user.npmplus_token_valid_after; tokens
// issued before the stamp die with 401 (AuthError "Token has been revoked"),
// and the self-service flows must issue a fresh cookie so the acting session
// survives its own revocation.
//
// NOTE on the users-route rate limiter: routes/users.js counts FAILED
// requests (5 per 5 min, skipSuccessfulRequests). Deliberate failures here
// are budgeted: one 400 (missing current password) and one 403 (peon revoking
// another user). Session-death (401) assertions therefore run against
// /api/nginx/proxy-hosts, which has no limiter, instead of /api/users/me.
// ---------------------------------------------------------------------------

test("a self password change issues a fresh cookie and kills the old session", async () => {
	const NEW_PASSWORD = "Rotated-Pass-2";
	const login1 = await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: PEON_PASSWORD } });
	assert.equal(login1.status, 200, login1.text);
	const oldCookie = sessionCookieOf(login1);
	assert.ok(oldCookie, "initial login set no cookie");

	const change = await api("PUT", `/api/users/${peonId}/auth`, {
		cookie: oldCookie,
		body: { type: "password", current: PEON_PASSWORD, secret: NEW_PASSWORD },
	});
	assert.equal(change.status, 200, change.text);
	// the self-change must hand out a token stamped after the revocation
	const freshCookie = sessionCookieOf(change);
	assert.ok(freshCookie, "self password change did not issue a fresh session cookie");
	assert.notEqual(freshCookie, oldCookie, "fresh cookie equals the revoked one");

	// the OLD token now fails as an authentication failure (401), keeping the
	// frontend's "log in again" semantics (limiter-free route)
	assert.equal(
		(await api("GET", "/api/nginx/proxy-hosts", { cookie: oldCookie })).status,
		401,
		"the pre-change session was not revoked",
	);
	// the fresh cookie keeps working
	assert.equal((await api("GET", "/api/nginx/proxy-hosts", { cookie: freshCookie })).status, 200);

	// the old password is dead and the new one works
	assert.equal(
		(await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: PEON_PASSWORD } })).status,
		400,
		"the old password still authenticates",
	);
	const login2 = await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: NEW_PASSWORD } });
	assert.equal(login2.status, 200, login2.text);
	peonCookie = sessionCookieOf(login2);
	assert.ok(peonCookie, "re-login after password change set no cookie");
	assert.equal(
		(await api("GET", "/api/nginx/proxy-hosts", { cookie: peonCookie })).status,
		200,
		"immediate re-login must issue a usable session",
	);
	const refreshed = await api("GET", "/api/tokens", { cookie: peonCookie });
	assert.equal(refreshed.status, 200, refreshed.text);
	const refreshedCookie = sessionCookieOf(refreshed);
	assert.ok(refreshedCookie);
	assert.equal((await api("GET", "/api/nginx/proxy-hosts", { cookie: refreshedCookie })).status, 200);
});

test("a self password change without the current password is refused", async () => {
	const res = await api("PUT", `/api/users/${peonId}/auth`, {
		cookie: peonCookie,
		body: { type: "password", secret: "Still-No-Current-1" },
	});
	assert.equal(res.status, 400, res.text);
	// the refusal must not have stamped token_valid_after: the session lives
	assert.equal((await api("GET", "/api/nginx/proxy-hosts", { cookie: peonCookie })).status, 200);
});

test("an admin password change for another user does not refresh the admin session", async () => {
	const OTHER_PASSWORD = "Other-User-Pass-3";
	const created = await api("POST", "/api/users", {
		cookie: adminCookie,
		body: {
			name: "Rotated",
			nickname: "rotated",
			email: "rotated@example.com",
			auth: { type: "password", secret: OTHER_PASSWORD },
		},
	});
	assert.equal(created.status, 201, created.text);
	const otherId = created.body.id;

	// admin rotates the OTHER user's password: no fresh cookie for the admin
	const change = await api("PUT", `/api/users/${otherId}/auth`, {
		cookie: adminCookie,
		body: { type: "password", secret: "Rotated-Pass-4" },
	});
	assert.equal(change.status, 200, change.text);
	assert.ok(!sessionCookieOf(change), "admin session was refreshed while changing someone else's password");
	// admin session is untouched by the other user's stamp
	assert.equal((await api("GET", "/api/users/me", { cookie: adminCookie })).status, 200);
	// the other user's pre-change password is dead
	assert.equal(
		(await api("POST", "/api/tokens", { body: { identity: "rotated@example.com", secret: OTHER_PASSWORD } }))
			.status,
		400,
		"the other user's pre-change password still works",
	);
});

test("revoking your own sessions clears the cookie and sets the oidc opt-out", async () => {
	// dedicated session so the shared peon cookie survives this test
	const login = await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: "Rotated-Pass-2" } });
	assert.equal(login.status, 200, login.text);
	const cookie = sessionCookieOf(login);
	assert.ok(cookie);

	const revoke = await api("DELETE", "/api/users/me/sessions", { cookie });
	assert.equal(revoke.status, 200, revoke.text);

	// the response must clear the session cookie and set the OIDC no-redirect
	// opt-out the login page reads after a self-revoke
	const cleared = revoke.setCookie.find((c) => CLEARED_SESSION_COOKIE_RE.test(c));
	assert.ok(cleared, "self session revoke did not clear the session cookie");
	const noRedirect = revoke.setCookie.find((c) => c.startsWith(OIDC_NO_REDIRECT_PREFIX));
	assert.ok(noRedirect, "self session revoke did not set the OIDC no-redirect cookie");
	assert.ok(OIDC_NO_REDIRECT_EXPIRY_RE.test(noRedirect), "oidc no-redirect cookie has no expiry");

	// the revoked session dies as 401 (limiter-free route) and re-login works
	assert.equal((await api("GET", "/api/nginx/proxy-hosts", { cookie })).status, 401);
	await nextSecond();
	const relogin = await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: "Rotated-Pass-2" } });
	assert.equal(relogin.status, 200, relogin.text);
	assert.ok(sessionCookieOf(relogin), "re-login after self session revoke set no cookie");
	// the self-revoke stamped the whole USER, so the shared peon cookie also
	// died; refresh it for the tests that follow
	peonCookie = sessionCookieOf(relogin);
});

test("revoking another user's sessions requires admin and does not clear the caller cookie", async () => {
	// a non-admin revoking someone else gets the permission wall (403)
	const otherSessions = await api("DELETE", `/api/users/${adminId}/sessions`, { cookie: peonCookie });
	assert.equal(otherSessions.status, 403);

	// admin revoking the peon's sessions: the peon dies, the admin survives
	const revoke = await api("DELETE", `/api/users/${peonId}/sessions`, { cookie: adminCookie });
	assert.equal(revoke.status, 200, revoke.text);
	assert.ok(!sessionCookieOf(revoke), "admin session was cleared while revoking the peon");
	const cleared = revoke.setCookie.find((c) => c.startsWith("__Host-npmplus_oidc_no_redirect"));
	assert.ok(!cleared, "oidc opt-out was set for a revoke of another user");
	assert.equal((await api("GET", "/api/users/me", { cookie: adminCookie })).status, 200);

	// the peon's session (issued at the end of the previous test) dies as 401
	// (limiter-free route) and can simply log back in
	assert.equal((await api("GET", "/api/nginx/proxy-hosts", { cookie: peonCookie })).status, 401);
	await nextSecond();
	const back = await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: "Rotated-Pass-2" } });
	assert.equal(back.status, 200, back.text);
	peonCookie = sessionCookieOf(back);
	assert.ok(peonCookie);
});

test("a revoked session is rejected on every request, not only the first after revoke", async () => {
	// pin that the revocation check runs per-request against the database
	// stamp: issue two requests on the same cookie, revoke between them
	await nextSecond();
	const cookie = sessionCookieOf(
		await api("POST", "/api/tokens", { body: { identity: PEON_EMAIL, secret: "Rotated-Pass-2" } }),
	);
	assert.ok(cookie);
	assert.equal((await api("GET", "/api/nginx/proxy-hosts", { cookie })).status, 200);
	await api("DELETE", "/api/users/me/sessions", { cookie });
	// same cookie object, brand-new request: must hit the revocation check
	assert.equal((await api("GET", "/api/nginx/proxy-hosts", { cookie })).status, 401);
});
