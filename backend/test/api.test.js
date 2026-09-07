// HTTP-level characterization tests: boot the real express app against a real
// (temporary) sqlite database and pin the auth, permission and CRUD contract.
// The nginx binary is mocked; everything else is the genuine article.
import process from "node:process";
process.env.COOKIE_SECRET ||= "api-test-cookie-secret";

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
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

// lib/config.js hardcodes /data/npmplus for the sqlite database and jwt keys;
// a previous run (or another process) may hold the file, in which case we
// reuse the database and reset the seeded rows after migrating
let dbIsFresh = true;
for (const suffix of ["", "-wal", "-shm"]) {
	try {
		rmSync(`/data/npmplus/database.sqlite${suffix}`, { force: true });
	} catch {
		dbIsFresh = false;
	}
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

await migrateUp();

if (!dbIsFresh) {
	// the database survived from a previous run: drop the previous seeds
	const stale = await getInstance()("user").whereIn("email", [ADMIN_EMAIL, PEON_EMAIL]).select("id");
	for (const { id } of stale) {
		await getInstance()("user_permission").where("user_id", id).del();
		await getInstance()("auth").where("user_id", id).del();
		await getInstance()("user").where("id", id).del();
	}
	await getInstance()("proxy_host").del();
}

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

let adminCookie = null;
let peonCookie = null;

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
		if (String(url).includes("gravatar.com")) return respond(url);
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
