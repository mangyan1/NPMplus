// smoke harness: real crowdsec router + real sqlite + fake LAPI (in-process).
// auth is stubbed only via res.locals.access when the x-smoke-admin header is
// present, so the unauthenticated and bad-cookie paths both stay real.
import { createHmac } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SMOKEDIR = path.dirname(fileURLToPath(import.meta.url));
const KEY_FILE = path.join(SMOKEDIR, "lapi-ui.key");
const MACHINE_FILE = path.join(SMOKEDIR, "lapi-ui-machine.key");
const COOKIE_SECRET = "smoke-cookie-secret";

process.env.CROWDSEC_LAPI_URL = "http://127.0.0.1:18080";
process.env.CROWDSEC_LAPI_KEY_FILE = KEY_FILE;
process.env.CROWDSEC_LAPI_MACHINE_KEY_FILE = MACHINE_FILE;
process.env.AUTH_REQUEST_ANUBIS_UPSTREAM = "http://127.0.0.1:18081";
process.env.CROWDSEC_LAPI_TIMEOUT_MS = "2000";
process.env.ANUBIS_HONEYPOT_LOG_FILE = `${SMOKEDIR}/honeypot.addrs`;

// env must be set before the router (and the fake lapi) read anything at import time
await writeFile(KEY_FILE, "smoke-bouncer-key-1234567890abcdef");
await writeFile(MACHINE_FILE, "smoke-machine-password-123456");

await import("./fake-lapi.mjs");
await (await import("./fake-anubis.mjs")).start();

const express = (await import("express")).default;
const cookieParser = (await import("cookie-parser")).default;
const crowdsecRouter = (await import("../routes/crowdsec.js")).default;
const Database = (await import("better-sqlite3")).default;

const app = express();
app.use(express.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(
	"/api/crowdsec",
	(req, res, next) => {
		if (req.headers["x-smoke-admin"] === "1") {
			// jwtdecode (which runs inside the router) assigns here; make the
			// getter keep returning the stub regardless
			Object.defineProperty(res.locals, "access", {
				get: () => ({
					can: async () => true,
					token: { getUserId: () => 1 },
				}),
				set: () => {},
				configurable: true,
			});
		}
		next();
	},
	crowdsecRouter,
);

const server = app.listen(13000, "127.0.0.1", async () => {
	const base = "http://127.0.0.1:13000/api/crowdsec";
	const admin = { "content-type": "application/json", "x-smoke-admin": "1" };
	let failures = 0;
	const check = (name, ok, detail) => {
		if (!ok) failures++;
		console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` -> ${detail}`}`);
	};

	const lapiLog = async () => {
		try {
			return JSON.parse(await readFile(path.join(SMOKEDIR, "lapi-requests.json"), "utf8"));
		} catch {
			return [];
		}
	};

	// 1. unauthenticated GET (no cookie) -> 403 from the route's admin gate,
	//    never touches the lapi
	const logCount0 = (await lapiLog()).length;
	const anon = await fetch(`${base}/decisions`);
	check("anon GET decisions -> 403", anon.status === 403, `got ${anon.status}`);
	check("anon GET did not reach the lapi", (await lapiLog()).length === logCount0);

	// 1b. a present-but-invalid session cookie -> 401 from jwtdecode (auth
	//     failure), which is what lets the frontend drop a ghost session
	//     back to the login form instead of rendering empty pages. the value
	//     is signed exactly like cookie-signature does (HMAC-SHA256, base64,
	//     trailing '=' stripped) so cookie-parser accepts it as signed and
	//     jwt.verify then rejects the payload as not-a-jwt.
	const signCookieValue = (value) =>
		`s:${value}.${createHmac("sha256", COOKIE_SECRET).update(value).digest("base64").replace(/=+$/, "")}`;
	const ghost = await fetch(`${base}/decisions`, {
		headers: { cookie: `__Host-Http-token=${signCookieValue("not.a.jwt")}` },
	});
	check(
		"GET with a bad session cookie -> 401",
		ghost.status === 401,
		`got ${ghost.status}`,
	);

	// 2. admin GET decisions -> the paged fixture, cap in the query, bouncer key sent
	const list = await fetch(`${base}/decisions`, { headers: admin });
	const decisions = (await list.json()).items ?? [];
	check(
		"GET decisions -> 200 with 4 rows",
		list.status === 200 && decisions.length === 4,
		`got ${list.status} ${JSON.stringify(decisions).slice(0, 80)}`,
	);
	check("lapi got the limit=201 cap probe", (await lapiLog()).at(-1).query === "limit=201");

	// 3. no bouncer key file -> 503 not-wired
	await rm(KEY_FILE);
	const unwired = await fetch(`${base}/decisions`, { headers: admin });
	check(
		"GET without key file -> 503 crowdsec.not-wired",
		unwired.status === 503 && (await unwired.json()).error?.message === "crowdsec.not-wired",
		`got ${unwired.status}`,
	);
	await writeFile(KEY_FILE, "smoke-bouncer-key-1234567890abcdef");

	// 4. invalid unban target -> 400 without hitting the lapi
	const logBefore = (await lapiLog()).length;
	const bad = await fetch(`${base}/decisions/delete`, {
		method: "POST",
		headers: admin,
		body: JSON.stringify({ id: "not-a-number" }),
	});
	check(
		"POST delete with bad scope -> 400 crowdsec.invalid-target",
		bad.status === 400 && (await bad.json()).error?.message === "crowdsec.invalid-target",
		`got ${bad.status}`,
	);
	check("invalid target never reached the lapi", (await lapiLog()).length === logBefore);

	// 5. unban: machine login + lapi delete + audit row
	const db = new Database("D:/data/npmplus/database.sqlite", { readonly: true });
	const auditBefore = db.prepare("select count(*) n from audit_log").get().n;
	const unban = await fetch(`${base}/decisions/delete`, {
		method: "POST",
		headers: admin,
		body: JSON.stringify({ id: 2 }),
	});
	const unbanBody = await unban.json();
	check(
		"POST delete -> 200 nbDeleted 1",
		unban.status === 200 && unbanBody.nbDeleted === "1",
		`got ${unban.status} ${JSON.stringify(unbanBody)}`,
	);
	const newRows = db.prepare("select * from audit_log order by id desc limit 1").get();
	check(
		"audit row written for the unban",
		auditBefore >= 0 &&
			newRows.action === "deleted" &&
			newRows.object_type === "crowdsec-decision" &&
			JSON.parse(newRows.meta).decisionId === 2,
		JSON.stringify(newRows),
	);
	const after = JSON.parse(await readFile(path.join(SMOKEDIR, "lapi-requests.json"), "utf8"));
	check(
		"machine login + bearer delete hit the lapi",
		after.some((r) => r.method === "POST" && r.path === "/v1/watchers/login") &&
			after.some((r) => r.method === "DELETE" && r.path.startsWith("/v1/decisions/")),
		JSON.stringify(after.map((r) => `${r.method} ${r.path}`)),
	);

	// 6. the deleted ip is gone from the list
	const list2 = await fetch(`${base}/decisions`, { headers: admin });
	const decisions2 = (await list2.json()).items ?? [];
	check(
		"unbanned decision is gone from the list",
		decisions2.length === 3 && !decisions2.some((d) => d.id === 2),
		JSON.stringify(decisions2.map((d) => d.value)),
	);

	// 7. alerts context for an ip
	const alerts = await fetch(`${base}/alerts?scope=Ip&value=198.51.100.7`, { headers: admin });
	const alertsBody = await alerts.json();
	check(
		"GET alerts -> 200 with the alert",
		alerts.status === 200 && alertsBody.length === 1 && alertsBody[0].scenario === "crowdsecurity/http-probing",
		`got ${alerts.status} ${JSON.stringify(alertsBody).slice(0, 80)}`,
	);

	// 8. no machine key file -> 503 not-wired-machine
	await rm(MACHINE_FILE);
	const noMachine = await fetch(`${base}/alerts?scope=Ip&value=198.51.100.7`, { headers: admin });
	check(
		"alerts without machine key -> 503 crowdsec.not-wired-machine",
		noMachine.status === 503 && (await noMachine.json()).error?.message === "crowdsec.not-wired-machine",
		`got ${noMachine.status}`,
	);
	await writeFile(MACHINE_FILE, "smoke-machine-password-123456");

	// 9. anubis status: honeypot bans filtered by scenario, container probed
	//    against the fake upstream (401 policy response = serving)
	const anubis = await fetch(`${base}/anubis`, { headers: admin });
	const anubisBody = await anubis.json();
	check(
		"GET anubis -> 200 with the honeypot decision",
		anubis.status === 200 &&
			anubisBody.honeypot.activeCount === 1 &&
			anubisBody.honeypot.items[0]?.value === "203.0.113.9" &&
			anubisBody.honeypot.items[0]?.scenario === "anubis-honeypot",
		`got ${anubis.status} ${JSON.stringify(anubisBody).slice(0, 120)}`,
	);
	check(
		"anubis lapi query filters by the honeypot scenario",
		(await lapiLog()).some((r) => r.query?.includes("scenarios_containing=anubis-honeypot")),
		JSON.stringify((await lapiLog()).map((r) => r.query)),
	);
	check(
		"anubis container counts a 401 policy response as up",
		anubisBody.configured === true && anubisBody.container.up === true && !anubisBody.container.error,
		JSON.stringify(anubisBody.container),
	);
	check(
		"anubis recent list reads the mounted honeypot log",
		(anubisBody.recent ?? []).length === 3 && anubisBody.recent[0] === "203.0.113.99",
		JSON.stringify(anubisBody.recent),
	);

	// 10. a hung anubis (accepts the connection, never answers) must read as down
	const fakeAnubis = await import("./fake-anubis.mjs");
	fakeAnubis.setAnswering(false);
	const anubisDown = await fetch(`${base}/anubis`, { headers: admin });
	const anubisDownBody = await anubisDown.json();
	check(
		"a not-answering anubis reads as down",
		anubisDown.status === 200 &&
			anubisDownBody.container.up === false &&
			anubisDownBody.container.error === "crowdsec.anubis-unreachable",
		JSON.stringify(anubisDownBody.container),
	);
	fakeAnubis.setAnswering(true);

	db.close();
	await (await import("./fake-anubis.mjs")).stop();
	console.log(failures === 0 ? "ALL BACKEND SMOKE CHECKS PASSED" : `${failures} FAILURES`);
	server.close();
	process.exit(failures === 0 ? 0 : 1);
});
