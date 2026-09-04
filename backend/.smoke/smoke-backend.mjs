// smoke harness: real crowdsec router + real sqlite + fake LAPI (in-process).
// auth is stubbed only via res.locals.access when the x-smoke-admin header is
// present, so the unauthenticated and bad-cookie paths both stay real.
import { createHmac } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SMOKEDIR = path.dirname(fileURLToPath(import.meta.url));
const KEY_FILE = path.join(SMOKEDIR, "lapi-ui.key");
const MACHINE_FILE = path.join(SMOKEDIR, "lapi-ui-machine.key");
const COOKIE_SECRET = "smoke-cookie-secret";

process.env.CROWDSEC_LAPI_URL = "http://127.0.0.1:18080";
process.env.CROWDSEC_METRICS_URL = "http://127.0.0.1:18082/metrics";
process.env.CROWDSEC_LAPI_KEY_FILE = KEY_FILE;
process.env.CROWDSEC_LAPI_MACHINE_KEY_FILE = MACHINE_FILE;
process.env.AUTH_REQUEST_ANUBIS_UPSTREAM = "http://127.0.0.1:18081";
process.env.CROWDSEC_LAPI_TIMEOUT_MS = "2000";
process.env.ANUBIS_HONEYPOT_LOG_FILE = `${SMOKEDIR}/honeypot.addrs`;

// env must be set before the router (and the fake lapi) read anything at import time
await writeFile(KEY_FILE, "smoke-bouncer-key-1234567890abcdef");
await writeFile(MACHINE_FILE, "smoke-machine-password-123456");

const fakeLapi = await import("./fake-lapi.mjs");
await (await import("./fake-anubis.mjs")).start();
await (await import("./fake-metrics.mjs")).start();

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
		`s:${value}.${createHmac("sha256", COOKIE_SECRET).update(value).digest("base64").replace(/[=]+$/, "")}`;
	const ghost = await fetch(`${base}/decisions`, {
		headers: { cookie: `__Host-Http-token=${signCookieValue("not.a.jwt")}` },
	});
	check("GET with a bad session cookie -> 401", ghost.status === 401, `got ${ghost.status}`);

	// 2. admin GET decisions -> only local decisions; CAPI never crosses the UI boundary
	const list = await fetch(`${base}/decisions`, { headers: admin });
	const decisions = (await list.json()).items ?? [];
	check(
		"GET decisions -> 200 with 3 local rows",
		list.status === 200 && decisions.length === 3 && !decisions.some((decision) => decision.origin === "capi"),
		`got ${list.status} ${JSON.stringify(decisions).slice(0, 80)}`,
	);
	check(
		"lapi decision query filters local origins server-side",
		(await lapiLog()).at(-1).query?.includes("origins=crowdsec%2Ccscli%2Ccscli-import"),
		(await lapiLog()).at(-1).query,
	);

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
		decisions2.length === 3 && !decisions2.some((d) => d.id === 2 || d.origin === "capi"),
		JSON.stringify(decisions2.map((d) => d.value)),
	);

	// 7. alerts context for an ip: attacker geo + sanitized event meta
	const alerts = await fetch(`${base}/alerts?scope=Ip&value=198.51.100.7`, { headers: admin });
	const alertsBody = await alerts.json();
	check(
		"GET alerts -> 200 with the alert",
		alerts.status === 200 && alertsBody.length === 1 && alertsBody[0].scenario === "crowdsecurity/http-probing",
		`got ${alerts.status} ${JSON.stringify(alertsBody).slice(0, 80)}`,
	);
	check(
		"alert carries attacker geo details",
		alertsBody[0]?.source?.country === "DE" && alertsBody[0]?.source?.as_name === "Example ASN",
		JSON.stringify(alertsBody[0]?.source),
	);
	check(
		"alert events keep attack meta but strip unknown keys",
		alertsBody[0]?.events?.[0]?.meta?.some((m) => m.key === "target_uri" && m.value === "/.env") &&
			!alertsBody[0]?.events?.[0]?.meta?.some((m) => m.key === "raw_request"),
		JSON.stringify(alertsBody[0]?.events?.[0]?.meta),
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

	// 9b. insights: 24h aggregation over recent alerts, stale ones excluded
	const insights = await fetch(`${base}/insights`, { headers: admin });
	const insightsBody = await insights.json();
	check(
		"GET insights -> 200 with a 24h window",
		insights.status === 200 && insightsBody.window_hours === 24,
		`got ${insights.status} ${JSON.stringify(insightsBody).slice(0, 120)}`,
	);
	check(
		"insights aggregates the two recent alerts only",
		insightsBody.alert_count === 2,
		`got ${JSON.stringify(insightsBody)}`,
	);
	const insightNames = (items) => items.map((i) => i.name);
	check(
		"insights top scenarios cover both recent scenarios",
		["crowdsecurity/http-probing", "crowdsecurity/ssh-bf"].every((s) =>
			insightNames(insightsBody.top_scenarios).includes(s),
		) && !insightNames(insightsBody.top_scenarios).includes("crowdsecurity/http-bad-user-agent"),
		JSON.stringify(insightsBody.top_scenarios),
	);
	check(
		"insights top countries and asns exclude the stale alert",
		insightNames(insightsBody.top_countries).includes("DE") &&
			insightNames(insightsBody.top_countries).includes("FR") &&
			!insightNames(insightsBody.top_countries).includes("JP") &&
			insightNames(insightsBody.top_asns).includes("Example ASN") &&
			!insightNames(insightsBody.top_asns).includes("Stale ASN"),
		JSON.stringify([insightsBody.top_countries, insightsBody.top_asns]),
	);
	check(
		"insights lapi query carries the since filter",
		(await lapiLog()).some((r) => r.path === "/v1/alerts" && r.query?.includes("since=24h")),
		"no since=24h probe logged",
	);
	check(
		"insights lapi query skips decisions",
		(await lapiLog()).some((r) => r.path === "/v1/alerts" && r.query?.includes("with_decisions=false")),
		"no with_decisions=false probe logged",
	);
	check(
		"insights include activity, location and target aggregates",
		insightsBody.activity?.length === 24 &&
			insightsBody.locations?.some((item) => item.country === "DE") &&
			insightNames(insightsBody.top_targets).includes("/.env"),
		JSON.stringify({
			activity: insightsBody.activity?.length,
			locations: insightsBody.locations,
			targets: insightsBody.top_targets,
		}),
	);

	// 9b1. paginated history applies structured filters on the bounded LAPI sample
	const history = await fetch(
		`${base}/history/alerts?page=1&page_size=25&window_hours=24&search=country%3ADE+target%3A.env`,
		{ headers: admin },
	);
	const historyBody = await history.json();
	check(
		"GET alert history -> filtered paginated response",
		history.status === 200 &&
			historyBody.page === 1 &&
			historyBody.items?.length === 1 &&
			historyBody.items[0]?.source?.ip === "198.51.100.7",
		`got ${history.status} ${JSON.stringify(historyBody).slice(0, 180)}`,
	);

	// 9b2. the metrics route parses the fixed private Prometheus endpoint
	const metrics = await fetch(`${base}/metrics`, { headers: admin });
	const metricsBody = await metrics.json();
	check(
		"GET metrics -> summarized private Prometheus data",
		metrics.status === 200 &&
			metricsBody.available === true &&
			metricsBody.appsec_blocked === 3 &&
			metricsBody.local_active_decisions === 3 &&
			metricsBody.community_active_decisions === 42100 &&
			metricsBody.parser_success_rate === 0.9 &&
			metricsBody.average_lapi_ms === 500,
		`got ${metrics.status} ${JSON.stringify(metricsBody)}`,
	);

	// 9b3. an attacked box overflows the primary sample (the lapi attaches
	// every event+meta to each alert); the card must degrade to the smaller
	// fallback sample instead of failing
	fakeLapi.setOversizedInsights(true);
	const insightsHeavy = await fetch(`${base}/insights`, { headers: admin });
	const insightsHeavyBody = await insightsHeavy.json();
	check(
		"insights survives an oversized primary sample via the fallback",
		insightsHeavy.status === 200 &&
			insightsHeavyBody.alert_count === 2 &&
			insightNames(insightsHeavyBody.top_scenarios).includes("crowdsecurity/http-probing"),
		`got ${insightsHeavy.status} ${JSON.stringify(insightsHeavyBody).slice(0, 150)}`,
	);
	fakeLapi.setOversizedInsights(false);

	// 9c. manual ban: validation rejects hostile input before touching the lapi
	const logBeforeBan = (await lapiLog()).length;
	const badBan = await fetch(`${base}/decisions`, {
		method: "POST",
		headers: admin,
		body: JSON.stringify({ value: "http://example.com/", duration: "4h", type: "ban" }),
	});
	const badBanBody = await badBan.json();
	check(
		"POST decisions with a bad target -> 400 crowdsec.invalid-ban-input",
		badBan.status === 400 && badBanBody.error?.message === "crowdsec.invalid-ban-input",
		`got ${badBan.status} ${JSON.stringify(badBanBody)}`,
	);
	check(
		"invalid ban reports the offending fields",
		Array.isArray(badBanBody.error?.fields) && badBanBody.error.fields.includes("value"),
		JSON.stringify(badBanBody.error?.fields),
	);
	check("invalid ban never reached the lapi", (await lapiLog()).length === logBeforeBan);

	const anonBan = await fetch(`${base}/decisions`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ value: "192.0.2.50", duration: "4h", type: "ban" }),
	});
	check("anon POST decisions -> 403", anonBan.status === 403, `got ${anonBan.status}`);

	// 9d. manual ban: valid input posts the manual/web-ui alert and shows up as cscli
	const ban = await fetch(`${base}/decisions`, {
		method: "POST",
		headers: admin,
		body: JSON.stringify({ value: "192.0.2.0/24", duration: "4h", type: "ban", reason: "smoke ban" }),
	});
	const banBody = await ban.json();
	check(
		"POST decisions with a cidr -> 200 created",
		ban.status === 200 && banBody.created === true && banBody.audit_logged === true,
		`got ${ban.status} ${JSON.stringify(banBody).slice(0, 120)}`,
	);
	const banProbe = (await lapiLog()).at(-1);
	check(
		"the lapi saw the manual alert post",
		banProbe.method === "POST" && banProbe.path === "/v1/alerts",
		JSON.stringify(banProbe),
	);
	const list3 = await fetch(`${base}/decisions`, { headers: admin });
	const decisions3 = (await list3.json()).items ?? [];
	const manualDecision = decisions3.find((d) => d.value === "192.0.2.0/24");
	check(
		"the manual ban appears in the list with cscli origin",
		list3.status === 200 && decisions3.length === 4 && manualDecision?.origin === "cscli",
		`got ${list3.status} ${JSON.stringify(decisions3.map((d) => d.value))}`,
	);
	const banRow = db.prepare("select * from audit_log order by id desc limit 1").get();
	check(
		"the manual ban was written to the audit log",
		banRow.action === "created" &&
			banRow.object_type === "crowdsec-decision" &&
			JSON.parse(banRow.meta).value === "192.0.2.0/24",
		JSON.stringify(banRow),
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
	await (await import("./fake-metrics.mjs")).stop();
	console.log(failures === 0 ? "ALL BACKEND SMOKE CHECKS PASSED" : `${failures} FAILURES`);
	server.close();
	process.exit(failures === 0 ? 0 : 1);
});
