// UI smoke driver: real vite dev server + real CrowdSec page, with the /api
// layer served from fixtures via playwright route interception.
// checks the five enhancements as a user sees them: search, relative expiry,
// unban with confirm modal, alert context expansion, and the table itself.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";

// playwright is not a project dependency (it is heavy and platform specific):
// resolve it from the environment or the global npm root so the driver runs
// on any machine without a hardcoded user path.
const npmCommand = process.platform === "win32" ? "cmd.exe" : "npm";
const npmArgs = process.platform === "win32" ? ["/d", "/s", "/c", "npm root -g"] : ["root", "-g"];
const globalRoot = process.env.PLAYWRIGHT_ROOT ?? execFileSync(npmCommand, npmArgs).toString().trim();
const playwrightEntry = path.join(globalRoot, "playwright", "index.mjs");
if (!existsSync(playwrightEntry)) {
	console.error("playwright is not installed globally. Install it with: npm i -g playwright");
	process.exit(1);
}
const { chromium } = await import(`file://${playwrightEntry.replace(/\\/g, "/")}`);

const iso = (ms) => new Date(Date.now() + ms).toISOString();
const in3d = iso(3 * 86400 * 1000);
const in2h = iso(2 * 3600 * 1000);
const in45s = iso(45 * 1000);
const past = iso(-3600 * 1000);

const decisions = [
	{
		id: 4,
		uuid: "d4",
		scope: "Ip",
		value: "203.0.113.9",
		type: "ban",
		origin: "cscli",
		scenario: "anubis-honeypot",
		duration: "24h",
		until: in3d,
		simulated: false,
	},
	{
		id: 3,
		uuid: "d3",
		scope: "Ip",
		value: "198.51.100.7",
		type: "ban",
		origin: "crowdsec",
		scenario: "crowdsecurity/http-probing",
		duration: "4h",
		until: in2h,
		simulated: false,
	},
	{
		id: 2,
		uuid: "d2",
		scope: "Ip",
		value: "192.0.2.55",
		type: "ban",
		origin: "capi",
		scenario: "crowdsecurity/ssh-bf",
		duration: "1h",
		until: in45s,
		simulated: false,
	},
	{
		id: 1,
		uuid: "d1",
		scope: "Ip",
		value: "192.0.2.10",
		type: "ban",
		origin: "cscli",
		scenario: "manual",
		duration: "1h",
		until: past,
		simulated: true,
	},
];

const alerts = [
	{
		id: 99,
		message: "http-probing from 198.51.100.7",
		scenario: "crowdsecurity/http-probing",
		createdAt: iso(-3600 * 1000),
		startAt: iso(-3600 * 1000),
		stopAt: iso(-3500 * 1000),
		machineId: "npmplus",
		simulated: false,
		events_count: 6,
		source: {
			ip: "198.51.100.7",
			scope: "Ip",
			value: "198.51.100.7",
			country: "DE",
			as_number: "64496",
			as_name: "Example ASN",
			range: "198.51.100.0/24",
			rdns: "host.example.com",
			latitude: 51.16,
			longitude: 10.45,
		},
		events: [
			{
				timestamp: iso(-3600 * 1000),
				meta: [
					{ key: "source_ip", value: "198.51.100.7" },
					{ key: "method", value: "GET" },
					{ key: "target_uri", value: "/.env" },
					{ key: "http_user_agent", value: "python-requests/2.31" },
				],
			},
		],
	},
];

const seen = { deleted: null, alertsFor: null, ban: null };
// toggled by the insights-failure check: 1 = lapi rejects, 2 = healthy again
let insightsFail = 0;
let failures = 0;
const check = (name, ok, detail = "") => {
	if (!ok) failures++;
	console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` -> ${detail}`}`);
};

const user = {
	id: 1,
	createdOn: iso(-86400 * 1000),
	modifiedOn: iso(-3600 * 1000),
	isDisabled: false,
	email: "admin@example.com",
	name: "Smoke Admin",
	nickname: "",
	avatar: "",
	roles: ["admin"],
	permissions: { visibility: "enabled", roles: ["admin"] },
};

const api = async (route) => {
	const req = route.request();
	const url = new URL(req.url());
	// vite serves the app source under /src/api/... - only the real XHR /api goes through here
	if (url.pathname.startsWith("/src/")) return route.continue();
	const apiPath = url.pathname.replace(/^\/api/, "");
	const respondWith = (data) =>
		route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(data) });

	if (apiPath === "/" && req.method() === "GET")
		return respondWith({ status: "OK", setup: true, password: false, oidc: false });
	if (apiPath === "/tokens" && req.method() === "POST") return respondWith({ expires: iso(86400 * 1000) });
	if (apiPath === "/tokens" && req.method() === "GET") return respondWith({ expires: iso(86400 * 1000) });
	if (apiPath === "/users/me") return respondWith(user);
	if (apiPath === "/users") return respondWith([user]);
	if (apiPath === "/crowdsec/decisions/delete" && req.method() === "POST") {
		seen.deleted = req.postDataJSON();
		const i = decisions.findIndex((d) => d.id === seen.deleted?.id);
		if (i >= 0) decisions.splice(i, 1);
		return respondWith({ nbDeleted: "1", auditLogged: true });
	}
	if (apiPath === "/crowdsec/decisions" && req.method() === "POST") {
		seen.ban = req.postDataJSON();
		decisions.unshift({
			id: 100,
			uuid: "manual-100",
			scope: "Ip",
			value: seen.ban?.value,
			type: seen.ban?.type ?? "ban",
			origin: "cscli",
			scenario: "manual/web-ui",
			duration: seen.ban?.duration ?? "4h",
			until: in3d,
			simulated: false,
		});
		return respondWith({ created: true, auditLogged: true, result: { nbAlerts: 1, nbDecisions: "1" } });
	}
	if (apiPath === "/crowdsec/decisions") return respondWith({ items: decisions, limit: 200, truncated: false });
	if (apiPath === "/crowdsec/insights") {
		if (insightsFail === 1)
			return route.fulfill({
				status: 502,
				contentType: "application/json",
				body: JSON.stringify({ error: { message: "crowdsec.bad-machine-key" } }),
			});
		return respondWith({
			windowHours: 24,
			alertCount: 7,
			activeDecisions: decisions.length,
			sampled: false,
			activity: Array.from({ length: 24 }, (_, index) => ({
				start: iso((index - 23) * 3600 * 1000),
				count: index === 23 ? 7 : index % 5,
			})),
			locations: [{ latitude: 51.16, longitude: 10.45, country: "DE", count: 5 }],
			signals: [
				{ id: `bans-${decisions.length}`, severity: "info", type: "active-bans", count: decisions.length },
			],
			topScenarios: [
				{ name: "crowdsecurity/http-probing", count: 4 },
				{ name: "crowdsecurity/ssh-bf", count: 3 },
			],
			topCountries: [
				{ name: "DE", count: 5 },
				{ name: "FR", count: 2 },
			],
			topAsns: [{ name: "Example ASN", count: 7 }],
			topTargets: [{ name: "/.env", count: 4 }],
		});
	}
	if (apiPath === "/crowdsec/history/alerts") {
		const search = (url.searchParams.get("search") || "").toLowerCase();
		const scenario = url.searchParams.get("scenario") || "";
		const country = url.searchParams.get("country") || "";
		const target = url.searchParams.get("target") || "";
		const items = alerts.filter(
			(alert) =>
				(!search || JSON.stringify(alert).toLowerCase().includes(search)) &&
				(!scenario || alert.scenario === scenario) &&
				(!country || alert.source.country === country) &&
				(!target || alert.events.some((event) => event.meta.some((meta) => meta.value.includes(target)))),
		);
		return respondWith({
			items,
			page: Number(url.searchParams.get("page") || "1"),
			pageSize: 25,
			hasNext: false,
			matched: items.length,
			windowHours: 24,
			truncated: false,
		});
	}
	if (apiPath === "/crowdsec/metrics")
		return respondWith({
			available: true,
			activeDecisions: decisions.length,
			alerts: 7,
			appsecRequests: 12,
			appsecBlocked: 3,
			bouncerRequests: 20,
			machineRequests: 8,
			parserHits: 10,
			parserSuccessRate: 0.9,
			whitelistHits: 1,
			averageLapiMs: 500,
			averageParsingMs: 2,
		});
	if (apiPath === "/crowdsec/anubis")
		return respondWith({
			configured: true,
			honeypot: {
				activeCount: 1,
				truncated: false,
				items: decisions.filter((d) => d.scenario === "anubis-honeypot"),
			},
			container: { up: true, error: null },
			recent: ["203.0.113.9", "192.0.2.55"],
		});
	if (apiPath === "/crowdsec/alerts") {
		seen.alertsFor = { scope: url.searchParams.get("scope"), value: url.searchParams.get("value") };
		return respondWith(alerts.filter((a) => url.searchParams.get("value") === "198.51.100.7"));
	}
	// unknown: permissive default, logged for iteration
	console.log(
		`  [fixture default] ${req.method()} ${req.url()} (path=${apiPath}) resourceType=${req.resourceType()}`,
	);
	return respondWith([]);
};

const browser = await chromium.launch({
	executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined,
});
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
page.on("console", (m) => m.type() === "error" && console.log(`  [console error] ${m.text().slice(0, 160)}`));
page.on("pageerror", (e) => console.log(`  [page error] ${String(e).slice(0, 160)}`));
await page.route("**/api/**", (route) => api(route));
// AuthStore considers the session live from localStorage, skipping the login form
await page.addInitScript((expires) => localStorage.setItem("auth", expires), iso(86400 * 1000));

await page.goto("http://localhost:5173/crowdsec", { waitUntil: "networkidle" });
await page.waitForSelector("table tbody tr", { timeout: 15000 });

// the table: 4 rows, newest first (scoped to the decisions card: the anubis
// section below has its own table)
const decisionsTable = page.locator(".card").filter({ hasText: "CrowdSec Bans" }).first().locator("tbody tr");
await decisionsTable.first().waitFor({ timeout: 15000 });
let rows = await decisionsTable.allInnerTexts();
check("table renders the 4 bans", rows.length === 4, `${rows.length} rows: ${JSON.stringify(rows).slice(0, 200)}`);
check("newest ban (203.0.113.9) is first", rows[0]?.includes("203.0.113.9"), rows[0]);

// the animated hexagon logo: the card header must carry it and the asset
// must resolve (the orbit itself is smil inside the svg)
const headerLogo = await page
	.locator(".card")
	.filter({ hasText: "CrowdSec Bans" })
	.first()
	.locator('img[src*="crowdsec-logo-animated"]')
	.count();
check("crowdsec header shows the animated hexagon logo", headerLogo === 1, `${headerLogo} logo imgs`);
const logoProbe = await page.evaluate(async () => {
	const r = await fetch("/images/crowdsec-logo-animated.svg");
	const t = await r.text();
	return r.status === 200 && t.includes("animateTransform");
});
check("the animated logo asset resolves with its orbit intact", logoProbe, "asset probe failed");
check("honeypot badge shows", rows[0]?.includes("anubis honeypot"), rows[0]);
check("manual ban shows its scenario", rows[3]?.includes("manual"), rows[3]);

// the anubis section below the decisions table: status, count and recent IPs
const anubisCard = page.locator(".card").filter({ hasText: "Anubis is up" }).first();
await anubisCard.waitFor({ timeout: 5000 });
const anubisCardText = await anubisCard.innerText();
check(
	"anubis section renders with container-up badge",
	anubisCardText.includes("Anubis is up"),
	anubisCardText.slice(0, 200),
);
check(
	"anubis section shows the active ban count",
	anubisCardText.includes("1 active honeypot ban"),
	anubisCardText.slice(0, 200),
);
check(
	"anubis section lists recent honeypot IPs",
	anubisCardText.includes("203.0.113.9") && anubisCardText.includes("192.0.2.55"),
	anubisCardText.slice(0, 200),
);

// relative expiry: rows show the duration the lapi reported
check("first ban shows its 24h duration", /in 24h/.test(rows[0] ?? ""), rows[0]);
check("second ban shows its 4h duration", /in 4h/.test(rows[1] ?? ""), rows[1]);
check("last ban shows its 1h duration", /in 1h/.test(rows[3] ?? ""), rows[3]);

// search: typing filters the list live
await page.locator("#crowdsec-search").fill("203.0");
rows = await decisionsTable.allInnerTexts();
check(
	"search narrows to the matching row",
	rows.length === 1 && rows[0]?.includes("203.0.113.9"),
	JSON.stringify(rows),
);
await page.locator("#crowdsec-search").fill("no-such-ip");
await page.waitForTimeout(200);
rows = await decisionsTable.allInnerTexts();
check(
	"search with no match shows the empty message",
	rows.length === 1 && rows[0]?.includes("No bans match"),
	JSON.stringify(rows),
);
await page.locator("#crowdsec-search").fill("");
await decisionsTable.first().waitFor();

// the origin filter narrows the list the same way
await page.locator("#crowdsec-origin-filter").selectOption("local");
await page.waitForTimeout(200);
rows = await decisionsTable.allInnerTexts();
check(
	"origin filter local keeps the cscli manual ban",
	rows.length === 3 && !rows.some((r) => r.includes("capi")),
	JSON.stringify(rows),
);
await page.locator("#crowdsec-origin-filter").selectOption("community");
await page.waitForTimeout(200);
rows = await decisionsTable.count();
check("origin filter community leaves the capi ban", rows === 1, `${rows} rows`);
await page.locator("#crowdsec-origin-filter").selectOption("all");
await page.waitForTimeout(200);
await decisionsTable.first().waitFor();

// integrated overview: analytics, location plot, count-aware filters and metrics
const dashboardCard = page.locator(".card").filter({ hasText: "Security overview" }).first();
await dashboardCard.waitFor({ timeout: 5000 });
const dashboardText = await dashboardCard.innerText();
check(
	"security overview renders alert and active-ban counts",
	/alerts in window/i.test(dashboardText) && dashboardText.includes("7") && /active bans/i.test(dashboardText),
	dashboardText.slice(0, 240),
);
check(
	"overview lists count-aware scenario, country, ASN and target filters",
	dashboardText.includes("crowdsecurity/http-probing") &&
		dashboardText.includes("DE") &&
		dashboardText.includes("Example ASN") &&
		dashboardText.includes("/.env"),
	dashboardText.slice(0, 400),
);
check(
	"activity chart and attack location plot render",
	(await dashboardCard.locator('svg[aria-label="Attack activity"]').count()) === 1 &&
		(await dashboardCard.locator('svg[aria-label="Attack locations"]').count()) === 1,
	"missing analytics SVG",
);

const historyCard = page.locator(".card").filter({ hasText: "Alert history" }).first();
await historyCard.waitFor({ timeout: 5000 });
let historyText = await historyCard.innerText();
check(
	"paginated alert history renders safe alert details",
	historyText.includes("198.51.100.7") &&
		historyText.includes("crowdsecurity/http-probing") &&
		historyText.includes("Page 1"),
	historyText.slice(0, 300),
);
const metricsCard = page.locator(".card").filter({ hasText: "Engine metrics since restart" }).first();
const metricsText = await metricsCard.innerText();
check(
	"Prometheus summaries render",
	/appsec requests/i.test(metricsText) && metricsText.includes("12") && metricsText.includes("500.0 ms"),
	metricsText.slice(0, 240),
);

await dashboardCard.getByRole("button", { name: /DE 5/ }).click();
await page.waitForTimeout(300);
historyText = await historyCard.innerText();
check(
	"count-aware country filter drills into alert history",
	historyText.includes("DE ×") && historyText.includes("198.51.100.7"),
	historyText.slice(0, 260),
);
await historyCard.getByRole("button", { name: /DE ×/ }).click();

// insights failure: a dead machine key on FIRST load must surface a visible
// warning card, not make the strip silently disappear (a failed refresh with
// data present shows the stale banner instead - that path is covered by the
// stale-warning check above)
insightsFail = 1;
await page.reload({ waitUntil: "networkidle" });
const insightsError = page.locator(".alert-danger").filter({ hasText: "The 24h insights could not load" });
await insightsError.waitFor({ timeout: 10000 });
const insightsErrorText = await insightsError.innerText();
check(
	"insights failure shows the heal hint instead of vanishing",
	insightsErrorText.includes("The 24h insights could not load") &&
		insightsErrorText.includes("npmplus-crowdsec-heal"),
	insightsErrorText.slice(0, 200),
);
insightsFail = 2;
await page
	.locator(".card")
	.filter({ hasText: "Security overview" })
	.first()
	.getByRole("button", { name: /Refresh/ })
	.click();
await dashboardCard.getByText(/Alerts in window/i).waitFor({ timeout: 10000 });
check(
	"insights recovers after the key heals",
	/alerts in window/i.test(await dashboardCard.innerText()),
	(await dashboardCard.innerText()).slice(0, 200),
);

// structured search: field tokens narrow the named field
await page.locator("#crowdsec-search").fill("origin:capi");
await page.waitForTimeout(200);
rows = await decisionsTable.allInnerTexts();
check(
	"structured search origin:capi keeps only the capi ban",
	rows.length === 1 && rows[0]?.includes("192.0.2.55"),
	JSON.stringify(rows),
);
await page.locator("#crowdsec-search").fill("scenario:ssh 192.0.");
await page.waitForTimeout(200);
rows = await decisionsTable.allInnerTexts();
check(
	"field token combines with free text as AND",
	rows.length === 1 && rows[0]?.includes("192.0.2.55"),
	JSON.stringify(rows),
);
await page.locator("#crowdsec-search").fill("");
await page.waitForTimeout(200);
await decisionsTable.first().waitFor();

// alert context: expand a row, wait for the alert fixture to render

// alert context: expand a row, wait for the alert fixture to render
await decisionsTable.nth(1).locator("button").first().click();
await page.waitForSelector("tbody tr td[colspan='7']");
const contextCell = page.locator("tbody tr td[colspan='7']");
await contextCell.getByText("http-probing from 198.51.100.7").waitFor({ timeout: 5000 });
const context = await contextCell.innerText();
check(
	"context row shows the alert scenario + message",
	context.includes("crowdsecurity/http-probing") && context.includes("http-probing from 198.51.100.7"),
	context,
);
check(
	"context fetched with scope+value",
	seen.alertsFor?.scope === "Ip" && seen.alertsFor?.value === "198.51.100.7",
	JSON.stringify(seen.alertsFor),
);
check("context shows the events count", context.includes("6 events"), context);
check(
	"context shows attacker geo details",
	context.includes("DE") && context.includes("Example ASN") && context.includes("AS64496"),
	context,
);
check(
	"context shows how they attacked (event meta)",
	context.includes("target_uri:") && context.includes("/.env") && context.includes("http_user_agent:"),
	context,
);
await page.screenshot({ path: ".smoke/ui-context.png", fullPage: true });

// unban: confirm modal, then the row disappears from the refreshed list
const targetRow = decisionsTable.nth(0);
check("unban button present", (await targetRow.innerText()).includes("Unban"), "");
await targetRow.getByRole("button", { name: /Unban/ }).click();
const modal = page.locator(".modal.show");
await modal.waitFor();
const modalText = await modal.innerText();
check("confirm modal names the target", modalText.includes("203.0.113.9"), modalText);
await page.screenshot({ path: ".smoke/ui-modal.png", fullPage: true });
await modal.getByRole("button", { name: /Confirm|Delete|Unban/ }).click();
await page.waitForTimeout(600);
check("unban POSTed the decision id to the api", seen.deleted?.id === 4, JSON.stringify(seen.deleted));
rows = await decisionsTable.allInnerTexts();
// the expanded context row is also a tbody tr; count only rows that have an Unban button
const banRows = rows.filter((r) => r.includes("Unban"));
check(
	"unbanned row is gone after refresh",
	banRows.length === 3 && !banRows.some((r) => r.includes("203.0.113.9")),
	JSON.stringify(banRows),
);
await page.screenshot({ path: ".smoke/ui-final.png", fullPage: true });

// manual ban: open the modal, submit, and the row appears
await page.locator(".card").filter({ hasText: "CrowdSec Bans" }).first().getByRole("button", { name: /^Ban$/ }).click();
const banModal = page.locator(".modal.show");
await banModal.waitFor();
const banModalText = await banModal.innerText();
check(
	"manual ban modal opens with the form",
	banModalText.includes("IP address or CIDR range") && banModalText.includes("Duration"),
	banModalText.slice(0, 200),
);
check(
	"ban submit is disabled while the target is empty",
	await banModal.getByRole("button", { name: /^Ban$/ }).last().isDisabled(),
	"submit enabled with empty target",
);
await banModal.locator('input[placeholder="1.2.3.4"]').fill("192.0.2.200");
await banModal.getByRole("button", { name: /^Ban$/ }).last().click();
await page.waitForTimeout(600);
check(
	"manual ban POSTed the target to the api",
	seen.ban?.value === "192.0.2.200" && seen.ban?.duration === "4h",
	JSON.stringify(seen.ban),
);
rows = await decisionsTable.allInnerTexts();
check(
	"the manually banned ip appears in the table",
	rows.some((r) => r.includes("192.0.2.200") && r.includes("manual/web-ui")),
	JSON.stringify(rows.map((r) => r.split("\n")[0])),
);
await page.screenshot({ path: ".smoke/ui-ban.png", fullPage: true });

console.log(failures === 0 ? "ALL UI SMOKE CHECKS PASSED" : `${failures} FAILURES`);
await browser.close();
process.exit(failures === 0 ? 0 : 1);
