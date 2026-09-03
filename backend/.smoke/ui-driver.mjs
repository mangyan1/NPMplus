// UI smoke driver: real vite dev server + real CrowdSec page, with the /api
// layer served from fixtures via playwright route interception.
// checks the five enhancements as a user sees them: search, relative expiry,
// unban with confirm modal, alert context expansion, and the table itself.
import { chromium } from "file:///C:/Users/Hashi/AppData/Roaming/npm/node_modules/playwright/index.mjs";

const iso = (ms) => new Date(Date.now() + ms).toISOString();
const in3d = iso(3 * 86400 * 1000);
const in2h = iso(2 * 3600 * 1000);
const in45s = iso(45 * 1000);
const past = iso(-3600 * 1000);

const decisions = [
	{ id: 4, uuid: "d4", scope: "Ip", value: "203.0.113.9", type: "ban", origin: "cscli", scenario: "anubis-honeypot", duration: "24h", until: in3d, simulated: false },
	{ id: 3, uuid: "d3", scope: "Ip", value: "198.51.100.7", type: "ban", origin: "crowdsec", scenario: "crowdsecurity/http-probing", duration: "4h", until: in2h, simulated: false },
	{ id: 2, uuid: "d2", scope: "Ip", value: "192.0.2.55", type: "ban", origin: "capi", scenario: "crowdsecurity/ssh-bf", duration: "1h", until: in45s, simulated: false },
	{ id: 1, uuid: "d1", scope: "Ip", value: "192.0.2.10", type: "ban", origin: "cscli", scenario: "manual", duration: "1h", until: past, simulated: true },
];

const alerts = [
	{ id: 99, message: "http-probing from 198.51.100.7", scenario: "crowdsecurity/http-probing", started_at: iso(-3600 * 1000), events_count: 6, events: [{}] },
];

const seen = { deleted: null, alertsFor: null };
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
	const path = url.pathname.replace(/^\/api/, "");
	const json = (data) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(data) });

	if (path === "/" && req.method() === "GET") return json({ status: "OK", setup: true, password: false, oidc: false });
	if (path === "/tokens" && req.method() === "POST") return json({ expires: iso(86400 * 1000) });
	if (path === "/tokens" && req.method() === "GET") return json({ expires: iso(86400 * 1000) });
	if (path === "/users/me") return json(user);
	if (path === "/users") return json([user]);
	if (path === "/crowdsec/decisions/delete" && req.method() === "POST") {
		seen.deleted = req.postDataJSON();
		const i = decisions.findIndex((d) => d.id === seen.deleted?.id);
		if (i >= 0) decisions.splice(i, 1);
		return json({ nbDeleted: "1", auditLogged: true });
	}
	if (path === "/crowdsec/decisions")
		return json({ items: decisions, limit: 200, truncated: false });
	if (path === "/crowdsec/anubis")
		return json({
			configured: true,
			honeypot: {
				activeCount: 1,
				truncated: false,
				items: decisions.filter((d) => d.scenario === "anubis-honeypot"),
			},
			container: { up: true, error: null },
			recent: ["203.0.113.9", "192.0.2.55"],
		});
	if (path === "/crowdsec/alerts") {
		seen.alertsFor = { scope: url.searchParams.get("scope"), value: url.searchParams.get("value") };
		return json(alerts.filter((a) => url.searchParams.get("value") === "198.51.100.7"));
	}
	// unknown: permissive default, logged for iteration
	console.log(`  [fixture default] ${req.method()} ${req.url()} (path=${path}) resourceType=${req.resourceType()}`);
	return json([]);
};

const browser = await chromium.launch({
	executablePath: "C:/Users/Hashi/AppData/Local/ms-playwright/chromium-1217/chrome-win64/chrome.exe",
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
check("honeypot badge shows", rows[0]?.includes("anubis honeypot"), rows[0]);
check("manual ban shows its scenario", rows[3]?.includes("manual"), rows[3]);

// the anubis section below the decisions table: status, count and recent IPs
const anubisCard = page.locator(".card").filter({ hasText: "Anubis is up" }).first();
await anubisCard.waitFor({ timeout: 5000 });
const anubisCardText = await anubisCard.innerText();
check("anubis section renders with container-up badge", anubisCardText.includes("Anubis is up"), anubisCardText.slice(0, 200));
check("anubis section shows the active ban count", anubisCardText.includes("1 active honeypot ban"), anubisCardText.slice(0, 200));
check("anubis section lists recent honeypot IPs", anubisCardText.includes("203.0.113.9") && anubisCardText.includes("192.0.2.55"), anubisCardText.slice(0, 200));

// relative expiry: rows show the duration the lapi reported
check("first ban shows its 24h duration", /in 24h/.test(rows[0] ?? ""), rows[0]);
check("second ban shows its 4h duration", /in 4h/.test(rows[1] ?? ""), rows[1]);
check("last ban shows its 1h duration", /in 1h/.test(rows[3] ?? ""), rows[3]);

// search: typing filters the list live
await page.locator(".input-group input").fill("203.0");
rows = await decisionsTable.allInnerTexts();
check("search narrows to the matching row", rows.length === 1 && rows[0]?.includes("203.0.113.9"), JSON.stringify(rows));
await page.locator(".input-group input").fill("no-such-ip");
await page.waitForTimeout(200);
rows = await decisionsTable.allInnerTexts();
check("search with no match shows the empty message", rows.length === 1 && rows[0]?.includes("No bans match"), JSON.stringify(rows));
await page.locator(".input-group input").fill("");
await decisionsTable.first().waitFor();

// the origin filter narrows the list the same way
await page.locator("#crowdsec-origin-filter").selectOption("local");
await page.waitForTimeout(200);
rows = await decisionsTable.allInnerTexts();
check("origin filter local keeps the cscli manual ban", rows.length === 3 && !rows.some((r) => r.includes("capi")), JSON.stringify(rows));
await page.locator("#crowdsec-origin-filter").selectOption("community");
await page.waitForTimeout(200);
rows = await decisionsTable.count();
check("origin filter community leaves the capi ban", rows === 1, `${rows} rows`);
await page.locator("#crowdsec-origin-filter").selectOption("all");
await page.waitForTimeout(200);
await decisionsTable.first().waitFor();

// alert context: expand a row, wait for the alert fixture to render
await decisionsTable.nth(1).locator("button").first().click();
await page.waitForSelector("tbody tr td[colspan='7']");
const contextCell = page.locator("tbody tr td[colspan='7']");
await contextCell.getByText("http-probing from 198.51.100.7").waitFor({ timeout: 5000 });
const context = await contextCell.innerText();
check("context row shows the alert scenario + message", context.includes("crowdsecurity/http-probing") && context.includes("http-probing from 198.51.100.7"), context);
check("context fetched with scope+value", seen.alertsFor?.scope === "Ip" && seen.alertsFor?.value === "198.51.100.7", JSON.stringify(seen.alertsFor));
check("context shows the events count", context.includes("6 events"), context);
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
check("unbanned row is gone after refresh", banRows.length === 3 && !banRows.some((r) => r.includes("203.0.113.9")), JSON.stringify(banRows));
await page.screenshot({ path: ".smoke/ui-final.png", fullPage: true });

console.log(failures === 0 ? "ALL UI SMOKE CHECKS PASSED" : `${failures} FAILURES`);
await browser.close();
process.exit(failures === 0 ? 0 : 1);