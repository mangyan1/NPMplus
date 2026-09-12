// Browser-level CrowdSec dashboard smoke test with intercepted API fixtures.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";

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
		until: iso(3 * 86400 * 1000),
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
		until: iso(2 * 3600 * 1000),
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
		until: iso(45 * 1000),
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
		until: iso(-3600 * 1000),
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
		eventsCount: 6,
		source: {
			ip: "198.51.100.7",
			scope: "Ip",
			value: "198.51.100.7",
			country: "DE",
			asNumber: "64496",
			asName: "Example ASN",
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
					{ key: "http_user_agent", value: "sqlmap/1.8 <img src=x onerror=alert(1)>" },
					{ key: "rule_name", value: "crowdsecurity/vpatch-env-access" },
				],
			},
		],
	},
];
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
const proxyHosts = [
	{
		id: 7,
		createdOn: iso(-86400 * 1000),
		owner: user,
		domainNames: ["browser.example.test"],
		forwardScheme: "http",
		forwardHost: "browser-app",
		forwardPort: 8080,
		certificate: null,
		accessLists: [],
		npmplusAccessListType: "public",
		npmplusAuthRequest: "anubis",
		locations: [],
		enabled: true,
		meta: { nginxOnline: true, nginxErr: null },
	},
];

let defaultSite = { id: "default-site", value: "congratulations", meta: { html: "<p>Custom fixture</p>" } };
let accountFailure = false;
let sessionRejected = false;
let rejectedRefreshes = 0;
let rejectedProfiles = 0;
let failures = 0;
let appsecConfigured = true;
let metricsMissing = false;
let metricsFailure = false;
let anubisReportFailure = false;
let countsTruncated = false;
let telemetryState = "observed";
const check = (name, ok, detail = "") => {
	if (!ok) failures++;
	console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` -> ${detail}`}`);
};

const api = async (route) => {
	const request = route.request();
	const url = new URL(request.url());
	if (url.pathname.startsWith("/src/")) return route.continue();
	const apiPath = url.pathname.replace(/^\/api/, "");
	const respond = (data) =>
		route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(data) });
	if (apiPath === "/settings/default-site") {
		if (request.method() === "PUT") defaultSite = { ...defaultSite, ...request.postDataJSON() };
		return respond(defaultSite);
	}
	if (apiPath === "/crowdsec/telemetry") {
		const counters = { checks: 51, inspected: 48, errors: 2, unreadable: 1, bans: 9, wafBans: 7, challenges: 3 };
		return respond({
			windowHours: Number(url.searchParams.get("window_hours") || 24),
			start: iso(-3600_000),
			end: iso(-300_000),
			nginx: {
				status: telemetryState,
				observedAt: iso(-30_000),
				coveredMs: telemetryState === "unavailable" ? 0 : 3300_000,
				incomplete: true,
				totals: counters,
				hostsTruncated: false,
				hosts: [
					{ id: 42, domains: ["shop.example.com"], counters },
					{
						id: 43,
						domains: ["api.example.com"],
						counters: Object.fromEntries(Object.keys(counters).map((key) => [key, 0])),
					},
				],
			},
			firewall: {
				status: telemetryState,
				observedAt: iso(-30_000),
				coveredMs: telemetryState === "unavailable" ? 0 : 3300_000,
				incomplete: true,
				totals: { inputPackets: 105, forwardPackets: 205 },
				serviceActive: true,
				inputRule: true,
				forwardRule: true,
			},
		});
	}
	if (apiPath === "/crowdsec/metrics" && metricsFailure)
		return route.fulfill({
			status: 503,
			contentType: "application/json",
			body: JSON.stringify({ error: { message: "Fixture outage" } }),
		});
	if (apiPath === "/crowdsec/metrics" && metricsMissing)
		return respond({
			available: true,
			appsecConfigured: true,
			appsecMetricsPresent: false,
			appsecRequests: null,
			appsecBlocked: null,
			appsecPassed: null,
			communityActiveDecisions: null,
		});

	if (apiPath === "/" && request.method() === "GET")
		return respond({ status: "OK", setup: true, password: sessionRejected, oidc: false });
	if (apiPath === "/tokens") {
		if (sessionRejected && request.method() === "GET") {
			rejectedRefreshes++;
			return route.fulfill({ status: 401, contentType: "text/html", body: "<p>Session expired</p>" });
		}
		return respond({ expires: iso(86400 * 1000) });
	}
	if (apiPath === "/users/me" && (accountFailure || sessionRejected)) {
		if (sessionRejected) rejectedProfiles++;
		return route.fulfill({
			status: sessionRejected ? 401 : 503,
			contentType: "text/html",
			body: "<p>Account unavailable</p>",
		});
	}
	if (apiPath === "/users/me") return respond(user);
	if (apiPath === "/users") return respond([user]);
	if (apiPath === "/nginx/proxy-hosts") return respond(proxyHosts);
	if (apiPath === "/crowdsec/decisions/delete" && request.method() === "POST") {
		const id = request.postDataJSON()?.id;
		const index = decisions.findIndex((decision) => decision.id === id);
		if (index >= 0) decisions.splice(index, 1);
		return respond({ nbDeleted: "1", auditLogged: true });
	}
	if (apiPath === "/crowdsec/decisions" && request.method() === "POST") {
		const ban = request.postDataJSON();
		if (ban.value === "999.999.999.999")
			return route.fulfill({
				status: 400,
				contentType: "application/json",
				body: JSON.stringify({ error: { message: "crowdsec.invalid-ban-input", fields: ["value"] } }),
			});
		decisions.unshift({
			id: 100,
			uuid: "manual-100",
			scope: "Ip",
			value: ban.value,
			type: ban.type,
			origin: "cscli",
			scenario: "manual/web-ui",
			duration: ban.duration,
			until: iso(86400 * 1000),
			simulated: false,
		});
		return respond({ created: true, auditLogged: true });
	}
	if (apiPath === "/crowdsec/decisions") {
		const local = decisions.filter((decision) => ["crowdsec", "cscli", "cscli-import"].includes(decision.origin));
		const search = (url.searchParams.get("search") || "").toLocaleLowerCase();
		const filtered = local.filter(
			(decision) => !search || JSON.stringify(decision).toLocaleLowerCase().includes(search),
		);
		const page = Number(url.searchParams.get("page") || "1");
		const pageSize = Number(url.searchParams.get("page_size") || "25");
		const start = (page - 1) * pageSize;
		return respond({
			items: filtered.slice(start, start + pageSize),
			limit: 500,
			truncated: false,
			page,
			pageSize,
			hasNext: filtered.length > start + pageSize,
			matched: filtered.length,
		});
	}
	if (apiPath === "/crowdsec/insights")
		return respond({
			windowHours: 24,
			alertCount: 10,
			activeDecisions: 3,
			localActiveDecisions: countsTruncated ? 500 : 1,
			localActiveDecisionsTruncated: countsTruncated,
			sampled: false,
			activity: Array.from({ length: 24 }, (_, index) => ({
				start: iso((index - 23) * 3600 * 1000),
				count: index === 23 ? 4 : index >= 21 ? 3 : 0,
			})),
			locations: [
				{ latitude: 51.16, longitude: 10.45, country: "DE", count: 5 },
				{ latitude: 37.09, longitude: -95.71, country: "US", count: 3 },
				{ latitude: 1.35, longitude: 103.82, country: "SG", count: 2 },
			],
			signals: [{ id: "bans-3", severity: "info", type: "active-bans", count: 3 }],
			topScenarios: [{ name: "crowdsecurity/http-probing", count: 4 }],
			topCountries: [
				{ name: "DE", count: 5 },
				{ name: "US", count: 3 },
				{ name: "SG", count: 2 },
			],
			topAsns: [{ name: "Example Telecommunications and Hosting Provider ASN", count: 7 }],
			topIps: [{ name: "203.0.113.9", count: 4 }],
			topTargets: [{ name: "very-long-subdomain-for-responsive-testing.example.internal/.env", count: 4 }],
		});
	if (apiPath === "/crowdsec/history/alerts" && url.searchParams.has("cursor")) {
		const older = url.searchParams.get("cursor") === "older-fixture";
		return respond({
			items: older ? [{ ...alerts[0], id: 20, source: { ...alerts[0].source, ip: "2001:db8::1234" } }] : [],
			scanMode: true,
			scanned: 25,
			start: iso(-86400_000),
			end: iso(-60_000),
			pageSize: 25,
			hasNext: !older,
			nextCursor: older ? null : "older-fixture",
			matched: older ? 1 : 0,
			truncated: false,
		});
	}
	if (apiPath === "/crowdsec/history/alerts")
		return respond({
			items: alerts,
			page: 1,
			pageSize: 25,
			hasNext: false,
			matched: 1,
			windowHours: 24,
			truncated: false,
		});
	if (apiPath === "/crowdsec/metrics")
		return respond({
			available: true,
			appsecConfigured,
			appsecFailureAction: "passthrough",
			appsecDropUnreadableBody: false,
			appsecMetricsPresent: appsecConfigured,
			activeDecisions: 42103,
			localActiveDecisions: 3,
			communityActiveDecisions: 42100,
			decisionOrigins: [
				{ name: "capi", count: 42000 },
				{ name: "lists", count: 100 },
				{ name: "cscli", count: 2 },
				{ name: "crowdsec", count: 1 },
			],
			alerts: 7,
			appsecRequests: 12,
			appsecBlocked: 3,
			appsecPassed: 9,
			appsecBlockRate: 0.25,
			appsecRules: [{ name: "crowdsecurity/vpatch-env-access", count: 3 }],
			bouncerRequests: 20,
			bouncerDecisionHits: 12,
			machineRequests: 8,
			parserHits: 10,
			parserMetricScope: "nodes",
			parserSuccessRate: 0.9,
			whitelistHits: 1,
			averageLapiMs: 500,
			averageParsingMs: 2,
		});
	if (apiPath === "/crowdsec/anubis-report" && anubisReportFailure)
		return route.fulfill({
			status: 503,
			contentType: "application/json",
			body: JSON.stringify({ error: { message: "fixture outage" } }),
		});
	if (apiPath === "/crowdsec/anubis-report")
		return respond({
			metrics: {
				status: "observed",
				observedAt: iso(0),
				start: iso(-3600000),
				end: iso(0),
				partial: true,
				totals: { issued: url.searchParams.get("window") === "1" ? 0 : 14, validated: 9, failed: null },
			},
			ledger: {
				attemptsStatus: "observed",
				status: "observed",
				observedAt: iso(0),
				gap: true,
				pending: false,
				total: 2,
				page: 1,
				items: [
					{ id: "attempt", time: iso(-60000), ip: "2001:db8::1234", kind: "accepted", activeBan: true },
					{ id: "seen", time: iso(-120000), ip: "198.51.100.7", kind: "observed", activeBan: null },
				],
			},
			coverage: {
				total: 1,
				page: 1,
				items: [
					{
						id: 1,
						domains: ["browser.example.test"],
						anubis: true,
						customUpstream: false,
						locationsTruncated: false,
						locations: [{ path: "/api", anubis: false, customUpstream: false }],
					},
				],
			},
		});
	if (apiPath === "/crowdsec/anubis")
		return respond({
			configured: true,
			checkedAt: iso(0),
			log: { modifiedAt: iso(-60_000), sizeBytes: 24, truncated: false, entries: 3, uniqueIps: 2 },
			bridge: { status: "failed", checkedAt: iso(-60_000), applied: 1, failed: 1, invalid: 0, pendingBytes: 12 },
			honeypot: {
				status: "ready",
				decisionsAvailable: true,
				activeCount: 1,
				truncated: false,
				items: decisions.filter((decision) => decision.scenario === "anubis-honeypot"),
			},
			container: { up: true, error: null, httpStatus: 403 },
			recent: ["203.0.113.9"],
		});
	if (apiPath === "/crowdsec/alerts")
		return respond(alerts.filter((alert) => url.searchParams.get("value") === alert.source.ip));
	console.log(`  [fixture default] ${request.method()} ${request.url()} (path=${apiPath})`);
	return respond([]);
};

const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
const browserErrors = [];
let expectedManualBanError = false;
page.on("console", (message) => {
	if (message.type() !== "error") return;
	if (accountFailure && message.text().includes("503")) return;
	if ((metricsFailure || anubisReportFailure) && message.text().includes("503")) return;
	if (
		expectedManualBanError &&
		message.text().includes("400") &&
		message.location().url.endsWith("/api/crowdsec/decisions")
	)
		return;
	browserErrors.push(message.text());
	console.log(`  [console error] ${message.text().slice(0, 160)}`);
});
page.on("pageerror", (error) => {
	browserErrors.push(String(error));
	console.log(`  [page error] ${String(error).slice(0, 160)}`);
});
await page.route("**/api/**", (route) => api(route));
await page.addInitScript((expires) => localStorage.setItem("auth", expires), iso(86400 * 1000));
await page.goto("http://localhost:5173/crowdsec", { waitUntil: "networkidle" });

await page.getByRole("heading", { name: "Security overview" }).waitFor({ timeout: 15000 });
check("security dashboard has one sticky toolbar", (await page.locator(".sticky-top").count()) === 1);
check("dashboard exposes five focused tabs", (await page.getByRole("tab").count()) === 5);
check(
	"dashboard header reports AppSec state",
	(await page.getByText("AppSec metrics available", { exact: true }).count()) >= 1,
);
check(
	"honeypot status distinguishes log readiness from active bans",
	(await page.getByText("Honeypot logging ready", { exact: true }).count()) >= 1,
);
const dashboardButtonLabels = await page
	.locator("button")
	.evaluateAll((buttons) => buttons.map((button) => button.getAttribute("aria-label") || button.textContent?.trim()));
check(
	"browser alert control communicates its current state",
	(await page.getByRole("button", { name: /Browser alerts (off|unavailable|blocked)/ }).count()) === 1,
	JSON.stringify(dashboardButtonLabels),
);
check(
	"dashboard header uses the animated hexagon mark",
	(await page
		.getByRole("heading", { name: "Security overview" })
		.locator('img[src="/images/crowdsec-logo-animated.svg"]')
		.count()) === 1,
);

const overviewTab = page.getByRole("tab", { name: "Overview" });
await overviewTab.focus();
await overviewTab.press("ArrowRight");
check(
	"dashboard tabs support arrow-key navigation",
	(await page.getByRole("tab", { name: "Attack activity" }).getAttribute("aria-selected")) === "true",
);
await overviewTab.click();
check(
	"attack map uses geographic land shapes",
	(await page.locator('svg[aria-label*="plotted across"] path[class*="worldLand"]').count()) === 2 &&
		(await page.locator('svg[aria-label*="plotted across"] path[class*="worldLand"]').last().getAttribute("d"))
			?.length > 30_000,
);
check("attack map renders animated origin markers", (await page.locator('[class*="meteor"]').count()) >= 3);
check(
	"attack map identifies the data as observed origins",
	(await page.getByText("Observed origins", { exact: true }).count()) === 1,
);
await page.emulateMedia({ reducedMotion: "reduce" });
check(
	"attack-map motion respects reduced-motion preferences",
	(await page.locator('[class*="mapScan"]').evaluate((element) => getComputedStyle(element).animationName)) ===
		"none",
);
await page.emulateMedia({ reducedMotion: "no-preference" });

await page.getByRole("button", { name: /Community blocklist entries/i }).click();
const communityModal = page.getByRole("dialog");
const communityText = await communityModal.innerText();
check(
	"community KPI opens aggregate details",
	communityText.includes("42,100") || communityText.includes("42100"),
	communityText,
);
check(
	"community modal describes configured enforcement without claiming current proof",
	/configured remediation components/i.test(communityText),
	communityText,
);
check(
	"community modal has no CAPI IPs or unban action",
	!communityText.includes("192.0.2.55") &&
		(await page.getByRole("dialog").getByRole("button", { name: /Unban/i }).count()) === 0,
	communityText,
);
await communityModal.getByRole("button", { name: /close/i }).first().click();

await page.getByRole("tab", { name: "Active bans" }).click();
const localTable = page.locator("#crowdsec-active-bans tbody");
await localTable.locator("tr").first().waitFor();
const localText = await localTable.innerText();
check("manual action is named clearly", (await page.getByRole("button", { name: "Add IP ban" }).count()) === 1);
check(
	"simulated decisions are visibly marked",
	(await localTable.getByText("simulated", { exact: true }).count()) === 1,
	localText,
);
check("ban expiry shows the real timestamp, not the raw lapi duration", !/in \d+[hms]/.test(localText), localText);
check(
	"active bans lists only this instance",
	localText.includes("203.0.113.9") && localText.includes("198.51.100.7"),
	localText,
);
check(
	"CAPI decision is hidden from the local table",
	!localText.includes("192.0.2.55") && !localText.includes("capi"),
	localText,
);
check(
	"unban actions exist only for local rows",
	(await localTable.getByRole("button", { name: /Unban/i }).count()) === 3,
);

const banSearch = page.getByRole("searchbox", { name: "Search bans" });
await banSearch.fill("198.51.100.7");
await page.getByText("1 match", { exact: true }).waitFor();
check(
	"ban search reports the match count",
	(await page.getByText("1 match", { exact: true }).count()) === 1 && (await localTable.locator("tr").count()) === 1,
	await localTable.innerText(),
);
await banSearch.fill("");

await page.getByRole("tab", { name: "Overview" }).click();
await page.getByRole("button", { name: /Honeypot decisions/i }).click();
const anubisModal = page.getByRole("dialog");
const anubisText = await anubisModal.innerText();
check(
	"Anubis KPI opens health and catch details",
	anubisText.includes("Anubis is up") && anubisText.includes("203.0.113.9"),
	anubisText,
);
check(
	"honeypot details report bridge failures independently of reachability",
	anubisText.includes("HTTP 403") &&
		anubisText.includes("1 ban commands accepted, 1 failed; 12 bytes pending") &&
		(await anubisModal.locator(".alert-warning").filter({ hasText: "Last run:" }).count()) === 1,
	anubisText,
);
check(
	"honeypot log counts explain retained scope and missing event timestamps",
	anubisText.includes("3 entries / 2 distinct IPs") &&
		anubisText.includes("Retained address entries have no event timestamps"),
	anubisText,
);
await anubisModal.getByRole("heading", { name: "Anubis outcomes" }).waitFor();
check(
	"Anubis counters show absent validation metrics as unknown",
	(await anubisModal.innerText()).includes("Failed validations") &&
		(await anubisModal.getByText("\u2014", { exact: true }).count()) >= 1,
);
await anubisModal.getByLabel("Anubis reporting window").selectOption("1");
await anubisModal.getByText("0", { exact: true }).waitFor();
check(
	"Anubis window changes retrieve scoped metrics",
	(await anubisModal.getByText("0", { exact: true }).count()) === 1,
);
await anubisModal.locator("summary").filter({ hasText: "Host configuration" }).click();
check(
	"Anubis coverage shows custom-location exceptions",
	(await anubisModal.innerText()).includes("/api: Anubis not selected"),
);
await anubisModal.locator("summary").filter({ hasText: "Honeypot observation" }).click();
await anubisModal.getByText("Detection evidence", { exact: true }).first().click();
await anubisModal
	.getByText("No alert context kept for this ban (alerts are pruned after their retention)", { exact: true })
	.waitFor();
check(
	"honeypot evidence explains unavailable request fingerprints",
	(await anubisModal.innerText()).includes("no request path, User-Agent"),
);
await anubisModal.getByText("Detection evidence", { exact: true }).first().click();
await anubisModal.getByText("Detection evidence", { exact: true }).nth(1).click();
await anubisModal.getByRole("region", { name: "Alert 99", exact: true }).waitFor();
check(
	"honeypot evidence loads same-IP alerts without claiming the same request",
	(await anubisModal.innerText()).includes("They may describe separate activity"),
);
await anubisModal.getByText("Detection evidence", { exact: true }).nth(1).click();

check(
	"Anubis history separates observation time and accepted IPv6 bans",
	(await anubisModal.innerText()).includes("2001:db8::1234") &&
		(await anubisModal.innerText()).includes("Ban command accepted") &&
		(await anubisModal.innerText()).includes("Unknown"),
);
await anubisModal.locator("summary").filter({ hasText: "Host configuration" }).click();
await anubisModal.locator("summary").filter({ hasText: "Honeypot observation" }).click();
await page.waitForFunction(() => getComputedStyle(document.querySelector('[role="dialog"]')).opacity === "1");
await page.screenshot({ path: ".smoke/ui-security-anubis.png", animations: "disabled" });
await page.setViewportSize({ width: 320, height: 900 });
check("honeypot details fit a 320px viewport", await anubisModal.evaluate((el) => el.scrollWidth <= el.clientWidth));
await page.screenshot({ path: ".smoke/ui-security-anubis-mobile.png", animations: "disabled" });
await anubisModal.locator("summary").filter({ hasText: "Honeypot observation" }).click();
await anubisModal.getByText("2001:db8::1234", { exact: true }).first().scrollIntoViewIfNeeded();
check(
	"Anubis IPv6 history stays within the mobile modal",
	await anubisModal.evaluate((el) => el.scrollWidth <= el.clientWidth),
);
await page.screenshot({ path: ".smoke/ui-security-anubis-history-mobile.png", animations: "disabled" });
await page.setViewportSize({ width: 1280, height: 900 });
anubisReportFailure = true;
await anubisModal.getByLabel("Anubis reporting window").selectOption("6");
await anubisModal.getByRole("button", { name: "Retry reporting" }).waitFor();
check(
	"Anubis initial reporting failure offers retry",
	(await anubisModal.innerText()).includes("Reporting unavailable"),
);
anubisReportFailure = false;
await anubisModal.getByRole("button", { name: "Retry reporting" }).click();
await anubisModal.getByRole("heading", { name: "Anubis outcomes" }).waitFor();
check(
	"Anubis reporting recovers after retry",
	(await anubisModal.getByLabel("Anubis reporting window").inputValue()) === "6",
);
anubisReportFailure = true;
await anubisModal.getByLabel("Anubis reporting window").selectOption("24");
await anubisModal.getByText("Refresh failed. Displayed reporting is stale.", { exact: true }).waitFor();
check(
	"Anubis failed refresh identifies cached data as stale",
	(await anubisModal.getByText("14", { exact: true }).count()) === 1,
);
anubisReportFailure = false;
await anubisModal.getByRole("button", { name: /close/i }).first().click();

await page.getByRole("tab", { name: "WAF" }).click();
await page.getByLabel("Proxy host", { exact: true }).waitFor();
const telemetryWaf = page.locator('section[aria-labelledby="telemetry-waf"]');
check("windowed WAF reports partial coverage explicitly", (await telemetryWaf.innerText()).includes("Partial history"));
await page.getByLabel("Proxy host", { exact: true }).selectOption("43");
check(
	"per-host WAF selection uses that host's counters",
	(await telemetryWaf.getByText("0", { exact: true }).count()) >= 2,
);
await page.getByLabel("Proxy host", { exact: true }).selectOption("42");
check(
	"per-host WAF can switch back to observed traffic",
	(await telemetryWaf.getByText("48", { exact: true }).count()) === 1,
);
await page.getByLabel("Proxy host", { exact: true }).selectOption("");
const wafText = await page.locator("#crowdsec-tab-panel").innerText();
check(
	"WAF rules explain attack type and aggregate limits",
	wafText.includes("sensitive configuration file") && wafText.includes("not individual attacker records"),
);
check(
	"WAF tab shows protection state and traffic outcomes",
	/web application firewall/i.test(wafText) &&
		/inspected requests/i.test(wafText) &&
		wafText.includes("25.0%") &&
		/false positives and compatibility/i.test(wafText),
	wafText.slice(0, 500),
);
check(
	"WAF traffic visualization has an accessible summary",
	(await page.getByRole("img", { name: /AppSec inspected 12 requests/i }).count()) === 1,
);
await page.screenshot({ path: ".smoke/ui-security-dashboard-waf.png", fullPage: true });

appsecConfigured = false;
await page.reload({ waitUntil: "networkidle" });
await page.getByRole("tab", { name: "WAF" }).click();
const disabledWafText = await page.locator("#crowdsec-tab-panel").innerText();
check(
	"WAF tab distinguishes globally disabled AppSec",
	/appsec disabled/i.test(disabledWafText) && disabledWafText.includes("--update --enable-appsec"),
	disabledWafText.slice(0, 300),
);
appsecConfigured = true;
await page.reload({ waitUntil: "networkidle" });

await page.getByRole("tab", { name: "System" }).click();
await page.getByText("Service active; INPUT and FORWARD drop rules present", { exact: true }).waitFor();
const systemText = await page.locator("body").innerText();
check(
	"enforcement separates HTTP requests from IPv4 packets",
	/HTTP ban actions/i.test(systemText) &&
		/IPv4 forwarded packets dropped/i.test(systemText) &&
		systemText.includes("Service active; INPUT and FORWARD drop rules present"),
);
check(
	"technical metrics moved to the System tab",
	/parser node evaluation success/i.test(systemText) && systemText.includes("500.0 ms"),
	systemText.slice(0, 300),
);
check(
	"whitelisted events are surfaced on the System tab",
	/whitelist node matches/i.test(systemText),
	systemText.slice(0, 300),
);
check(
	"system metrics are informational cards rather than misleading buttons",
	(await page.getByRole("button", { name: /Parser success/i }).count()) === 0,
);

await page.getByRole("tab", { name: "Attack activity" }).click();
await page.locator("#crowdsec-alert-history tbody tr").first().waitFor();
const attackRows = await page.locator("#crowdsec-alert-history tbody tr").count();
check("attack history lives inside the dashboard", attackRows === 1, `${attackRows} rows`);

const historyPanel = page.locator("#crowdsec-alert-history");
await historyPanel.locator('button[aria-expanded="false"]').first().click();
const attackEvidence = historyPanel.getByRole("region", { name: "Alert 99", exact: true });
await attackEvidence.waitFor();
check(
	"attack details identify recorded rule, type, and spoofable tool claim",
	(await attackEvidence.innerText()).includes("sqlmap") &&
		(await attackEvidence.innerText()).includes("can be spoofed") &&
		(await attackEvidence.innerText()).includes("sensitive configuration file"),
);
check(
	"attack details render hostile User-Agent as text",
	(await attackEvidence.locator("img").count()) === 0 && (await attackEvidence.innerText()).includes("<img src=x"),
);
check(
	"attack details show sampling and avoid claiming enforcement",
	(await attackEvidence.innerText()).includes("1 retained event") &&
		(await attackEvidence.innerText()).includes("does not prove"),
);
await page.screenshot({ path: ".smoke/ui-attack-evidence.png", fullPage: true, animations: "disabled" });
const evidenceViewport = page.viewportSize();
await page.setViewportSize({ width: 320, height: 900 });
check(
	"attack evidence fits phone width",
	await attackEvidence.evaluate((el) => el.getBoundingClientRect().width <= 320),
);
await attackEvidence.screenshot({ path: ".smoke/ui-attack-evidence-mobile.png", animations: "disabled" });
await page.setViewportSize(evidenceViewport);
await historyPanel.locator('button[aria-expanded="true"]').first().click();

await page.getByRole("button", { name: "Explore older alerts", exact: true }).click();
await historyPanel.getByText("0 matches in this batch", { exact: true }).waitFor();
check(
	"empty exploration batches keep older results reachable",
	await historyPanel.getByRole("button", { name: "Next", exact: true }).isEnabled(),
);
await historyPanel.getByRole("button", { name: "Next", exact: true }).click();
await historyPanel.getByText("2001:db8::1234", { exact: true }).waitFor();
check("extended history renders IPv6 offenders", (await historyPanel.innerText()).includes("1 match in this batch"));
await page.screenshot({ path: ".smoke/ui-security-history.png", fullPage: true });
await page.setViewportSize({ width: 320, height: 844 });
check(
	"history exploration controls and IPv6 values fit 320px",
	await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
);
await page.screenshot({ path: ".smoke/ui-security-history-mobile.png", fullPage: true });
await historyPanel.getByRole("button", { name: "Previous", exact: true }).click();
await historyPanel.getByText("0 matches in this batch", { exact: true }).waitFor();
check(
	"history exploration can return to its previous batch",
	await historyPanel.getByRole("button", { name: "Next", exact: true }).isEnabled(),
);
await page.getByRole("button", { name: "Return to recent history", exact: true }).click();
await historyPanel.getByText("198.51.100.7", { exact: true }).waitFor();
await page.setViewportSize({ width: 1280, height: 900 });

await page.getByRole("tab", { name: "Overview" }).click();
await page.screenshot({ path: ".smoke/ui-security-dashboard.png", fullPage: true });
await page.setViewportSize({ width: 390, height: 844 });
check(
	"security dashboard fits a narrow viewport",
	await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
);
const narrowTabLayout = await page.getByRole("tab").evaluateAll((tabs) => {
	const boxes = tabs.map((tab) => tab.getBoundingClientRect());
	return {
		rows: new Set(boxes.map((box) => Math.round(box.top))).size,
		allVisible: boxes.every((box) => box.left >= 0 && box.right <= window.innerWidth && box.height >= 44),
	};
});
check(
	"all five tabs form three unclipped rows on mobile",
	narrowTabLayout.rows === 3 && narrowTabLayout.allVisible,
	JSON.stringify(narrowTabLayout),
);
await page.getByRole("tab", { name: "WAF" }).click();
check(
	"WAF monitoring fits a narrow viewport",
	await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
);
await page.screenshot({ path: ".smoke/ui-security-dashboard-waf-mobile.png", fullPage: true });
await page.getByRole("tab", { name: "Overview" }).click();
await page.screenshot({ path: ".smoke/ui-security-dashboard-mobile.png", fullPage: true });
await page.setViewportSize({ width: 320, height: 720 });
check(
	"security dashboard and tabs fit a 320px viewport",
	await page.evaluate(() => {
		const tabs = [...document.querySelectorAll('[role="tab"]')].map((tab) => tab.getBoundingClientRect());
		return (
			document.documentElement.scrollWidth <= document.documentElement.clientWidth &&
			tabs.every((box) => box.left >= 0 && box.right <= window.innerWidth && box.height >= 44)
		);
	}),
);
await page.getByRole("tab", { name: "Active bans" }).click();
check(
	"the manual-ban control does not clip at 320px",
	await page
		.getByRole("button", { name: "Add IP ban" })
		.evaluate((button) => button.scrollWidth <= button.clientWidth),
);
await page.locator("#crowdsec-active-bans .btn-loading").waitFor({ state: "hidden" });
await page.screenshot({ path: ".smoke/ui-security-dashboard-320.png", fullPage: true, animations: "disabled" });

check(
	"mobile decisions expose targets, expiry and unban without horizontal scrolling",
	await localTable.evaluate((table) => {
		const rows = [...table.querySelectorAll("tr")];
		return rows.every((row) =>
			[...row.querySelectorAll("td")].every((cell) => {
				const rect = cell.getBoundingClientRect();
				return rect.left >= 0 && rect.right <= window.innerWidth && cell.scrollWidth <= cell.clientWidth;
			}),
		);
	}),
);
check(
	"phone toolbar scrolls away so decisions retain reading space",
	await page.locator(".sticky-top").evaluate((toolbar) => getComputedStyle(toolbar).position === "static"),
);
const bansRefresh = page.locator("#crowdsec-active-bans").getByRole("button", { name: "Refresh", exact: true });
check(
	"outline refresh and pagination use contrasting Tabler variants",
	await bansRefresh.evaluate(
		(button) => button.classList.contains("btn-outline-secondary") && !button.classList.contains("btn-secondary"),
	),
);
await page.setViewportSize({ width: 1280, height: 900 });
await page.getByRole("button", { name: "Enable dark mode", exact: true }).click();
await page.setViewportSize({ width: 320, height: 720 });
await page.waitForTimeout(250);
await page.screenshot({ path: ".smoke/ui-security-bans-dark-320.png", fullPage: true, animations: "disabled" });
await page.setViewportSize({ width: 1280, height: 900 });
await page.screenshot({ path: ".smoke/ui-security-bans-dark.png", fullPage: true, animations: "disabled" });
await page.getByRole("button", { name: "Enable light mode", exact: true }).click();

await page.getByRole("button", { name: "Add IP ban", exact: true }).click();
const manualDialog = page.getByRole("dialog");
await manualDialog.locator("#manual-ban-target").fill("999.999.999.999");
expectedManualBanError = true;
await manualDialog.getByRole("button", { name: "Add IP ban", exact: true }).click();
await manualDialog.locator('[aria-invalid="true"]').waitFor();
check(
	"invalid ban stays open with target-specific validation",
	(await manualDialog.locator("#manual-ban-target").getAttribute("aria-invalid")) === "true",
);
await manualDialog.getByRole("button", { name: "Cancel", exact: true }).click();
expectedManualBanError = false;

await page.setViewportSize({ width: 1280, height: 900 });
metricsMissing = true;
countsTruncated = true;
await page.reload({ waitUntil: "networkidle" });
check(
	"capped local counts are visibly lower bounds",
	(await page.getByRole("button", { name: /Local active decisions/i }).innerText()).includes("500+"),
);
await page.getByRole("tab", { name: "WAF" }).click();
check(
	"missing AppSec counters do not render a fabricated zero-traffic chart",
	(await page.getByRole("img", { name: /AppSec inspected 0 requests/i }).count()) === 0 &&
		(await page.locator("#crowdsec-tab-panel").innerText()).includes("—"),
);
await page.screenshot({ path: ".smoke/ui-security-dashboard-missing-metrics.png", fullPage: true });
metricsMissing = false;
countsTruncated = false;
await page.reload({ waitUntil: "networkidle" });
metricsFailure = true;
await page.getByRole("button", { name: "Refresh", exact: true }).click();
await page.getByText("Displayed data stale", { exact: true }).first().waitFor({ timeout: 20000 });
check(
	"a failed metrics refresh marks cached WAF data stale",
	(await page.getByText("AppSec metrics available", { exact: true }).count()) === 0,
);
await page.reload({ waitUntil: "networkidle" });
await page.getByText("AppSec metrics unavailable", { exact: true }).first().waitFor({ timeout: 20000 });
await page.getByRole("tab", { name: "WAF" }).click();
check(
	"an initial metrics outage renders an error instead of an endless skeleton",
	/CrowdSec metrics are unavailable/.test(await page.locator("#crowdsec-tab-panel").innerText()),
);
metricsFailure = false;
await page.reload({ waitUntil: "networkidle" });
check(
	"WAF state recovers when metrics return",
	(await page.getByText("AppSec metrics available", { exact: true }).count()) >= 1,
);
telemetryState = "stale";
await page.getByRole("tab", { name: "System" }).click();
await page.getByRole("button", { name: "Refresh", exact: true }).click();
const enforcement = page.locator('section[aria-labelledby="telemetry-enforcement"]');
await enforcement.getByText("Not currently verified", { exact: true }).waitFor();
check(
	"stale firewall observations cannot claim current rule verification",
	(await enforcement.innerText()).includes("Observation stale"),
);
telemetryState = "unavailable";
await page.getByRole("button", { name: "Refresh", exact: true }).click();
await enforcement
	.getByText("Telemetry unavailable. Update the image and installer to enable collection.", { exact: true })
	.first()
	.waitFor();
check(
	"missing telemetry history renders unknown counts instead of zeros",
	(await enforcement.getByText("—", { exact: true }).count()) === 4,
);
telemetryState = "observed";
await page.goto("http://localhost:5173/nginx/proxy", { waitUntil: "networkidle" });
await page.getByRole("heading", { name: "Proxy Hosts", exact: true }).waitFor();
check("proxy-host list shows when Anubis is enabled", (await page.getByText("Anubis enabled").count()) === 1);
await page.getByRole("button", { name: "Add Proxy Host" }).click();
const proxyModal = page.getByRole("dialog");
const appsecToggle = proxyModal.getByRole("checkbox", { name: /CrowdSec AppSec protection/i });
check("new proxy hosts enable their AppSec preference by default", await appsecToggle.isChecked());
const authRequest = proxyModal.getByLabel(/Authentication \/ Bot Protection/i);
check("new proxy hosts leave Anubis off by default", (await authRequest.inputValue()) === "none");
await authRequest.selectOption("anubis");
check("Anubis can be selected per proxy host", (await authRequest.inputValue()) === "anubis");
check(
	"Anubis guidance distinguishes browser sites from APIs",
	(await proxyModal.getByText(/Leave it off for APIs, webhooks, and licensing services/).count()) === 1,
);
await page.screenshot({ path: ".smoke/ui-proxy-host-protection.png", fullPage: true });
await page.setViewportSize({ width: 390, height: 844 });
await authRequest.scrollIntoViewIfNeeded();
check(
	"proxy-host protection control fits a narrow viewport",
	await proxyModal.evaluate((dialog) => {
		const box = dialog.getBoundingClientRect();
		return box.left >= 0 && box.right <= window.innerWidth && dialog.scrollWidth <= dialog.clientWidth;
	}),
);
await page.screenshot({ path: ".smoke/ui-proxy-host-protection-mobile.png", fullPage: true });
await appsecToggle.uncheck();
check("proxy-host AppSec protection can be turned off", !(await appsecToggle.isChecked()));
await proxyModal.getByRole("button", { name: /close/i }).click();
await page.goto("http://127.0.0.1:5173/settings");
const forbiddenOption = page.getByRole("radio", { name: "Animated forbidden page (403)", exact: true });
await forbiddenOption.locator("..").click();
await Promise.all([
	page.waitForResponse(
		(response) => response.url().includes("/settings/default-site") && response.request().method() === "PUT",
	),
	page.getByRole("button", { name: "Save", exact: true }).click(),
]);
check("forbidden selection saves its built-in value", defaultSite.value === "forbidden");
await page.reload();
await forbiddenOption.waitFor();
check("forbidden selection survives reload", await forbiddenOption.isChecked());
check("built-in page needs no HTML editor", (await page.locator("textarea#html").count()) === 0);
await page.getByRole("radio", { name: "Custom HTML", exact: true }).locator("..").click();
check("custom HTML is preserved", (await page.locator("textarea#html").inputValue()) === "<p>Custom fixture</p>");
await forbiddenOption.locator("..").click();
for (const width of [1440, 390, 320]) {
	await page.setViewportSize({ width, height: 900 });
	check(
		`default-site choices fit ${width}px`,
		await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
	);
	await page.screenshot({ path: `.smoke/ui-default-site-${width}.png`, fullPage: true });
}
accountFailure = true;
await page.reload();
await page.getByRole("heading", { name: "Unable to load your account" }).waitFor();
check(
	"failed account fetch shows recovery instead of a partial menu",
	(await page.locator("#navbar-menu").count()) === 0,
);
check("account recovery reports HTTP status", await page.getByText("HTTP 503", { exact: true }).isVisible());
await page.screenshot({ path: ".smoke/ui-account-recovery-320.png", fullPage: true });
accountFailure = false;
await page.getByRole("button", { name: "Retry", exact: true }).click();
await page.locator('#navbar-menu a[href="/settings"]').waitFor({ state: "attached" });
check("retry restores admin navigation", (await page.locator('#navbar-menu a[href="/crowdsec"]').count()) === 1);
const expiredPage = await browser.newPage();
await expiredPage.addInitScript(
	(expires) => {
		if (!sessionStorage.getItem("expired-profile-fixture")) {
			sessionStorage.setItem("expired-profile-fixture", "true");
			localStorage.setItem("auth", expires);
		}
	},
	iso(86400 * 1000),
);
await expiredPage.route("**/api/**", (route) => api(route));
sessionRejected = true;
await expiredPage.goto("http://127.0.0.1:5173/settings");
await expiredPage.locator('input[name="password"]').waitFor();
check(
	"HTML 401 clears the expired session and shows login",
	(await expiredPage.evaluate(() => localStorage.getItem("auth"))) === null,
);
await expiredPage.waitForTimeout(1000);
check("rejected session recovery does not loop", rejectedRefreshes <= 2);
await expiredPage.close();
sessionRejected = false;
check("changed dashboard and host flows have no browser errors", browserErrors.length === 0, browserErrors.join(" | "));
console.log(failures === 0 ? "ALL UI SMOKE CHECKS PASSED" : `${failures} FAILURES`);
await browser.close();
process.exit(failures === 0 ? 0 : 1);
