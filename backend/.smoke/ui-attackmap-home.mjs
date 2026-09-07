// Focused browser smoke for the attack map's home marker: does a meteor
// actually fly from an attacker origin to the green instance dot, and does the
// dot pulse? API is fully intercepted, only vite needs to run.
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

let failures = 0;
let homeKnown = true;
const check = (name, ok, detail = "") => {
	if (!ok) failures++;
	console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` -> ${detail}`}`);
};

// home in Sydney, origins in Germany/US/Singapore: long, distinct flights
const insights = {
	windowHours: 24,
	alertCount: 7,
	activeDecisions: 3,
	localActiveDecisions: 3,
	sampled: false,
	activity: Array.from({ length: 24 }, (_, index) => ({
		start: iso((index - 23) * 3600 * 1000),
		count: index % 5,
	})),
	locations: [
		{ latitude: 51.16, longitude: 10.45, country: "DE", count: 5 },
		{ latitude: 37.09, longitude: -95.71, country: "US", count: 3 },
		{ latitude: 1.35, longitude: 103.82, country: "SG", count: 2 },
	],
	home: { latitude: -33.87, longitude: 151.21 },
	signals: [],
	topScenarios: [{ name: "crowdsecurity/http-probing", count: 4 }],
	topCountries: [{ name: "DE", count: 5 }],
	topAsns: [{ name: "Example ASN", count: 7 }],
	topIps: [{ name: "203.0.113.9", count: 4 }],
	topTargets: [{ name: "example.test/.env", count: 4 }],
};

const api = async (route) => {
	const request = route.request();
	const url = new URL(request.url());
	if (url.pathname.startsWith("/src/")) return route.continue();
	const apiPath = url.pathname.replace(/^\/api/, "");
	const respond = (data) =>
		route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(data) });

	if (apiPath === "/" && request.method() === "GET")
		return respond({ status: "OK", setup: true, password: false, oidc: false });
	if (apiPath === "/tokens") return respond({ expires: iso(86400 * 1000) });
	if (apiPath === "/users/me") return respond(user);
	if (apiPath === "/nginx/proxy-hosts") return respond([]);
	if (apiPath === "/crowdsec/decisions")
		return respond({
			items: [
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
			],
			limit: 500,
			truncated: false,
			page: 1,
			pageSize: 25,
			hasNext: false,
			matched: 1,
		});
	if (apiPath === "/crowdsec/anubis")
		return respond({
			configured: true,
			honeypot: { status: "ready", decisionsAvailable: true, activeCount: 0, truncated: false, items: [] },
			container: { up: true, error: null },
			recent: [],
		});
	if (apiPath === "/crowdsec/insights")
		return respond({ ...insights, home: homeKnown ? insights.home : null });
	if (apiPath === "/crowdsec/metrics")
		return respond({
			available: true,
			appsecConfigured: true,
			appsecMetricsPresent: true,
			appsecRequests: 12,
			appsecBlocked: 3,
			appsecPassed: 9,
			appsecBlockRate: 0.25,
			bouncerRequests: 20,
			bouncerDecisionHits: 12,
			bouncerPulls: 20,
			machineRequests: 8,
			parserHits: 10,
			parserSuccessRate: 0.9,
			activeDecisions: 3,
			localActiveDecisions: 3,
			communityActiveDecisions: 0,
			whitelistHits: 1,
			averageLapiMs: 500,
			averageParsingMs: 2,
		});
	console.log(`  [fixture default] ${request.method()} ${request.url()} (path=${apiPath})`);
	return respond([]);
};

const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
const browserErrors = [];
page.on("console", (message) => {
	if (message.type() === "error") browserErrors.push(message.text());
});
page.on("pageerror", (error) => browserErrors.push(String(error)));
await page.route("**/api/**", (route) => api(route));
await page.addInitScript((expires) => localStorage.setItem("auth", expires), iso(86400 * 1000));
await page.goto("http://localhost:5173/crowdsec", { waitUntil: "networkidle" });

await page.getByRole("heading", { name: "Security overview" }).waitFor({ timeout: 15000 });

check(
	"green instance dot renders when the insights response carries home",
	(await page.locator('[class*="homeDot"]').count()) === 1,
);

// follow the first meteor (delay 0) through one full animation and record the
// closest its head ever gets to the home dot plus how far it travels; a flying
// meteor must land on the dot, and travel even when the home location is unknown
const observeMeteor = () =>
	page.evaluate(async () => {
		const svg = document.querySelector('svg[class*="worldMap"]');
		const meteor = svg.querySelector('g[class*="meteor"]');
		const home = svg.querySelector('[class*="homeDot"]')?.parentElement;
		const gap = (a, b) => {
			const ar = a.getBoundingClientRect();
			const hr = b.getBoundingClientRect();
			return Math.hypot(
				(ar.left + ar.right) / 2 - (hr.left + hr.right) / 2,
				(ar.top + ar.bottom) / 2 - (hr.top + hr.bottom) / 2,
			);
		};
		const center = meteor.getBoundingClientRect();
		const startGap = home ? gap(meteor, home) : null;
		const started = performance.now();
		let closest = startGap;
		let travel = 0;
		let sawFlight = false;
		while (performance.now() - started < 15000) {
			await new Promise((resolve) => requestAnimationFrame(resolve));
			const opacity = Number(getComputedStyle(meteor).opacity);
			if (opacity > 0.1) sawFlight = true;
			const box = meteor.getBoundingClientRect();
			travel = Math.max(travel, Math.hypot(box.left - center.left, box.top - center.top));
			if (home) closest = Math.min(closest, gap(meteor, home));
		}
		return { startGap, closest, travel, sawFlight };
	});

const flight = await observeMeteor();
check("meteor becomes visible during its animation", flight.sawFlight);
check("meteor visibly travels across the map", flight.sawFlight && flight.travel > 30, `travel=${flight.travel.toFixed(1)}`);
check(
	"meteor head lands on the instance dot",
	flight.sawFlight && flight.closest < 25,
	`startGap=${flight.startGap?.toFixed(1)} closest=${flight.closest?.toFixed(1)}`,
);

const homeAnimation = await page.evaluate(
	() => getComputedStyle(document.querySelector('[class*="homePulse"]')).animationName,
);
check("instance dot pulses", homeAnimation !== "none", homeAnimation);

// unknown home must degrade to a center-ward flight, not a fade-in-place
homeKnown = false;
await page.reload({ waitUntil: "networkidle" });
await page.getByRole("heading", { name: "Security overview" }).waitFor({ timeout: 15000 });
check(
	"instance dot is absent without a known home location",
	(await page.locator('[class*="homeDot"]').count()) === 0,
);
const degraded = await observeMeteor();
check(
	"meteor still flies when the home location is unknown",
	degraded.sawFlight && degraded.travel > 30,
	`travel=${degraded.travel.toFixed(1)}`,
);
check("instance dot never pulses when it does not exist", (await page.locator('[class*="homePulse"]').count()) === 0);

check("no browser errors", browserErrors.length === 0, browserErrors.join(" | "));
console.log(failures === 0 ? "ALL ATTACK-MAP HOME CHECKS PASSED" : `${failures} FAILURES`);
await browser.close();
process.exit(failures === 0 ? 0 : 1);