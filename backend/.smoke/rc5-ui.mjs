// rc.5 install simulation, browser layer: drives the real UI served by a real
// NPMplus container (no route interception) through a login, the main pages,
// and the CrowdSec dashboard's not-wired degraded states.
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

const BASE_URL = process.env.SMOKE_BASE_URL || "https://127.0.0.1:8181";
const EMAIL = process.env.SMOKE_ADMIN_EMAIL || "admin@example.test";
const PASSWORD = process.env.SMOKE_ADMIN_PASSWORD || "rc5-smoke-password";

let failures = 0;
const check = (name, ok, detail = "") => {
	if (!ok) failures++;
	console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` -> ${detail}`}`);
};

const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, ignoreHTTPSErrors: true });
const browserErrors = [];
const expectedDegradedState = (text) =>
	// the login page probes the session before sign-in (401) and the crowdsec
	// routes honestly answer 503 not-wired on a bare container; both are
	// handled by design, anything else is a real failure
	/status of (401|503)/.test(text);
page.on("console", (message) => {
	if (message.type() === "error" && !expectedDegradedState(message.text())) {
		browserErrors.push(message.text());
		console.log(`  [console error] ${message.text().slice(0, 160)}`);
	}
});
page.on("pageerror", (error) => {
	browserErrors.push(String(error));
	console.log(`  [page error] ${String(error).slice(0, 160)}`);
});

// 1. login with the seeded admin; the app swaps to the authenticated shell
//    on auth state, the url itself stays /login, so wait for the site menu
await page.goto(`${BASE_URL}/login`, { waitUntil: "networkidle" });
await page.getByLabel(/email/i).first().fill(EMAIL);
await page
	.getByLabel(/password/i)
	.first()
	.fill(PASSWORD);
await page.getByRole("button", { name: /sign in|log in/i }).click();
await page.waitForFunction(() => document.querySelector('a[href="/nginx/proxy"]') !== null, { timeout: 15000 });
check("seeded admin logs into the real UI", true, page.url());

// 2. hosts page renders the real (empty) inventory
await page.goto(`${BASE_URL}/nginx/proxy`, { waitUntil: "networkidle" });
await page
	.getByRole("heading", { name: /proxy hosts/i })
	.first()
	.waitFor({ timeout: 15000 });

// 2. hosts page renders the real (empty) inventory
await page.waitForLoadState("networkidle");
check(
	"hosts page shows an empty inventory",
	(await page.getByText(/no.*hosts?|there are no hosts/i).count()) >= 1 ||
		(await page.locator("table tbody tr").count()) === 0,
	await page
		.locator("body")
		.innerText()
		.then((text) => text.slice(0, 200)),
);

// 3. certificate and stream pages render without errors
await page.goto(`${BASE_URL}/certificates`, { waitUntil: "networkidle" });
check("certificates page renders", (await page.locator("body").innerText()).length > 100);
await page.goto(`${BASE_URL}/nginx/stream`, { waitUntil: "networkidle" });
check("streams page renders", (await page.locator("body").innerText()).length > 100);

// 4. the crowdsec dashboard renders its honest not-wired states instead of crashing
await page.goto(`${BASE_URL}/crowdsec`, { waitUntil: "networkidle" });
await page
	.getByRole("heading", { name: /security overview|crowdsec/i })
	.first()
	.waitFor({ timeout: 15000 });
const crowdsecText = await page
	.locator("#crowdsec-tab-panel")
	.innerText()
	.catch(() => "");
check(
	"crowdsec dashboard renders the not-wired state",
	/unconfigured|not wired|unavailable|degraded|insights/i.test(crowdsecText),
	crowdsecText.slice(0, 300),
);
check("crowdsec dashboard exposes its five tabs", (await page.getByRole("tab").count()) === 5);
for (const tabName of ["Attack activity", "Active bans", "WAF", "System"]) {
	await page.getByRole("tab", { name: tabName }).click();
	await page.waitForTimeout(300);
}
check("every crowdsec tab opens without a page error", true);

// 5. users page renders the admin
await page.goto(`${BASE_URL}/users`, { waitUntil: "networkidle" });
check("users page lists the admin", (await page.locator("body").innerText()).includes(EMAIL));

check("real-container UI walkthrough has no browser errors", browserErrors.length === 0, browserErrors.join(" | "));
await page.screenshot({ path: ".smoke/rc5-ui-final.png", fullPage: true });
console.log(failures === 0 ? "ALL RC5 UI FEATURE CHECKS PASSED" : `${failures} FAILURES`);
await browser.close();
process.exit(failures === 0 ? 0 : 1);
