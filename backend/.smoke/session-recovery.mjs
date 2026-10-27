// biome-ignore-all lint/suspicious/noMisplacedAssertion: standalone browser regression assertions
import assert from "node:assert/strict";
import { chromium } from "playwright";

const base = process.env.SMOKE_BASE_URL || "http://127.0.0.1:5173";
assert.ok(["127.0.0.1", "localhost"].includes(new URL(base).hostname));
const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined });
try {
	for (const scenario of ["rejected-cookie", "missing-cookie", "permission-denied", "outage"]) {
		const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
		try {
			const page = await context.newPage();
			page.setDefaultTimeout(15000);
			const errors = [];
			page.on("pageerror", (error) => errors.push(error.message));
			page.on("console", (message) => {
				if (message.type() === "error" && !/status of (401|403|503)/.test(message.text()))
					errors.push(message.text());
			});
			let restored = false;
			let deletes = 0;
			let refreshes = 0;
			let navigations = 0;
			page.on("framenavigated", (frame) => {
				if (frame === page.mainFrame()) navigations++;
			});
			await page.addInitScript(() => {
				// Seed only the original visit: a reload must not restore stale auth.
				if (!sessionStorage.getItem("session-fixture")) {
					sessionStorage.setItem("session-fixture", "true");
					localStorage.setItem("auth", new Date(Date.now() + 86400000).toISOString());
				}
			});
			await page.route("**/api/**", (route) => {
				const path = new URL(route.request().url()).pathname;
				if (path.startsWith("/src/")) return route.continue();
				const method = route.request().method();
				const respond = (status, data) =>
					route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });
				if (path === "/api/") return respond(200, { status: "OK", setup: true, password: true, oidc: false });
				if (path === "/api/tokens") {
					if (method === "DELETE") {
						deletes++;
						return respond(200, true);
					}
					refreshes++;
					if (!restored && scenario === "outage")
						return respond(503, { error: { message: "Fixture outage" } });
					if (["rejected-cookie", "missing-cookie"].includes(scenario))
						return respond(401, { error: { message: "Invalid or expired token" } });
					return respond(200, { expires: new Date(Date.now() + 86400000).toISOString() });
				}
				if (path === "/api/users/me") {
					if (!restored) {
						const status = { "rejected-cookie": 401, outage: 503 }[scenario] || 403;
						return respond(status, { error: { message: "Fixture account unavailable" } });
					}
					return respond(200, {
						id: 1,
						name: "Session fixture",
						email: "admin@example.test",
						roles: ["admin"],
						permissions: { visibility: "all" },
					});
				}
				return respond(200, []);
			});
			await page.goto(`${base}/users`);
			if (["rejected-cookie", "missing-cookie"].includes(scenario)) {
				// Recover immediately, not after the five-minute refresh interval.
				await page.getByLabel(/password/i).waitFor({ timeout: 5000 });
				assert.equal(await page.evaluate(() => localStorage.getItem("auth")), null);
				await page.waitForTimeout(1000);
				assert.ok(refreshes <= 3, `session checks looped: ${refreshes}`);
				assert.ok(navigations <= 3, `page reloads looped: ${navigations}`);
				console.log(`PASS ${scenario} returns to login immediately without a reload loop`);
			} else {
				await page.getByRole("heading", { name: "Unable to load your account" }).waitFor();
				await page.getByText(`HTTP ${scenario === "outage" ? 503 : 403}`, { exact: true }).waitFor();
				assert.ok(await page.evaluate(() => localStorage.getItem("auth")));
				assert.equal(deletes, 0);
				assert.equal(navigations, 1);
				if (scenario === "outage") {
					await page.setViewportSize({ width: 390, height: 844 });
					assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
					await page.screenshot({ path: "backend/.smoke/ui-session-outage-mobile.png", fullPage: true });
				}
				restored = true;
				await page.getByRole("button", { name: "Retry", exact: true }).click();
				await page.getByRole("link", { name: "Open user menu" }).waitFor();
				console.log(`PASS ${scenario} preserves the session and Retry restores account access`);
			}
			assert.deepEqual(errors, []);
		} finally {
			await context.close();
		}
	}
} finally {
	await browser.close();
}
