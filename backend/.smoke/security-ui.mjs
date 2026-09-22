// biome-ignore-all lint/suspicious/noMisplacedAssertion: standalone browser smoke assertions
// Fresh-install and MFA clicks against a disposable local container, no API mocks.
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { generate } from "otplib";
import { chromium } from "playwright";

const base = process.env.SMOKE_BASE_URL || "https://127.0.0.1:28182";
assert.ok(["127.0.0.1", "localhost"].includes(new URL(base).hostname));
const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined });
try {
	const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
	const page = await context.newPage();
	page.setDefaultTimeout(15000);
	const errors = [];
	page.on("pageerror", (error) => {
		errors.push(error.message);
		console.error(error.stack);
	});
	page.on("console", (message) => {
		if (message.type() === "error" && !/status of (400|401|403|503)/.test(message.text()))
			errors.push(message.text());
	});
	await page.goto(base, { waitUntil: "networkidle" });
	await page.getByLabel("Full Name", { exact: true }).fill("Security Browser Fixture");
	await page.getByLabel(/email/i).fill("browser-audit@example.test");
	await page
		.getByLabel("One-time setup token")
		.fill(process.env.SMOKE_SETUP_TOKEN || "local-security-setup-token-20260919-only");
	await page.getByLabel(/new password/i).fill("Browser-Security-Fixture-1");
	await page.getByRole("button", { name: "Save", exact: true }).click();
	await page.getByRole("link", { name: "Open user menu" }).waitFor({ timeout: 20000 });
	console.log("PASS fresh first-admin setup through the browser");
	await page.getByRole("link", { name: "Open user menu" }).click();
	await page.getByRole("link", { name: "MFA", exact: true }).click();
	await page.getByRole("button", { name: "Enable TOTP", exact: true }).click();
	const secret = await page.locator("input[readonly]").inputValue();
	const code = await generate({ secret });
	await page.locator('input[name="code"]').fill(code);
	const enrolled = page.waitForResponse((response) => response.url().endsWith("/mfa/totp/enable"));
	await page.getByRole("button", { name: "Verify and Enable", exact: true }).click();
	assert.equal((await enrolled).status(), 200);
	const backupCodes = await page.locator(".modal code").allTextContents();
	assert.equal(backupCodes.length, 8);
	await page.getByRole("button", { name: "I have saved my backup codes" }).click();
	await page.getByText("Enabled", { exact: true }).waitFor();
	await page.getByRole("button", { name: "Close", exact: true }).click();
	console.log("PASS MFA enrollment and backup-code acknowledgement");
	await page.getByRole("link", { name: "Open user menu" }).click();
	await page.getByRole("link", { name: "Logout", exact: true }).click();
	await page.getByLabel(/email/i).fill("browser-audit@example.test");
	await page
		.getByLabel(/password/i)
		.first()
		.fill("Browser-Security-Fixture-1");
	await page.getByRole("button", { name: /sign in|log in/i }).click();
	await page.locator('input[name="code"]').waitFor();
	await page.locator('input[name="code"]').fill(code);
	const replayed = page.waitForResponse((response) => response.url().endsWith("/tokens/totp"));
	await page.getByRole("button", { name: "Verify", exact: true }).click();
	assert.equal((await replayed).status(), 403);
	await page
		.getByRole("alert")
		.filter({ hasText: /invalid/i })
		.waitFor();
	await page.screenshot({ path: "backend/.smoke/security-replay-desktop.png" });
	await page.setViewportSize({ width: 390, height: 844 });
	await page.screenshot({ path: "backend/.smoke/security-replay-mobile.png" });
	assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
	console.log("PASS replay is rejected visibly on desktop and mobile");
	await delay(31000 - (Date.now() % 30000));
	await page.locator('input[name="code"]').fill(await generate({ secret }));
	await page.getByRole("button", { name: "Verify", exact: true }).click();
	await page.getByRole("link", { name: "Open user menu" }).waitFor({ timeout: 15000 });
	console.log("PASS a fresh authenticator code logs in successfully");
	await page.setViewportSize({ width: 1280, height: 900 });
	await page.goto(`${base}/nginx/proxy`, { waitUntil: "networkidle" });
	await page.getByRole("button", { name: /add proxy host/i }).click();
	await page.locator("#domainNames").getByRole("combobox").fill("browser-audit.example.test");
	await page.locator("#domainNames").getByRole("combobox").press("Enter");
	await page.getByLabel(/^Forward Hostname \/ IP/).fill("127.0.0.1");
	await page.getByLabel("Forward Port", { exact: true }).fill("81");
	const saved = page.waitForResponse(
		(response) => response.request().method() === "POST" && response.url().endsWith("/nginx/proxy-hosts"),
	);
	await page.getByRole("button", { name: "Save", exact: true }).click();
	assert.equal((await saved).status(), 201);
	await page.getByRole("dialog").waitFor({ state: "hidden" });
	await page.getByText("browser-audit.example.test", { exact: true }).waitFor();
	await page.screenshot({ path: "backend/.smoke/security-proxy-desktop.png" });
	console.log("PASS normal proxy creation through the real UI");
	await page.getByRole("button", { name: /add proxy host/i }).click();
	await page.getByRole("button", { name: "Cancel", exact: true }).click();
	await page.getByRole("dialog").waitFor({ state: "hidden" });
	console.log("PASS proxy editor cancel closes cleanly");
	assert.deepEqual(errors, []);
	console.log("PASS no unexpected browser errors");
} finally {
	await browser.close();
}
