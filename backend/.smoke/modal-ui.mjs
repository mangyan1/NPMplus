// biome-ignore-all lint/suspicious/noMisplacedAssertion: standalone browser integration assertions
import assert from "node:assert/strict";
import { chromium } from "playwright";

const base = process.env.SMOKE_BASE_URL || "https://127.0.0.1:28183";
const fixtureEmail = `modal-${Date.now()}@example.test`;
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
	await page.goto(`${base}/login`, { waitUntil: "networkidle" });
	await page.getByLabel(/email/i).fill("admin@example.test");
	await page.getByLabel(/password/i).fill("rc5-smoke-password");
	await page.getByRole("button", { name: /sign in|log in/i }).click();
	await page.getByRole("link", { name: "Open user menu" }).waitFor();
	const dialog = page.getByRole("dialog");
	const cancel = async (name) => {
		await dialog
			.getByRole("button", { name: /^(Cancel|Close)$/ })
			.last()
			.click();
		try {
			await dialog.waitFor({ state: "hidden" });
		} catch (error) {
			console.error("Remaining dialog:", await dialog.innerText());
			await page.screenshot({ path: "backend/.smoke/security-modal-failure.png" });
			throw error;
		}
		assert.equal(await page.locator(".modal-backdrop").count(), 0);
		console.log(`PASS ${name} cancels without a stranded backdrop`);
	};
	const invalid = async (name) => {
		await dialog.getByRole("button", { name: "Save", exact: true }).click();
		const nativeInvalid = dialog.locator("input:invalid, select:invalid, textarea:invalid").first();
		if (await nativeInvalid.count()) {
			assert.ok(
				await nativeInvalid.evaluate((input) => !input.validity.valid && input.validationMessage.length > 0),
			);
			await dialog.getByRole("button", { name: "Cancel", exact: true }).focus();
			// Blurring a native-invalid input can add Formik feedback and move the
			// footer. Let that layout commit before testing the Cancel click.
			await dialog.evaluate(
				() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
			);
		} else {
			await dialog.locator(".invalid-feedback:visible, .text-danger:visible").first().waitFor();
		}
		if (name === "empty user form") {
			assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
			await page.screenshot({ path: "backend/.smoke/security-modal-validation-mobile.png" });
		}
		await cancel(name);
	};
	await page.goto(`${base}/users`, { waitUntil: "networkidle" });
	await page.setViewportSize({ width: 390, height: 844 });
	await page.getByRole("button", { name: "Add User", exact: true }).click();
	await invalid("empty user form");
	await page.setViewportSize({ width: 1280, height: 900 });
	await page.getByRole("button", { name: "Add User", exact: true }).click();
	await dialog.getByLabel("Full Name", { exact: true }).fill("Modal Fixture");
	await dialog.getByLabel(/email/i).fill(fixtureEmail);
	const userSaved = page.waitForResponse(
		(response) => response.request().method() === "POST" && response.url().endsWith("/api/users"),
	);
	await dialog.getByRole("button", { name: "Save", exact: true }).click();
	assert.equal((await userSaved).status(), 201);
	await dialog.waitFor({ state: "hidden" });
	const row = page.getByRole("row").filter({ hasText: fixtureEmail });
	const action = async (name) => {
		await row.locator("button.dropdown-toggle").click();
		await row.getByRole("button", { name, exact: true }).click();
	};
	await action("Permissions");
	await dialog.getByRole("button", { name: "Save", exact: true }).click();
	await dialog.waitFor({ state: "hidden" });
	console.log("PASS user and permissions save");
	await action("Permissions");
	await cancel("permissions");
	await action("Set Password");
	await invalid("empty set-password form");
	await action("Set Password");
	await dialog.getByLabel(/new password/i).fill("Modal-Fixture-Password-1");
	await dialog.getByRole("button", { name: "Save", exact: true }).click();
	await dialog.waitFor({ state: "hidden" });
	console.log("PASS set-password save");
	await action("Delete");
	await cancel("delete confirmation");
	assert.ok(await row.isVisible());
	await page.getByRole("link", { name: "Open user menu" }).click();
	await page.getByRole("link", { name: "Change Password", exact: true }).click();
	await invalid("empty change-password form");
	for (const [route, button, name] of [
		["/nginx/redirection", "Add Redirection Host", "redirection"],
		["/nginx/404", "Add 404 Host", "404 host"],
		["/nginx/stream", "Add Stream", "stream"],
		["/access", "Add Access List", "access list"],
	]) {
		await page.goto(`${base}${route}`, { waitUntil: "networkidle" });
		await page.getByRole("button", { name: button, exact: true }).click();
		await invalid(`empty ${name} form`);
	}
	await page.goto(`${base}/certificates`, { waitUntil: "networkidle" });
	for (const name of [/Certbot.*HTTP/i, /Certbot.*DNS/i, /^Custom Certificate$/, /^mTLS$/]) {
		await page.getByRole("button", { name: "Add Certificate", exact: true }).click();
		await page.getByRole("button", { name }).click();
		await invalid(`empty certificate ${name}`);
	}
	await page.goto(`${base}/audit-log`, { waitUntil: "networkidle" });
	await page.getByRole("button", { name: "View Details", exact: true }).first().click();
	await cancel("audit event details");
	// Renewal begins immediately on opening. Intercept only this synthetic
	// certificate so the browser tests error/close without contacting an ACME CA.
	const certificateRoutes = /\/api\/nginx\/certificates(?:\/900001(?:\/renew)?)?(?:\?.*)?$/;
	const certificate = {
		id: 900001,
		owner_user_id: 1,
		owner: { id: 1, name: "Fixture owner", avatar: "" },
		created_on: "2026-09-01 00:00:00",
		modified_on: "2026-09-01 00:00:00",
		provider: "letsencrypt",
		nice_name: "Renewal fixture",
		domain_names: ["renewal.example.test"],
		expires_on: "2027-01-01 00:00:00",
		meta: {},
		proxy_hosts: [],
		redirection_hosts: [],
		dead_hosts: [],
		streams: [],
	};
	let renewalRequests = 0;
	await page.route(certificateRoutes, async (route) => {
		const url = new URL(route.request().url());
		if (url.pathname.endsWith("/renew")) {
			renewalRequests++;
			await route.fulfill({
				status: 400,
				json: { error: { message: "certificate.renew", output: "Synthetic renewal failure" } },
			});
		} else {
			await route.fulfill({ json: url.pathname.endsWith("/900001") ? certificate : [certificate] });
		}
	});
	await page.goto(`${base}/certificates`, { waitUntil: "networkidle" });
	const certRow = page.getByRole("row").filter({ hasText: "renewal.example.test" });
	await certRow.locator("button.dropdown-toggle").click();
	await certRow.getByRole("button", { name: /renew/i }).click();
	await dialog.getByText("Synthetic renewal failure", { exact: true }).waitFor();
	await cancel("failed certificate renewal fixture");
	assert.equal(renewalRequests, 1);
	await page.unroute(certificateRoutes);
	await page.goto(`${base}/users`, { waitUntil: "networkidle" });
	await action("Delete");
	await dialog.getByRole("button", { name: "Delete", exact: true }).click();
	await dialog.waitFor({ state: "hidden" });
	await row.waitFor({ state: "hidden" });
	console.log("PASS delete confirmation removes only the fixture user");
	assert.deepEqual(errors, []);
	await page.screenshot({ path: "backend/.smoke/security-modals-desktop.png" });
	console.log("PASS modal browser checks");
} finally {
	await browser.close();
}
