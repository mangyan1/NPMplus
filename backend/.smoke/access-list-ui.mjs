// biome-ignore-all lint/suspicious/noMisplacedAssertion: standalone browser integration assertions
import assert from "node:assert/strict";
import { chromium } from "playwright";

const base = process.env.SMOKE_BASE_URL || "https://127.0.0.1:28183";
assert.ok(["127.0.0.1", "localhost"].includes(new URL(base).hostname));
const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined });
try {
	const page = await browser.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
	const errors = [];
	page.on("pageerror", (error) => errors.push(error.message));
	page.on("console", (event) => {
		if (event.type() === "error" && !event.text().includes("status of 400")) errors.push(event.text());
	});
	await page.goto(`${base}/login`, { waitUntil: "networkidle" });
	await page.getByLabel(/email/i).fill(process.env.SMOKE_ADMIN_EMAIL || "admin@example.test");
	await page.getByLabel(/password/i).fill(process.env.SMOKE_ADMIN_PASSWORD || "rc5-smoke-password");
	await page.getByRole("button", { name: /sign in|log in/i }).click();
	await page.getByRole("link", { name: "Open user menu" }).waitFor();
	const fixture = {
		id: 900001,
		name: "Synthetic access policy",
		owner_user_id: 1,
		owner: { id: 1, name: "Fixture owner", avatar: "" },
		created_on: "2026-09-01 00:00:00",
		modified_on: "2026-09-01 00:00:00",
		satisfy_any: false,
		pass_auth: false,
		proxy_host_count: 0,
		items: [{ username: "original", password: "" }],
		clients: [],
	};
	let writes = 0;
	await page.route(/\/api\/nginx\/access-lists(?:\/900001)?(?:\?.*)?$/, (route) => {
		if (route.request().method() !== "GET") {
			writes++;
			return route.fulfill({
				status: 400,
				contentType: "application/json",
				body: JSON.stringify({ error: { message: "error.access.password-required" } }),
			});
		}
		return route.fulfill({
			status: 200,
			contentType: "application/json",
			body: JSON.stringify(new URL(route.request().url()).pathname.endsWith("900001") ? fixture : [fixture]),
		});
	});
	await page.goto(`${base}/access`, { waitUntil: "networkidle" });
	const row = page.getByRole("row").filter({ hasText: fixture.name });
	await row.locator("button.dropdown-toggle").click();
	await row.getByRole("button", { name: "Edit", exact: true }).click();
	const dialog = page.getByRole("dialog");
	const message = "Enter a password for each new or renamed authorization user";
	await dialog.getByRole("tab", { name: "Authorizations", exact: true }).click();
	await dialog.locator('#tab-auth input[type="text"]').fill("renamed");
	await dialog.getByRole("button", { name: "Save", exact: true }).click();
	await dialog.getByText(message, { exact: true }).waitFor();
	assert.equal(writes, 0, "blank-password rename must be rejected before the API request");
	await page.screenshot({ path: "backend/.smoke/security-access-list-validation.png" });
	await dialog.locator('#tab-auth input[type="text"]').fill("original");
	const unchanged = page.waitForResponse(
		(response) =>
			response.request().method() === "PUT" && response.url().includes("/api/nginx/access-lists/900001"),
	);
	await dialog.getByRole("button", { name: "Save", exact: true }).click();
	await unchanged;
	assert.equal(writes, 1, "unchanged masked credentials must reach the API");
	await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
	await dialog.waitFor({ state: "hidden" });
	await page.getByRole("button", { name: "Add Access List", exact: true }).click();
	await dialog.getByLabel("Name", { exact: true }).fill("Synthetic rejected create");
	await dialog.getByRole("tab", { name: "Authorizations", exact: true }).click();
	await dialog.locator("#tab-auth").getByRole("button", { name: "Add", exact: true }).click();
	await dialog.locator('#tab-auth input[type="text"]').fill("new-user");
	await dialog.locator('#tab-auth input[type="password"]').fill("Synthetic-Fixture-Password-1");
	const rejected = page.waitForResponse(
		(response) => response.request().method() === "POST" && response.url().includes("/api/nginx/access-lists"),
	);
	await dialog.getByRole("button", { name: "Save", exact: true }).click();
	assert.equal((await rejected).status(), 400);
	await dialog.getByText(message, { exact: true }).waitFor();
	assert.equal(await dialog.getByRole("button", { name: "Save", exact: true }).isEnabled(), true);
	await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
	await dialog.waitFor({ state: "hidden" });
	assert.deepEqual(errors, [], "rejected creates must not raise a rollback TypeError");
	console.log("PASS access-list browser validation, masked credentials, and rejected-create recovery");
} finally {
	await browser.close();
}
