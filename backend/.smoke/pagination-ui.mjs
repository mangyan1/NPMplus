// biome-ignore-all lint/suspicious/noMisplacedAssertion: standalone browser integration assertions
import assert from "node:assert/strict";
import { chromium } from "playwright";

const base = process.env.SMOKE_BASE_URL;
assert.ok(["127.0.0.1", "localhost"].includes(new URL(base).hostname));
const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM || undefined });
try {
	const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
	const page = await context.newPage();
	page.setDefaultTimeout(15000);
	const errors = [];
	page.on("pageerror", (error) => errors.push(error.message));
	page.on("console", (message) => {
		if (message.type() === "error" && !/status of (400|401|403)/.test(message.text())) errors.push(message.text());
	});
	await page.goto(`${base}/login`, { waitUntil: "networkidle" });
	await page.getByLabel(/email/i).fill(process.env.SMOKE_ADMIN_EMAIL);
	await page.getByLabel(/password/i).fill(process.env.SMOKE_ADMIN_PASSWORD);
	await page.getByRole("button", { name: /sign in|log in/i }).click();
	await page.getByRole("link", { name: "Open user menu" }).waitFor();
	const users = Array.from({ length: 51 }, (_, index) => ({
		id: index + 1000,
		name: `Pagination user ${String(index + 1).padStart(3, "0")}`,
		email: `page-${index + 1}@example.test`,
		roles: [],
		avatar: "",
		created_on: "2026-10-01T12:00:00.000Z",
		is_disabled: false,
	}));
	let auditPage = 0;
	await page.route(/\/api\/users(?:\?.*)?$/, (route) => route.fulfill({ json: users }));
	await page.route(/\/api\/audit-log(?:\?.*)?$/, (route) => {
		const params = new URL(route.request().url()).searchParams;
		auditPage = Number(params.get("page") || 0);
		const size = Number(params.get("page_size") || 25);
		const query = params.get("query") || "";
		const rows = users
			.filter((user) => user.name.includes(query))
			.map((user) => ({
				id: user.id,
				created_on: user.created_on,
				action: "created",
				object_type: "user",
				object_id: user.id,
				meta: { name: user.name, email: user.email },
			}));
		return route.fulfill({
			json: { results: rows.slice(auditPage * size, (auditPage + 1) * size), total: rows.length },
		});
	});
	await page.goto(`${base}/users`, { waitUntil: "networkidle" });
	assert.equal(await page.locator("tbody tr").count(), 25);
	await page.getByRole("button", { name: "Next page", exact: true }).first().click();
	await page.getByRole("row").filter({ hasText: "Pagination user 026" }).waitFor();
	await page.getByRole("button", { name: "Last page", exact: true }).first().click();
	await page.getByRole("row").filter({ hasText: "Pagination user 051" }).waitFor();
	assert.equal(await page.locator("tbody tr").count(), 1);
	await page.getByRole("button", { name: "First page", exact: true }).first().click();
	await page.getByLabel("Rows per page").first().selectOption("50");
	assert.equal(await page.locator("tbody tr").count(), 50);
	await page.getByRole("textbox").fill("Pagination user 051");
	assert.equal(await page.locator("tbody tr").count(), 1);
	console.log("PASS user-table pagination, page size and filtering use the retained table dependency");
	await page.goto(`${base}/audit-log`, { waitUntil: "networkidle" });
	assert.equal(await page.locator("tbody tr").count(), 25);
	const nextResponse = page.waitForResponse((response) => new URL(response.url()).searchParams.get("page") === "1");
	await page.getByRole("button", { name: "Next page", exact: true }).first().click();
	await nextResponse;
	await page.waitForLoadState("networkidle");
	assert.equal(auditPage, 1);
	const filterResponse = page.waitForResponse((response) => {
		const url = new URL(response.url());
		return url.pathname === "/api/audit-log" && url.searchParams.get("query") === "Pagination user 051";
	});
	await page.getByRole("textbox").fill("Pagination user 051");
	await filterResponse;
	await page.waitForFunction(() => document.querySelectorAll("tbody tr").length === 1);
	assert.equal(auditPage, 0);
	assert.equal(await page.locator("tbody tr").count(), 1);
	await page.getByRole("textbox").fill("");
	await page.waitForFunction(() => document.querySelectorAll("tbody tr").length === 25);
	for (const width of [1280, 390, 320]) {
		await page.setViewportSize({ width, height: 900 });
		assert.ok(
			await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
			`overflow at ${width}px`,
		);
		const boxes = await page.getByLabel("Page number").evaluateAll((inputs) =>
			inputs.map((input) => {
				const box = input.getBoundingClientRect();
				return { left: box.left, right: box.right };
			}),
		);
		assert.ok(boxes.length === 2 && boxes.every((box) => box.left >= 0 && box.right <= width));
		await page.screenshot({ path: `backend/.smoke/security-pagination-${width}.png`, fullPage: true });
	}
	assert.deepEqual(errors, []);
	console.log("PASS audit pagination filters on the server, resets its page and fits desktop and phone widths");
} finally {
	await browser.close();
}
