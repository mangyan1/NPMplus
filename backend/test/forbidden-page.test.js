import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import utils from "../lib/utils.js";

test("forbidden page CSP permits exactly its stylesheet and denies scripts and framing", async () => {
	const html = readFileSync(new URL("../../rootfs/usr/local/nginx/html/forbidden.html", import.meta.url), "utf8");
	const template = readFileSync(new URL("../templates/default.conf", import.meta.url), "utf8");
	const styles = [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)];
	assert.equal(styles.length, 1);
	const hash = createHash("sha256").update(styles[0][1].replace(/\r\n/g, "\n")).digest("base64");
	const engine = utils.getRenderEngine();
	const render = (value) => engine.parseAndRender(template, { value, meta: {}, env: {} });
	const config = await render("forbidden");
	const location = config.match(/location = \/forbidden\.html \{([\s\S]*?)\}/)?.[1];
	assert.ok(location);
	assert.match(config, /content_by_lua_block \{\s*return ngx\.exit\(ngx\.HTTP_FORBIDDEN\)/);
	assert.ok(location.includes(`style-src 'sha256-${hash}'`), "CSP style hash must match the bundled page");
	for (const directive of [
		"default-src 'none'",
		"script-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	])
		assert.ok(location.includes(directive));
	assert.match(location, /add_header Content-Security-Policy "[^"\n]+" always;/);
	assert.match(location, /add_header X-Frame-Options "DENY" always;/);
	for (const value of ["congratulations", "404", "444", "redirect", "html"]) {
		assert.doesNotMatch(await render(value), /Content-Security-Policy|X-Frame-Options/);
	}
});
