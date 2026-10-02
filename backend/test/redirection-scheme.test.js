import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import test from "node:test";
import internalNginx from "../internal/nginx.js";

for (const scheme of ["auto", "http", "https"]) {
	for (const preservePath of [false, true]) {
		test(`redirection scheme ${scheme} preserves path=${preservePath}`, async () => {
			await mkdir("/data/nginx/redirection_host", { recursive: true });
			const host = {
				id: 72,
				domain_names: ["redirect.example.test"],
				forward_scheme: scheme,
				forward_domain_name: "destination.example.test",
				preserve_path: preservePath,
			};
			for (const status of [301, 302, 307, 308]) {
				await internalNginx.generateConfig("redirection_host", { ...host, forward_http_code: status });
				const config = await readFile(internalNginx.getConfigName("redirection_host", host.id), "utf8");
				const renderedScheme = scheme === "auto" ? "$scheme" : scheme;
				const renderedPath = preservePath ? "$request_uri" : "";
				assert.ok(
					config.includes(`return ${status} ${renderedScheme}://destination.example.test${renderedPath};`),
				);
				assert.ok(!config.includes("auto://"));
			}
		});
	}
}
