import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { fetchWithTimeout, readBoundedText } from "../lib/bounded-fetch.js";
import { assertPrivilegedNginxFields, privilegedProjection } from "../lib/nginx-privilege.js";

const exceedsEightBytesPattern = /exceeds 8 bytes/;
const delegatedAccess = {
	can: (permission) => {
		if (permission === "admin:access") return Promise.reject(new Error("not an admin"));
		return Promise.resolve(true);
	},
};

test("bounded response reader rejects oversized streaming bodies", async () => {
	const response = new Response("123456789");
	await assert.rejects(readBoundedText(response, 8), exceedsEightBytesPattern);
});

test("outbound timeout remains active while the response body is read", async () => {
	const server = createServer((_, response) => {
		response.writeHead(200, { "content-type": "text/plain" });
		response.flushHeaders();
	});
	await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
	try {
		const { port } = server.address();
		const response = await fetchWithTimeout(`http://127.0.0.1:${port}`, {}, 1000);
		await assert.rejects(readBoundedText(response, 1024));
	} finally {
		server.closeAllConnections();
		await new Promise((resolve) => server.close(resolve));
	}
});

test("delegated users cannot introduce raw nginx configuration", async () => {
	await assert.rejects(
		assertPrivilegedNginxFields(delegatedAccess, { advanced_config: "proxy_set_header X-Test yes;" }),
		(error) => error.status === 403,
	);
});

test("delegated users cannot introduce a local filesystem proxy target", async () => {
	assert.deepEqual(privilegedProjection({ forward_scheme: "path", forward_host: "/data/html" }), {
		localPath: { forward_scheme: "path", forward_host: "/data/html" },
	});
	await assert.rejects(
		assertPrivilegedNginxFields(delegatedAccess, {
			forward_scheme: "path",
			forward_host: "/data/html",
		}),
		(error) => error.status === 403,
	);
});

test("delegated users cannot add syntax-bearing custom location paths", async () => {
	await assert.rejects(
		assertPrivilegedNginxFields(delegatedAccess, {
			locations: [{ path: "/safe # injected", forward_scheme: "http", forward_host: "example.com" }],
		}),
		(error) => error.status === 403,
	);
});

test("delegated users may update ordinary fields without changing existing privileged fields", async () => {
	const existing = { id: 1, advanced_config: "add_header X-Test yes;", enabled: true };
	await assert.doesNotReject(assertPrivilegedNginxFields(delegatedAccess, { id: 1, enabled: false }, existing));
});
