import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { fetchWithTimeout, readBoundedText } from "../lib/bounded-fetch.js";
import { assertPrivilegedNginxFields, privilegedProjection } from "../lib/nginx-privilege.js";
import utils from "../lib/utils.js";

const exceedsEightBytesPattern = /exceeds 8 bytes/;
const delegatedAccess = {
	// merged permission model: canAdmin() throws for non-admins, can() stays
	// synchronous
	canAdmin: () => {
		throw new Error("not an admin");
	},
	can: () => true,
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

test("delegated users cannot introduce raw nginx configuration", () => {
	assert.throws(
		() => assertPrivilegedNginxFields(delegatedAccess, { advanced_config: "proxy_set_header X-Test yes;" }),
		(error) => error.status === 403,
	);
});

test("delegated users cannot introduce a local filesystem proxy target", () => {
	assert.deepEqual(privilegedProjection({ forward_scheme: "path", forward_host: "/data/html", forward_port: 9000 }), {
		localPath: { forward_scheme: "path", forward_host: "/data/html", forward_port: 9000 },
	});
	assert.throws(
		() =>
			assertPrivilegedNginxFields(delegatedAccess, {
				forward_scheme: "path",
				forward_host: "/data/html",
				forward_port: 9000,
			}),
		(error) => error.status === 403,
	);
});

test("delegated users cannot change the local-path fastcgi port on an existing host", () => {
	// the local-path fastcgi target renders from forward_port
	// (fastcgi_pass unix:/run/php{{ forward_port }}.sock), so changing it must
	// trip the admin-only guard, not just scheme/host
	const existing = { forward_scheme: "path", forward_host: "/data/html", forward_port: 9000 };
	assert.equal(assertPrivilegedNginxFields(delegatedAccess, { forward_port: 9000 }, existing), undefined);
	assert.throws(
		() => assertPrivilegedNginxFields(delegatedAccess, { forward_port: 9090 }, existing),
		(error) => error.status === 403,
	);
});

test("delegated users cannot add syntax-bearing custom location paths", () => {
	assert.throws(
		() =>
			assertPrivilegedNginxFields(delegatedAccess, {
				locations: [{ path: "/safe # injected", forward_scheme: "http", forward_host: "example.com" }],
			}),
		(error) => error.status === 403,
	);
});

test("delegated users may update ordinary fields without changing existing privileged fields", () => {
	const existing = { id: 1, advanced_config: "add_header X-Test yes;", enabled: true };
	// the guard is synchronous in the merged permission model: no throw is the pass
	assert.equal(assertPrivilegedNginxFields(delegatedAccess, { id: 1, enabled: false }, existing), undefined);
});

test("the nginxAccessRule filter drops addresses carrying nginx syntax", async () => {
	// addresses render into generated nginx configs; a row stored before the
	// schema pattern existed may still carry syntax, so the filter must drop
	// such rules instead of rendering them (deny-all stays the default)
	const engine = utils.getRenderEngine();
	const injected = await engine.parseAndRender("{{ rule | nginxAccessRule }}", {
		rule: { directive: "allow", address: "1.2.3.4;\nlocation /pwn { alias /; }\nlocation / {\n#" },
	});
	assert.equal(injected, "");
	const legit = await engine.parseAndRender("{{ rule | nginxAccessRule }}", {
		rule: { directive: "allow", address: "192.168.0.0/24" },
	});
	assert.equal(legit, "allow 192.168.0.0/24;");
});

test("auth-request upstreams must be a bare scheme://host:port", () => {
	// the same shape envs.sh enforces for AUTH_REQUEST_*_UPSTREAM; anything
	// else must be treated as absent when picking the effective upstream
	assert.equal(utils.isValidAuthRequestUpstream("https://anubis:8923"), true);
	assert.equal(utils.isValidAuthRequestUpstream("http://127.0.0.1:80"), true);
	assert.equal(utils.isValidAuthRequestUpstream("https://[2001:db8::1]:443"), true);
	assert.equal(utils.isValidAuthRequestUpstream(""), false);
	assert.equal(utils.isValidAuthRequestUpstream("https://anubis:8923/path"), false);
	assert.equal(
		utils.isValidAuthRequestUpstream(
			"https://127.0.0.2:443;\n}\nserver { listen 80; }\nupstream z {\nserver 127.0.0.1:80;\n#:443",
		),
		false,
	);
});
