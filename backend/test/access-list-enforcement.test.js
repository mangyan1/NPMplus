import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import test from "node:test";
import internalNginx from "../internal/nginx.js";
import acl from "../internal/proxy-host-access-list.js";

const deny = { id: 1, items: [], clients: [{ directive: "deny", address: "all" }] };
const allow = { id: 2, items: [], clients: [{ directive: "allow", address: "all" }] };
const auth = { id: 3, items: [{ username: "user", password: "fixture-hash" }], clients: [] };

test("deny-only selections retain their catch-all, including mixed lists", () => {
	for (const lists of [[deny], [deny, allow], [allow, deny], [deny, auth]]) {
		assert.deepEqual(acl.buildAclFile(lists).clients, deny.clients);
	}
});

test("Basic Auth-only selections do not invent an IP policy", () => {
	assert.deepEqual(acl.buildAclFile([auth]).clients, []);
	assert.deepEqual(acl.buildAclFile([allow]).clients, allow.clients);
});

test("deny-only policy renders in both the host and a custom location", async () => {
	await mkdir("/data/nginx/proxy_host", { recursive: true });
	await internalNginx.generateConfig("proxy_host", {
		id: 71,
		domain_names: ["acl-fixture.example.test"],
		forward_scheme: "http",
		forward_host: "127.0.0.1",
		forward_port: 8080,
		npmplus_access_list_type: "custom",
		npmplus_access_list_ids: [deny.id],
		access_lists: [deny],
		locations: [
			{
				id: 0,
				path: "/private",
				forward_scheme: "http",
				forward_host: "127.0.0.1",
				forward_port: 8080,
				npmplus_access_list_type: "custom",
				npmplus_access_list_ids: [deny.id],
				access_lists: [deny],
			},
		],
	});
	const config = await readFile(internalNginx.getConfigName("proxy_host", 71), "utf8");
	assert.equal(config.match(/deny all;/g)?.length, 2);
});
