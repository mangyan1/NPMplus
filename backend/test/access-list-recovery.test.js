import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import test from "node:test";
import db from "../db.js";
import internalAccessList from "../internal/access-list.js";
import internalAuditLog from "../internal/audit-log.js";
import internalNginx from "../internal/nginx.js";
import proxyAccess from "../internal/proxy-host-access-list.js";
import { migrateUp } from "../migrate.js";
import AccessList from "../models/access_list.js";
import AccessListAuth from "../models/access_list_auth.js";
import AccessListClient from "../models/access_list_client.js";
import ProxyHost from "../models/proxy_host.js";

await migrateUp();
await mkdir("/data/access", { recursive: true });
await mkdir("/data/nginx/proxy_host", { recursive: true });
process.env.HTTP_PORT = "80";
process.env.HTTPS_PORT = "443";
const access = { can() {}, token: { getUserId: () => 1 }, visibility: "all" };
const seed = async () => {
	const list = await AccessList.query().insertAndFetch({
		name: "Original",
		owner_user_id: 1,
		satisfy_any: false,
		pass_auth: false,
	});
	await AccessListAuth.query().insert({
		access_list_id: list.id,
		username: "original",
		password: "fixture-password-hash",
	});
	return list;
};

test("a blank-password rename rejects before changing any access-list fields or credentials", async (t) => {
	t.mock.method(internalNginx, "reload", async () => {});
	t.mock.method(internalNginx, "test", async () => {});
	const list = await seed();
	await assert.rejects(
		internalAccessList.update(access, {
			id: list.id,
			name: "Changed",
			items: [{ username: "renamed", password: "" }],
		}),
		(error) => error.status === 400,
	);
	assert.equal((await AccessList.query().findById(list.id)).name, "Original");
	assert.equal((await AccessListAuth.query().where("access_list_id", list.id).first()).username, "original");
});

test("a blank masked password keeps the matching existing credential unchanged", async (t) => {
	t.mock.method(internalNginx, "reload", async () => {});
	t.mock.method(internalNginx, "test", async () => {});
	const list = await seed();
	const result = await internalAccessList.update(access, {
		id: list.id,
		items: [{ username: "original", password: "" }],
	});
	assert.equal(result.items.length, 1);
	assert.equal(result.items[0].password, "fixture-password-hash");
});

for (const [table, key, replacement] of [
	["access_list_auth", "items", [{ username: "replacement", password: "new-password" }]],
	["access_list_client", "clients", [{ directive: "deny", address: "all" }]],
]) {
	test(`a failed ${key} insertion preserves the complete previous policy`, async () => {
		const list = await seed();
		await AccessListClient.query().insert({ access_list_id: list.id, directive: "deny", address: "all" });
		await db().raw(
			`CREATE TRIGGER reject_acl_insert BEFORE INSERT ON ${table} WHEN NEW.access_list_id=${list.id} BEGIN SELECT RAISE(ABORT, 'injected insertion failure'); END`,
		);
		try {
			await assert.rejects(
				internalAccessList.update(access, { id: list.id, name: "Changed", [key]: replacement }),
				/injected insertion failure/,
			);
			assert.equal((await AccessList.query().findById(list.id)).name, "Original");
			assert.equal((await AccessListAuth.query().where("access_list_id", list.id).first()).username, "original");
			assert.equal((await AccessListClient.query().where("access_list_id", list.id).first()).directive, "deny");
		} finally {
			await db().raw("DROP TRIGGER reject_acl_insert");
		}
	});
}

test("a failed audit restores both database rows and the previously generated password file", async (t) => {
	t.mock.method(internalNginx, "reload", async () => {});
	t.mock.method(internalNginx, "test", async () => {});
	t.mock.method(internalAuditLog, "add", async () => {
		throw new Error("injected audit failure");
	});
	const list = await seed();
	await writeFile(internalAccessList.getFilename(list), "original:fixture-password-hash\n");
	await assert.rejects(
		internalAccessList.update(access, {
			id: list.id,
			name: "Changed",
			items: [{ username: "replacement", password: "new-password" }],
		}),
		/injected audit failure/,
	);
	assert.equal((await AccessList.query().findById(list.id)).name, "Original");
	assert.equal((await AccessListAuth.query().where("access_list_id", list.id).first()).username, "original");
	assert.equal(await readFile(internalAccessList.getFilename(list), "utf8"), "original:fixture-password-hash\n");
});

const attach = async (list) => {
	const second = await seed();
	const host = await ProxyHost.query().insertAndFetch({
		owner_user_id: 1,
		domain_names: [`recovery-${list.id}.example.test`],
		enabled: true,
		forward_scheme: "http",
		forward_host: "127.0.0.1",
		forward_port: 8080,
		certificate_id: 0,
		npmplus_access_list_type: "custom",
		npmplus_access_list_ids: [list.id, second.id],
		locations: [
			{
				id: 1,
				path: "/private",
				forward_scheme: "http",
				forward_host: "127.0.0.1",
				forward_port: 8080,
				npmplus_access_list_type: "custom",
				npmplus_access_list_ids: [list.id, second.id],
			},
		],
	});
	await db()("npmplus_proxy_host_access_list").insert([
		{ proxy_host_id: host.id, access_list_id: list.id },
		{ proxy_host_id: host.id, access_list_id: second.id },
	]);
	const expanded = await ProxyHost.query().findById(host.id).withGraphFetched("[access_lists.[items,clients]]");
	await proxyAccess.populateLocationAccessLists(expanded);
	await internalAccessList.build(await internalAccessList.get(access, { id: list.id, expand: ["items", "clients"] }));
	await proxyAccess.build("proxy_host", expanded);
	await internalNginx.generateConfig("proxy_host", expanded);
	return host;
};

for (const phase of ["generate", "validate", "reload", "audit"]) {
	test(`a ${phase} failure restores host and custom-location enforcement`, async (t) => {
		const list = await seed();
		const host = await attach(list);
		const files = [
			internalAccessList.getFilename(list),
			`/data/access/host-${host.id}`,
			`/data/access/host-${host.id}-location-1`,
			internalNginx.getConfigName("proxy_host", host.id),
		];
		const before = await Promise.all(files.map((filename) => readFile(filename, "utf8")));
		t.mock.method(internalNginx, "test", async () => {
			if (phase === "validate") throw new Error("injected validation failure");
		});
		let reloads = 0;
		t.mock.method(internalNginx, "reload", async () => {
			if (++reloads === 1 && phase === "reload") throw new Error("injected reload failure");
		});
		if (phase === "generate")
			t.mock.method(internalNginx, "generateConfig", async () => {
				await writeFile(files[3], "partially generated");
				throw new Error("injected generation failure");
			});
		if (phase === "audit")
			t.mock.method(internalAuditLog, "add", async () => {
				throw new Error("injected audit failure");
			});
		await assert.rejects(
			internalAccessList.update(access, {
				id: list.id,
				items: [{ username: "replacement", password: "new-password" }],
			}),
			/injected/,
		);
		assert.equal((await AccessListAuth.query().where("access_list_id", list.id).first()).username, "original");
		assert.deepEqual(await Promise.all(files.map((filename) => readFile(filename, "utf8"))), before);
		assert.match(await readFile(files[3], "utf8"), /auth_basic\s+"/);
	});
}

test("a successful replacement updates attached host and custom-location files and commits one audit", async (t) => {
	t.mock.method(internalNginx, "reload", async () => {});
	t.mock.method(internalNginx, "test", async () => {});
	const list = await seed();
	const host = await attach(list);
	const result = await internalAccessList.update(access, {
		id: list.id,
		items: [{ username: "replacement", password: "new-password" }],
	});
	assert.equal(result.items[0].username, "replacement");
	for (const filename of [
		`/data/access/${list.id}`,
		`/data/access/host-${host.id}`,
		`/data/access/host-${host.id}-location-1`,
	])
		assert.match(await readFile(filename, "utf8"), /^replacement:/m);
	assert.equal((await ProxyHost.query().findById(host.id)).npmplus_nginx_online, true);
	assert.equal(
		await db()("audit_log")
			.where({ object_type: "access-list", object_id: list.id, action: "updated" })
			.count("* as n")
			.first()
			.then((row) => row.n),
		1,
	);
});

test("hosts attached after initial validation are included in failure recovery", async (t) => {
	const list = await seed();
	const originalGet = internalAccessList.get;
	let attached = false;
	let files;
	let before;
	t.mock.method(internalAccessList, "get", async (...args) => {
		const result = await originalGet(...args);
		if (!attached) {
			attached = true;
			const host = await attach(list);
			files = [
				internalNginx.getConfigName("proxy_host", host.id),
				`/data/access/host-${host.id}`,
				`/data/access/host-${host.id}-location-1`,
			];
			before = await Promise.all(files.map((filename) => readFile(filename, "utf8")));
		}
		return result;
	});
	t.mock.method(internalNginx, "test", () => Promise.reject(new Error("injected validation failure")));
	t.mock.method(internalNginx, "reload", async () => {});
	await assert.rejects(
		internalAccessList.update(access, {
			id: list.id,
			items: [{ username: "replacement", password: "new-password" }],
		}),
		/injected validation failure/,
	);
	assert.deepEqual(await Promise.all(files.map((filename) => readFile(filename, "utf8"))), before);
});
