import "./helpers/environment.js";
import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import knex from "knex";
import db from "../db.js";
import { hostCoverage } from "../internal/anubis-reporting.js";
import { migrateUp } from "../migrate.js";
import ProxyHost from "../models/proxy_host.js";
import { root } from "./helpers/environment.js";

test("a populated fork database keeps ordered location ACLs, Anubis coverage and a restorable legacy snapshot", async (t) => {
	const files = (await readdir(new URL("../migrations/", import.meta.url)))
		.filter(
			(name) => name.endsWith(".js") && (name < "20261008000000" || name === "20261402145603_http3_support.js"),
		)
		.sort();
	const legacy = knex(db().client.config);
	t.after(() => legacy.destroy());
	await legacy.migrate.latest({
		tableName: "migrations",
		migrationSource: {
			getMigrations: async () => files,
			getMigrationName: (name) => name,
			getMigration: (name) => import(new URL(`../migrations/${name}`, import.meta.url)),
		},
	});
	const stamp = { created_on: "2026-10-01 00:00:00", modified_on: "2026-10-01 00:00:00" };
	await legacy("user").insert({
		id: 1,
		...stamp,
		name: "Upgrade fixture",
		email: "upgrade@example.test",
		roles: '["admin"]',
		avatar: "",
		nickname: "",
	});
	await legacy("access_list").insert(
		[11, 12].map((id) => ({ id, ...stamp, owner_user_id: 1, name: `ACL ${id}`, meta: "{}" })),
	);
	const locations = [
		{
			id: 7,
			path: "/private",
			npmplus_auth_request: "anubis",
			npmplus_access_list_type: "custom",
			npmplus_access_list_ids: [12, 11],
			forward_host: "origin.example.test",
			forward_port: 8080,
		},
		{
			id: 8,
			path: "/inherit",
			npmplus_auth_request: "none",
			npmplus_access_list_type: "global",
			npmplus_access_list_ids: [],
		},
	];
	await legacy("proxy_host").insert({
		id: 21,
		...stamp,
		owner_user_id: 1,
		domain_names: '["upgrade.example.test"]',
		forward_scheme: "http",
		forward_host: "origin.example.test",
		forward_port: 8080,
		meta: "{}",
		locations: JSON.stringify(locations),
		npmplus_auth_request: "anubis",
		npmplus_access_list_type: "custom",
		npmplus_access_list_ids: "[11]",
	});
	await legacy("npmplus_proxy_host_access_list").insert({ proxy_host_id: 21, access_list_id: 11 });
	await legacy("user").insert({
		id: 2,
		...stamp,
		name: "Deleted fixture",
		email: "deleted@example.test",
		roles: "[]",
		is_deleted: 1,
		avatar: "",
		nickname: "",
	});
	await legacy("auth").insert({ ...stamp, user_id: 2, type: "oidc", secret: "deleted-fixture", meta: "{}" });
	const snapshot = path.join(root, "pre-location-upgrade.sqlite");
	const connection = await legacy.client.acquireConnection();
	await connection.backup(snapshot);
	await legacy.client.releaseConnection(connection);
	await legacy.destroy();

	await migrateUp();
	const host = await ProxyHost.query().findById(21).withGraphFetched("[access_lists,locations.access_lists]");
	assert.deepEqual(
		host.access_lists.map(({ id }) => id),
		[11],
	);
	assert.deepEqual(
		host.locations.map(({ path: locationPath }) => locationPath),
		["/private", "/inherit"],
	);
	assert.deepEqual(
		host.locations[0].access_lists.map(({ id }) => id),
		[12, 11],
	);
	assert.equal(await db()("user").where({ id: 2 }).first(), undefined);
	assert.equal(await db()("auth").where({ user_id: 2 }).first(), undefined);
	const coverage = await hostCoverage();
	assert.deepEqual(
		coverage.items[0].locations.map(({ path: locationPath, anubis }) => [locationPath, anubis]),
		[
			["/private", true],
			["/inherit", true],
		],
	);
	await migrateUp();
	assert.equal(
		await db()("npmplus_location")
			.where({ proxy_host_id: 21 })
			.count()
			.first()
			.then((row) => Object.values(row)[0]),
		2,
	);

	const restored = knex({ ...db().client.config, connection: { filename: snapshot } });
	try {
		assert.equal(await restored.schema.hasTable("npmplus_location"), false);
		assert.deepEqual(JSON.parse((await restored("proxy_host").where({ id: 21 }).first()).locations), locations);
		assert.ok(await restored("user").where({ id: 2 }).first());
	} finally {
		await restored.destroy();
	}
});
