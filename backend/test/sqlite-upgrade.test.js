import "./helpers/environment.js";
import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import test from "node:test";
import knex from "knex";
import { generate, generateSecret } from "otplib";
import db from "../db.js";
import internalToken from "../internal/token.js";
import totp from "../internal/totp.js";
import { migrateUp } from "../migrate.js";
import Auth from "../models/auth.js";
import ProxyHost from "../models/proxy_host.js";
import User from "../models/user.js";

test("an existing SQLite MFA account and proxy survive the replay migration", async (t) => {
	let epoch = 1900000000;
	t.mock.method(Date, "now", () => epoch * 1000);
	// Reconstruct the schema shipped immediately before replay protection.
	// The historical http3 migration sorts after the replay migration, so a
	// simple filename cutoff would not reproduce that deployed database.
	const files = (await readdir(new URL("../migrations/", import.meta.url)))
		.filter(
			(name) =>
				name.endsWith(".js") &&
				(name < "20260919000000_totp_replay.js" || name === "20261402145603_http3_support.js"),
		)
		.sort();
	const legacy = knex(db().client.config);
	await legacy.migrate.latest({
		tableName: "migrations",
		migrationSource: {
			getMigrations: async () => files,
			getMigrationName: (name) => name,
			getMigration: (name) => import(new URL(`../migrations/${name}`, import.meta.url)),
		},
	});
	await legacy.destroy();
	assert.equal(await db().schema.hasColumn("auth", "npmplus_totp_last_used_step"), false);
	const user = await User.query().insertAndFetch({
		name: "Upgrade fixture",
		email: "upgrade@example.test",
		nickname: "fixture",
		avatar: "",
		roles: ["admin"],
		npmplus_token_valid_after: 0,
	});
	const secret = generateSecret();
	const auth = await Auth.query().insertAndFetch({
		user_id: user.id,
		type: "password",
		secret: "Upgrade-Fixture-1",
		meta: { totp_enabled: true, totp_secret: secret },
	});
	const proxy = await ProxyHost.query().insertAndFetch({
		owner_user_id: user.id,
		domain_names: ["upgrade.example.test"],
		forward_scheme: "http",
		forward_host: "127.0.0.1",
		forward_port: 8080,
	});
	// Switch from the historical migration source to the actual startup path.
	await migrateUp();
	const upgraded = await Auth.query().findById(auth.id);
	assert.deepEqual(upgraded.meta, auth.meta);
	assert.equal(upgraded.secret, auth.secret);
	assert.equal(upgraded.npmplus_totp_last_used_step, null);
	assert.deepEqual(await ProxyHost.query().findById(proxy.id), proxy);
	const challenge = await internalToken.getTokenFromEmail({ identity: user.email, secret: "Upgrade-Fixture-1" });
	const code = await generate({ secret });
	assert.ok((await internalToken.verifyTotp(challenge.token, code)).token);
	assert.equal(await totp.verifyCode(user.id, code), false);
	await migrateUp();
	assert.equal(await totp.verifyCode(user.id, code), false);
	epoch += 30;
	assert.equal(await totp.verifyCode(user.id, await generate({ secret })), true);
	assert.deepEqual(await ProxyHost.query().findById(proxy.id), proxy);
});
