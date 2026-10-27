import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

test("the UTC upgrade converts local SQLite dates once and keeps UTC certificate expiry and backup", {
	skip: process.platform === "win32" ? "SQLite on Windows does not use the POSIX TZ setting" : false,
}, () => {
	const result = execFileSync(
		process.execPath,
		[
			"--input-type=module",
			"-e",
			`
import "./test/helpers/environment.js";
import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import path from "node:path";
import knex from "knex";
import db from "./db.js";
import { migrateUp } from "./migrate.js";
import { jsonReplacer } from "./lib/helpers.js";
import { root } from "./test/helpers/environment.js";
const files = (await readdir("./migrations")).filter(name => name.endsWith(".js") &&
 (name < "20261025170922" || name === "20261402145603_http3_support.js")).sort();
const legacy = knex(db().client.config);
await legacy.migrate.latest({tableName:"migrations", migrationSource:{
 getMigrations:async()=>files, getMigrationName:name=>name,
 getMigration:name=>import("./migrations/"+name)
}});
const stamp = {created_on:"2026-10-01 12:00:00", modified_on:"2026-10-01 12:00:00"};
await legacy("user").insert({id:1,...stamp,name:"UTC fixture",email:"utc@example.test",roles:'["admin"]',avatar:"",nickname:""});
await legacy("certificate").insert({id:1,...stamp,owner_user_id:1,provider:"other",nice_name:"UTC expiry",domain_names:'["utc.example.test"]',expires_on:"2027-01-01T20:30:00.000Z",meta:"{}"});
const snapshot = path.join(root,"before-utc.sqlite");
const connection = await legacy.client.acquireConnection();
await connection.backup(snapshot);
await legacy.client.releaseConnection(connection);
await legacy.destroy();
await migrateUp();
const converted = await db()("user").where({id:1}).first();
assert.equal(converted.created_on,"2026-10-01 18:00:00");
assert.equal(converted.modified_on,"2026-10-01 18:00:00");
const expiry = (await db()("certificate").where({id:1}).first()).expires_on;
assert.equal(expiry,"2027-01-01 20:30:00");
assert.equal(JSON.parse(JSON.stringify({created_on:converted.created_on,expires_on:expiry},jsonReplacer)).created_on,"2026-10-01T18:00:00.000Z");
await migrateUp();
assert.equal((await db()("user").where({id:1}).first()).created_on,converted.created_on);
const restored = knex({...db().client.config,connection:{filename:snapshot}});
assert.equal((await restored("user").where({id:1}).first()).created_on,stamp.created_on);
await restored.destroy();
await db().destroy();
console.log("UTC_UPGRADE_OK");
`,
		],
		{ cwd: new URL("../", import.meta.url), env: { ...process.env, TZ: "America/Edmonton" }, encoding: "utf8" },
	);
	assert.match(result, /UTC_UPGRADE_OK/);
});
