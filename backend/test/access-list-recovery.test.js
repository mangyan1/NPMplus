import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import test from "node:test";
import internalAccessList from "../internal/access-list.js";
import internalNginx from "../internal/nginx.js";
import { migrateUp } from "../migrate.js";
import AccessList from "../models/access_list.js";
import AccessListAuth from "../models/access_list_auth.js";

await migrateUp();
await mkdir("/data/access", { recursive: true });
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
	const list = await seed();
	const result = await internalAccessList.update(access, {
		id: list.id,
		items: [{ username: "original", password: "" }],
	});
	assert.equal(result.items.length, 1);
	assert.equal(result.items[0].password, "fixture-password-hash");
});
