import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import test from "node:test";
import db from "../db.js";
import internalAudit from "../internal/audit-log.js";
import internalNginx from "../internal/nginx.js";
import internalSetting from "../internal/setting.js";
import { migrateUp } from "../migrate.js";
import Setting from "../models/setting.js";

await migrateUp();
const configPath = "/usr/local/nginx/conf/conf.d/default.conf";
const htmlPath = "/data/html/index.html";
const originalHtml = "<p>Previous page</p>";
const originalConfig = "previous valid config";
const access = { canAdmin() {}, token: { getUserId: () => 1 } };
const original = {
	id: "default-site",
	name: "Default Site",
	description: "Default",
	value: "html",
	meta: { html: originalHtml, status: 404 },
};
const candidate = { id: "default-site", value: "html", meta: { html: "<p>Replacement page</p>", status: 200 } };

const seed = async (t) => {
	await Setting.query().delete();
	await db()("audit_log").delete();
	await Setting.query().insert(original);
	await mkdir("/usr/local/nginx/conf/conf.d", { recursive: true });
	await mkdir("/data/html", { recursive: true });
	await writeFile(configPath, originalConfig);
	await writeFile(htmlPath, originalHtml);
	t.mock.method(internalNginx, "generateConfig", async () => writeFile(configPath, "candidate config"));
	t.mock.method(internalNginx, "test", async () => {});
	t.mock.method(internalNginx, "reload", async () => {});
};

const restoredState = async () => {
	const row = await Setting.query().findById("default-site");
	return {
		value: row.value,
		meta: row.meta,
		config: await readFile(configPath, "utf8"),
		html: await readFile(htmlPath, "utf8"),
		audits: (await db()("audit_log").count("id as count").first()).count,
	};
};
const previousState = {
	value: original.value,
	meta: original.meta,
	config: originalConfig,
	html: originalHtml,
	audits: 0,
};

test("default-site success persists settings and one audit event after reload", async (t) => {
	await seed(t);
	t.mock.method(internalNginx, "reload", async () => {
		assert.deepEqual((await Setting.query().findById("default-site")).meta, original.meta);
		assert.equal((await db()("audit_log").count("id as count").first()).count, 0);
	});
	const row = await internalSetting.update(access, candidate);
	assert.deepEqual(row.meta, candidate.meta);
	assert.equal(await readFile(htmlPath, "utf8"), candidate.meta.html);
	assert.equal((await db()("audit_log").count("id as count").first()).count, 1);
});

for (const stage of ["generateConfig", "test", "reload"]) {
	test(`default-site ${stage} failure restores database, HTML, config and audit state`, async (t) => {
		await seed(t);
		let attempts = 0;
		t.mock.method(internalNginx, stage, async () => {
			if (++attempts === 1) throw new Error(`rejected ${stage}`);
		});
		await assert.rejects(internalSetting.update(access, candidate), /Could not reconfigure/);
		assert.deepEqual(await restoredState(), previousState);
	});
}

test("a failed default-site audit insertion rolls back database and restored files", async (t) => {
	await seed(t);
	t.mock.method(internalAudit, "add", async () => {
		throw new Error("rejected audit");
	});
	await assert.rejects(internalSetting.update(access, candidate));
	assert.deepEqual(await restoredState(), previousState);
});

test("default-site database failure restores the previous serving configuration", async (t) => {
	await seed(t);
	await db().raw(
		"CREATE TRIGGER reject_setting BEFORE UPDATE ON setting BEGIN SELECT RAISE(ABORT, 'rejected setting'); END",
	);
	try {
		await assert.rejects(internalSetting.update(access, candidate));
		assert.deepEqual(await restoredState(), previousState);
	} finally {
		await db().raw("DROP TRIGGER reject_setting");
	}
});

test("default-site recovery failure is internal and does not claim successful restoration", async (t) => {
	await seed(t);
	t.mock.method(internalNginx, "test", async () => {
		throw new Error("invalid candidate");
	});
	t.mock.method(internalNginx, "reload", async () => {
		throw new Error("recovery reload failed");
	});
	await assert.rejects(internalSetting.update(access, candidate), (error) => {
		assert.ok(!error.public);
		return true;
	});
	assert.deepEqual(await restoredState(), previousState);
});

test("concurrent default-site updates cannot restore over the preceding successful update", async (t) => {
	await seed(t);
	let release;
	let entered;
	const hold = new Promise((resolve) => {
		release = resolve;
	});
	const started = new Promise((resolve) => {
		entered = resolve;
	});
	let generations = 0;
	t.mock.method(internalNginx, "generateConfig", async () => {
		generations++;
		await writeFile(configPath, `candidate ${generations}`);
		if (generations === 1) {
			entered();
			await hold;
		}
	});
	let validations = 0;
	t.mock.method(internalNginx, "test", async () => {
		if (++validations === 2) throw new Error("second rejected");
	});
	const first = internalSetting.update(access, candidate);
	await started;
	const second = internalSetting.update(access, { ...candidate, meta: { html: "second page", status: 200 } });
	const rejected = assert.rejects(second, /Could not reconfigure/);
	await new Promise((resolve) => setTimeout(resolve, 100));
	const simultaneousGenerations = generations;
	release();
	await first;
	await rejected;
	assert.equal(simultaneousGenerations, 1);
	assert.deepEqual(await restoredState(), {
		value: candidate.value,
		meta: candidate.meta,
		config: "candidate 1",
		html: candidate.meta.html,
		audits: 1,
	});
});

test("failed default-site creation restores originally absent files", async (t) => {
	await seed(t);
	await rm(configPath);
	await rm(htmlPath);
	let attempts = 0;
	t.mock.method(internalNginx, "test", async () => {
		if (++attempts === 1) throw new Error("invalid candidate");
	});
	await assert.rejects(internalSetting.update(access, candidate), /Could not reconfigure/);
	await assert.rejects(readFile(configPath), { code: "ENOENT" });
	await assert.rejects(readFile(htmlPath), { code: "ENOENT" });
	assert.deepEqual((await Setting.query().findById("default-site")).meta, original.meta);
});
