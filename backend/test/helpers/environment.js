// Import before application modules. Each test worker owns a fresh filesystem
// tree; no test may reuse the container's database, keys or generated files.
import fs from "node:fs";
import fsp from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after } from "node:test";

const root = fs.mkdtempSync(path.join(tmpdir(), "npmplus-test-"));
const originalRm = fsp.rm.bind(fsp);
const isolatedPath = (value) => {
	if (typeof value !== "string") return value;
	if (
		["/data", "/usr/local/nginx", "/tmp/certbot-credentials"].some(
			(prefix) => value === prefix || value.startsWith(`${prefix}/`),
		)
	) {
		return path.join(root, value.slice(1));
	}
	return value;
};

process.env.NODE_ENV = "test";
process.env.NPMPLUS_TEST_ROOT = root;
// A developer's external database configuration must not leak into tests.
for (const key of Object.keys(process.env)) {
	if (key.startsWith("DB_MYSQL_") || key.startsWith("DB_POSTGRES_")) delete process.env[key];
}
fs.mkdirSync(path.join(root, "data/npmplus"), { recursive: true });

// Keep production paths and certificate command arguments intact while real
// filesystem operations run inside this worker's temporary tree. SQLite's
// native driver uses the explicit test database path from lib/config.js.
for (const [target, names] of [
	[fs, ["existsSync", "readFileSync", "writeFileSync", "mkdirSync", "rmSync", "statSync"]],
	[fsp, ["readFile", "writeFile", "mkdir", "rm", "readdir", "stat", "access", "open", "unlink"]],
]) {
	for (const name of names) {
		const original = target[name].bind(target);
		target[name] = (filename, ...args) => original(isolatedPath(filename), ...args);
	}
}
const originalRename = fsp.rename.bind(fsp);
fsp.rename = (source, destination) => originalRename(isolatedPath(source), isolatedPath(destination));
syncBuiltinESMExports();

// Registered at import time, cleanup runs after each file's tests; close the
// database before removal even if a test fails during initialization.
const cleanup = async () => {
	const { default: db } = await import("../../db.js");
	await db().destroy();
	await originalRm(root, { recursive: true, force: true });
};
after(cleanup);

export { cleanup, isolatedPath, root };
