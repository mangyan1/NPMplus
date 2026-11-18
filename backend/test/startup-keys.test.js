import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The fork keeps the ES512 JWT key pair in keys-ec.json; upstream's Ed25519
// migration deletes that path on startup. Removing it invalidates every
// session at each container restart, so pin the fork behaviour.
test("startup keeps the fork's EC signing key file", () => {
	const script = readFileSync(new URL("../../rootfs/usr/local/bin/start.sh", import.meta.url), "utf8");
	assert.ok(
		!script.includes("/data/npmplus/keys-ec.json"),
		"start.sh must not delete /data/npmplus/keys-ec.json",
	);
});
