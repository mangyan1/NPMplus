import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdir, rm, writeFile } from "node:fs/promises";
import test from "node:test";
import { readAppsecConfiguration } from "../internal/crowdsec.js";

test("CRS installer choice is non-secret and does not imply live rule loading", async () => {
	await mkdir("/data/crowdsec", { recursive: true });
	const path = "/data/crowdsec/crowdsec.conf";
	await writeFile(
		path,
		"APPSEC_URL=http://private:7422\nAPI_KEY=fixture-secret\nAPPSEC_FAILURE_ACTION=deny\n# NPMPLUS_CRS_MODE=observe\n",
	);
	const configuration = await readAppsecConfiguration();
	assert.equal(configuration.crs_installer_mode, "observe");
	assert.equal(configuration.appsec_configured, true);
	assert.equal(configuration.appsec_failure_action, "deny");
	assert.equal(JSON.stringify(configuration).includes("fixture-secret"), false);
	assert.equal(JSON.stringify(configuration).includes("private"), false);
	// biome-ignore lint/security/noSecrets: non-secret bouncer switches in a temporary test file
	await writeFile(path, "APPSEC_URL=\n# NPMPLUS_CRS_MODE=blocking\n");
	assert.equal((await readAppsecConfiguration()).crs_installer_mode, null);
	await rm(path);
	assert.equal((await readAppsecConfiguration()).crs_installer_mode, null);
});
