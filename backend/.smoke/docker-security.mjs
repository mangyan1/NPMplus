// Disposable Docker integration target; run from the repository root after building the image.
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const image = process.env.NPMPLUS_TEST_IMAGE || "npmplus:security-ci";
const prefix = `npmplus-security-${randomUUID().slice(0, 8)}`;
const containers = [];
const volumes = [];
const docker = (...args) => execFileSync("docker", args, { encoding: "utf8" }).trim();
const start = async (kind, env) => {
	const name = `${prefix}-${kind}`;
	const volume = `${name}-data`;
	containers.push(name);
	volumes.push(volume);
	docker(
		"run",
		"-d",
		"--name",
		name,
		"--label",
		"npmplus.test=security",
		"-p",
		"127.0.0.1::81",
		"--mount",
		`type=volume,source=${volume},target=/data`,
		"-e",
		"TZ=UTC",
		...env.flatMap((value) => ["-e", value]),
		image,
	);
	for (let attempt = 0; attempt < 90; attempt++) {
		const [state] = JSON.parse(docker("inspect", name));
		if (state.State.Health?.Status === "healthy") {
			const port = state.NetworkSettings.Ports["81/tcp"][0].HostPort;
			console.log(`Ready: ${kind}`);
			return `https://127.0.0.1:${port}`;
		}
		if (!state.State.Running || state.State.Health?.Status === "unhealthy") break;
		await delay(2000);
	}
	throw new Error(`${kind} container did not become healthy`);
};
const run = (script, base) => {
	const result = spawnSync(process.execPath, [`backend/.smoke/${script}`], {
		stdio: "inherit",
		env: {
			...process.env,
			SMOKE_BASE_URL: base,
			SMOKE_ADMIN_EMAIL: "admin@example.test",
			SMOKE_ADMIN_PASSWORD: "rc5-smoke-password",
			SMOKE_SETUP_TOKEN: "local-security-setup-token-20260919-only",
		},
		timeout: 180000,
	});
	if (result.error || result.status !== 0) throw new Error(`${script} failed`, { cause: result.error });
};
try {
	const api = await start("api", [
		"INITIAL_ADMIN_EMAIL=admin@example.test",
		"INITIAL_ADMIN_PASSWORD=rc5-smoke-password",
	]);
	run("security-regressions.mjs", api);
	run("modal-ui.mjs", api);
	const setup = await start("setup", ["INITIAL_SETUP_TOKEN=local-security-setup-token-20260919-only"]);
	run("security-ui.mjs", setup);
	console.log("PASS Docker security and browser integration");
} finally {
	for (const name of containers) {
		const result = spawnSync("docker", ["rm", "-f", name], { encoding: "utf8" });
		if (result.status !== 0) console.error(`Container cleanup failed: ${name}`);
	}
	for (const volume of volumes) {
		const result = spawnSync("docker", ["volume", "rm", volume], { encoding: "utf8" });
		if (result.status !== 0) console.error(`Volume cleanup failed: ${volume}`);
	}
}
