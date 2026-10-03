import "./helpers/environment.js";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createCrsControl } from "../internal/crs-control.js";

const fixture = async (t, reply) => {
	const directory = await mkdtemp(path.join(os.tmpdir(), "npmplus-crs-"));
	const socketPath = path.join(directory, "control.sock");
	const verbs = [];
	const connections = [];
	const server = net.createServer((socket) => {
		connections.push(socket);
		socket.on("error", () => {});
		socket.once("data", (data) => {
			verbs.push(data.toString());
			if (reply === null) return;
			socket.end(reply);
		});
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});
	t.after(async () => {
		for (const connection of connections) connection.destroy();
		await new Promise((resolve) => server.close(resolve));
		await rm(directory, { recursive: true, force: true });
	});
	return { client: createCrsControl(socketPath), verbs };
};

test("CRS control uses fixed verbs and sanitizes host status", async (t) => {
	const { client, verbs } = await fixture(
		t,
		`${JSON.stringify({ version: 1, available: true, eligible: true, enabled: false, state: "idle", retry_after: 999, key: "fixture-secret", path: "/root" })}\n`,
	);
	assert.deepEqual(await client.status(), {
		available: true,
		eligible: true,
		enabled: false,
		state: "idle",
		retry_after: 300,
	});
	assert.deepEqual(verbs, ["STATUS\n"]);
});

test("CRS control activation cannot forward caller arguments", async (t) => {
	const { client, verbs } = await fixture(t, '{"accepted":true,"state":"running","output":"not-public"}\n');
	assert.deepEqual(await client.enable({ command: "not-a-command" }), { accepted: true, state: "running" });
	assert.deepEqual(verbs, ["ENABLE\n"]);
});

test("CRS control deactivation uses its fixed verb and bounded states", async (t) => {
	const { client, verbs } = await fixture(t, '{"accepted":true,"state":"running","output":"not-public"}\n');
	assert.deepEqual(await client.disable(), { accepted: true, state: "running" });
	assert.deepEqual(verbs, ["DISABLE\n"]);
	const idle = await fixture(t, '{"accepted":true,"state":"idle"}\n');
	assert.deepEqual(await idle.client.disable(), { accepted: true, state: "idle" });
	const refused = await fixture(t, '{"accepted":false,"reason":"unsupported"}\n');
	await assert.rejects(refused.client.disable(), { status: 409, message: "crowdsec.crs.control-unsupported" });
});

test("CRS control rejects oversized, partial and malformed responses", async (t) => {
	for (const reply of ["x".repeat(1025), '{"available":true}', "invalid\n", '{"accepted":true,"state":"shell"}\n']) {
		await t.test(reply.slice(0, 30), async (sub) => {
			const { client } = await fixture(sub, reply);
			assert.equal((await client.status()).available, false);
			await assert.rejects(client.enable(), { status: 503, message: "crowdsec.crs.control-unavailable" });
		});
	}
});

test("CRS control reports persistent host cooldown without exposing output", async (t) => {
	const { client } = await fixture(t, '{"accepted":false,"reason":"cooldown","output":"not-public"}\n');
	await assert.rejects(client.enable(), { status: 429, message: "crowdsec.crs.control-cooldown" });
});

test("a hung CRS helper becomes unavailable within the request budget", { timeout: 5000 }, async (t) => {
	const { client } = await fixture(t, null);
	const start = Date.now();
	assert.equal((await client.status()).available, false);
	assert.ok(Date.now() - start < 4500);
});
