import "./helpers/environment.js";
import assert from "node:assert/strict";
import { access, mkdir, readFile } from "node:fs/promises";
import test from "node:test";
import db from "../db.js";
import internalNginx from "../internal/nginx.js";
import { getEnvironmentHash } from "../lib/environment-hash.js";
import utils from "../lib/utils.js";
import { migrateUp } from "../migrate.js";
import DeadHost from "../models/dead_host.js";
import ProxyHost from "../models/proxy_host.js";
import RedirectionHost from "../models/redirection_host.js";
import Stream from "../models/stream.js";
import User from "../models/user.js";
import setup from "../setup.js";

test("startup regenerates existing enabled hosts of every type before completing", async (t) => {
	await migrateUp();
	for (const directory of ["proxy_host", "redirection_host", "dead_host", "stream", "default"]) {
		await mkdir(`/data/nginx/${directory}`, { recursive: true });
	}
	await mkdir("/usr/local/nginx/conf/conf.d", { recursive: true });
	await mkdir("/data/access/temp", { recursive: true });
	const user = await User.query().insertAndFetch({
		name: "Existing administrator",
		email: "startup@example.test",
		nickname: "fixture",
		avatar: "",
		roles: ["admin"],
	});
	const proxy = {
		owner_user_id: user.id,
		domain_names: ["existing-proxy.example.test"],
		forward_scheme: "http",
		forward_host: "127.0.0.1",
		forward_port: 8080,
		enabled: true,
	};
	const hosts = [
		[ProxyHost, "proxy_host", await ProxyHost.query().insertAndFetch(proxy)],
		[
			RedirectionHost,
			"redirection_host",
			await RedirectionHost.query().insertAndFetch({
				owner_user_id: user.id,
				domain_names: ["existing-redirect.example.test"],
				forward_scheme: "https",
				forward_domain_name: "destination.example.test",
				forward_http_code: 301,
				enabled: true,
			}),
		],
		[
			DeadHost,
			"dead_host",
			await DeadHost.query().insertAndFetch({
				owner_user_id: user.id,
				domain_names: ["existing-dead.example.test"],
				enabled: true,
			}),
		],
		[
			Stream,
			"stream",
			await Stream.query().insertAndFetch({
				owner_user_id: user.id,
				incoming_port: 41000,
				forwarding_host: "127.0.0.1",
				forwarding_port: 8443,
				tcp_forwarding: true,
				udp_forwarding: false,
				enabled: true,
			}),
		],
	];
	const disabled = await ProxyHost.query().insertAndFetch({
		...proxy,
		domain_names: ["disabled.example.test"],
		enabled: false,
	});
	const deleted = await ProxyHost.query().insertAndFetch({ ...proxy, domain_names: ["deleted.example.test"] });
	await db()("proxy_host").where("id", deleted.id).update({ is_deleted: 1 });
	const previous = process.env.REGENERATE_ALL;
	process.env.REGENERATE_ALL = "true";
	t.after(() => {
		if (previous === undefined) delete process.env.REGENERATE_ALL;
		else process.env.REGENERATE_ALL = previous;
	});
	// Keep real queries, template rendering, file generation and online-status
	// persistence. Only the external nginx/formatter processes are substituted.
	t.mock.method(utils, "execFile", async () => "");
	const reload = t.mock.method(internalNginx, "reload", async () => {});
	await setup();
	for (const [model, type, host] of hosts) {
		const config = await readFile(internalNginx.getConfigName(type, host.id), "utf8");
		assert.ok(config.includes(type === "stream" ? "41000" : host.domain_names[0]), type);
		assert.equal((await model.query().findById(host.id)).npmplus_nginx_online, true, type);
	}
	for (const host of [disabled, deleted]) {
		await assert.rejects(access(internalNginx.getConfigName("proxy_host", host.id)), { code: "ENOENT" });
	}
	assert.equal(reload.mock.callCount(), 1);
	assert.equal(await readFile("/data/npmplus/env.sha512sum", "utf8"), await getEnvironmentHash());
});
