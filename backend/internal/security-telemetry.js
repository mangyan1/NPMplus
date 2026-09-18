import { open } from "node:fs/promises";
import http from "node:http";
import db from "../db.js";
import { clearOutage, global as logger, reportOutage } from "../logger.js";
import ProxyHost from "../models/proxy_host.js";
import { collectAnubis } from "./anubis-reporting.js";

const BUCKET = 300_000;
const RETENTION = 7 * 24 * 3600_000;
const MAX_GAP = 150_000;
const MAX_BYTES = 256 * 1024;
const COUNTERS = ["checks", "inspected", "errors", "unreadable", "bans", "waf_bans", "challenges"];
const FIREWALL_COUNTERS = ["input_packets", "forward_packets", "input_bytes", "forward_bytes"];
const empty = (names = COUNTERS) => Object.fromEntries(names.map((key) => [key, 0]));
const validCounters = (values, names) => names.every((key) => Number.isSafeInteger(values?.[key]) && values[key] >= 0);
// The exporter refuses with a stable code when nginx has no CrowdSec bouncer
// installed. That is a supported configuration, not a fault, so the reading
// becomes the disabled state. Anything else - other codes, prose, an unreadable
// body - stays a read failure and is reported as unavailable.
const DISABLED_REASON = "bouncer-not-installed";
const refusalState = (body) => {
	try {
		return JSON.parse(body).reason === DISABLED_REASON ? { disabled: true } : null;
	} catch {
		return null;
	}
};
const readNginx = () =>
	new Promise((resolve, reject) => {
		const request = http.get(
			{ socketPath: "/run/npmplus-telemetry.sock", path: "/", timeout: 3000 },
			(response) => {
				let size = 0;
				const chunks = [];
				response.on("data", (chunk) => {
					size += chunk.length;
					if (size > MAX_BYTES) request.destroy(new Error("Telemetry response too large"));
					else chunks.push(chunk);
				});
				response.on("error", reject);
				response.on("end", () => {
					const body = Buffer.concat(chunks).toString("utf8");
					try {
						if (response.statusCode !== 200) {
							const state = refusalState(body);
							if (!state) throw new Error("Telemetry unavailable");
							resolve(state);
							return;
						}
						resolve(JSON.parse(body));
					} catch (err) {
						reject(err);
					}
				});
			},
		);
		const deadline = setTimeout(() => request.destroy(new Error("Telemetry timeout")), 3000);
		request.on("close", () => clearTimeout(deadline));
		request.on("timeout", () => request.destroy(new Error("Telemetry timeout")));
		request.on("error", reject);
	});
const readFirewall = async () => {
	const file = await open("/data/crowdsec/firewall-telemetry.json", "r");
	try {
		if ((await file.stat()).size > MAX_BYTES) throw new Error("Firewall snapshot too large");
		return JSON.parse(await file.readFile("utf8"));
	} finally {
		await file.close();
	}
};

// Persist counters and their baselines together; restarting the backend cannot
// replay a delta. Missing intervals and epoch resets are never invented as zero.
const recordSnapshot = async (source, raw, now = Date.now()) => {
	const nginx = source === "nginx";
	const names = nginx ? COUNTERS : FIREWALL_COUNTERS;
	// A disabled source observed nothing, so no counters are invented and no
	// interval is credited as covered. The reading still has to be persisted:
	// the API answers from stored rows, and only a fresh reading can tell
	// "switched off on purpose" from "not answering", so the marker is replaced
	// by the next real snapshot and ages into stale like any other row.
	if (nginx && raw?.disabled === true) {
		await db()("security_telemetry")
			.insert({ source, bucket: -1, data: JSON.stringify({ time: now, disabled: true }) })
			.onConflict(["source", "bucket"])
			.merge();
		return;
	}
	const time = nginx ? now : raw.collected_at;
	if (
		!raw ||
		typeof raw.epoch !== "string" ||
		raw.epoch.length > 128 ||
		!raw.epoch ||
		!Number.isSafeInteger(time) ||
		time > now + 5000 ||
		now - time > MAX_GAP
	)
		throw new Error("Invalid telemetry timestamp/epoch");
	const hosts = nginx ? raw.hosts : [{ id: 0, counters: raw.counters }];
	if (
		!Array.isArray(hosts) ||
		hosts.length > 200 ||
		new Set(hosts.map((host) => host.id)).size !== hosts.length ||
		hosts.some(
			(host) =>
				!Number.isSafeInteger(host.id) || host.id < (nginx ? 1 : 0) || !validCounters(host.counters, names),
		)
	)
		throw new Error("Invalid telemetry counters");
	const snapshot = {
		time,
		epoch: raw.epoch,
		hosts: hosts.map((host) => ({
			id: host.id,
			counters: Object.fromEntries(names.map((name) => [name, host.counters[name]])),
		})),
		overflow: nginx ? raw.overflow !== 0 : false,
		service_active: nginx ? null : raw.service_active === true,
		input_rule: nginx ? null : raw.input_rule === true,
		forward_rule: nginx ? null : raw.forward_rule === true,
	};
	await db().transaction(async (trx) => {
		const previousRow = await trx("security_telemetry").where({ source, bucket: -1 }).first();
		const previous = previousRow ? JSON.parse(previousRow.data) : null;
		if (previous && time <= previous.time) return;
		// A disabled marker keeps no counter baseline: resuming inside the accepted
		// interval must not read the bouncer's whole cumulative counters as a delta.
		// The marker carries no epoch, so this also holds by construction.
		const continuous =
			previous && !previous.disabled && previous.epoch === snapshot.epoch && time - previous.time <= MAX_GAP;
		const start = Math.floor((time - 1) / BUCKET) * BUCKET;
		const bucketRow = await trx("security_telemetry").where({ source, bucket: start }).first();
		const bucket = bucketRow ? JSON.parse(bucketRow.data) : { covered_ms: 0, hosts: {}, incomplete: false };
		bucket.incomplete ||= !continuous || snapshot.overflow;
		if (continuous) {
			// Do not split a counter delta across a boundary using invented traffic
			// timing. Assign it to the ending bucket, with capped interval coverage.
			bucket.covered_ms = Math.min(BUCKET, bucket.covered_ms + time - previous.time);
			for (const host of hosts) {
				const before = previous.hosts.find((item) => item.id === host.id)?.counters ?? empty(names);
				if (names.some((name) => host.counters[name] < before[name])) {
					bucket.incomplete = true;
					continue;
				}
				const values = bucket.hosts[host.id] ?? empty(names);
				for (const name of names) values[name] += host.counters[name] - before[name];
				bucket.hosts[host.id] = values;
			}
		}
		await trx("security_telemetry")
			.insert({ source, bucket: start, data: JSON.stringify(bucket) })
			.onConflict(["source", "bucket"])
			.merge();
		await trx("security_telemetry")
			.insert({ source, bucket: -1, data: JSON.stringify(snapshot) })
			.onConflict(["source", "bucket"])
			.merge();
		await trx("security_telemetry")
			.where("bucket", ">=", 0)
			.where("bucket", "<", now - RETENTION - BUCKET)
			.delete();
	});
};

const readTelemetry = async (hours = 24, now = Date.now()) => {
	const end = Math.floor(now / BUCKET) * BUCKET;
	const start = end - hours * 3600_000;
	const rows = await db()("security_telemetry")
		.where((query) =>
			query.where("bucket", -1).orWhere((q) => q.where("bucket", ">=", start).where("bucket", "<", end)),
		)
		.limit(4040);
	const result = {
		window_hours: hours,
		start: new Date(start).toISOString(),
		end: new Date(end).toISOString(),
		bucket_minutes: 5,
		nginx: {
			status: "unavailable",
			observed_at: null,
			covered_ms: 0,
			incomplete: false,
			totals: empty(),
			hosts: [],
		},
		firewall: {
			status: "unavailable",
			observed_at: null,
			covered_ms: 0,
			incomplete: false,
			totals: empty(FIREWALL_COUNTERS),
			service_active: null,
			input_rule: null,
			forward_rule: null,
		},
	};
	const hostCounts = new Map();
	for (const row of rows) {
		const layer = result[row.source];
		if (!layer) continue;
		const value = JSON.parse(row.data);
		if (Number(row.bucket) === -1) {
			// A disabled source was never observed: it keeps null timestamps and says
			// only why. It still ages, so reads that start failing again cannot leave
			// "switched off" on the dashboard forever.
			if (value.disabled === true) {
				layer.status = now - value.time > MAX_GAP ? "stale" : "disabled";
				continue;
			}
			layer.observed_at = new Date(value.time).toISOString();
			layer.status = now - value.time > MAX_GAP || value.time > now + 5000 ? "stale" : "observed";
			if (row.source === "firewall")
				for (const key of ["service_active", "input_rule", "forward_rule"]) layer[key] = value[key];
			continue;
		}
		layer.covered_ms += value.covered_ms;
		layer.incomplete ||= value.incomplete;
		for (const [id, counters] of Object.entries(value.hosts)) {
			for (const key of Object.keys(layer.totals)) layer.totals[key] += counters[key] ?? 0;
			if (row.source === "nginx") {
				const host = hostCounts.get(id) ?? { id: Number(id), counters: empty() };
				for (const key of COUNTERS) host.counters[key] += counters[key] ?? 0;
				hostCounts.set(id, host);
			}
		}
	}
	const selected = [...hostCounts.values()]
		.sort((a, b) => b.counters.waf_bans - a.counters.waf_bans || a.id - b.id)
		.slice(0, 200);
	const hosts =
		selected.length > 0
			? await ProxyHost.query()
					.select("id", "domain_names")
					.whereIn(
						"id",
						selected.map((host) => host.id),
					)
					.where("is_deleted", 0)
			: [];
	result.nginx.hosts = selected.map((host) => ({
		...host,
		domains: hosts.find((item) => item.id === host.id)?.domain_names ?? [],
	}));
	result.nginx.hosts_truncated = hostCounts.size > selected.length;
	for (const layer of [result.nginx, result.firewall]) layer.incomplete ||= layer.covered_ms < end - start;
	return result;
};

let timer;
let running = false;
const collect = async () => {
	if (running) return;
	running = true;
	try {
		await collectAnubis();
		for (const [source, read] of [
			["nginx", readNginx],
			["firewall", readFirewall],
		]) {
			try {
				await recordSnapshot(source, await read());
				// a source that is not installed at all - no host firewall
				// observer, or nginx without the CrowdSec bouncer - would fail
				// on every one of these 60s ticks
				clearOutage(`telemetry:${source}`);
			} catch (err) {
				reportOutage(`telemetry:${source}`, logger, `Security telemetry ${source}: ${err.message}`);
			}
		}
	} finally {
		running = false;
	}
};
const startTelemetry = () => {
	if (timer) return;
	void collect();
	timer = setInterval(() => void collect(), 60_000);
	timer.unref();
};

export { readTelemetry, recordSnapshot, refusalState, startTelemetry };
