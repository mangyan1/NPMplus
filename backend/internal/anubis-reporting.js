import { createHash, randomUUID } from "node:crypto";
import { open } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";
import db from "../db.js";
import { parsePrometheusText } from "../lib/crowdsec-contract.js";
import { debug, global as logger } from "../logger.js";
import ProxyHost from "../models/proxy_host.js";

const DIRECTORY = path.dirname(process.env.ANUBIS_HONEYPOT_LOG_FILE || "/data/anubis/honeypot.addrs");
const LIMIT = 512 * 1024;
const RETENTION = 7 * 86400_000;
const GAP = 150_000;
const BUCKET = 300_000;
const METRICS = {
	issued: "anubis_challenges_issued",
	validated: "anubis_challenges_validated",
	failed: "anubis_failed_validations",
};
const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonicalIp = (value) => {
	if (typeof value !== "string" || value.length > 45 || !/^[0-9a-fA-F.:]+$/.test(value)) return null;
	if (isIP(value) === 6) return new URL(`http://[${value}]`).hostname.slice(1, -1);
	return isIP(value) === 4 ? value : null;
};
const readFile = async (name, tail = false) => {
	const file = await open(path.join(DIRECTORY, name), "r");
	try {
		const stat = await file.stat();
		if (!tail && stat.size > LIMIT) throw new Error("Anubis observation too large");
		const start = tail ? Math.max(0, stat.size - LIMIT) : 0;
		const buffer = Buffer.alloc(Math.min(stat.size, LIMIT));
		const { bytesRead } = await file.read(buffer, 0, buffer.length, start);
		let text = buffer.toString("utf8", 0, bytesRead);
		if (start) text = text.includes("\n") ? text.slice(text.indexOf("\n") + 1) : "";
		return { text, time: stat.mtimeMs, truncated: start > 0 };
	} finally {
		await file.close();
	}
};
const getState = async (trx, id) => {
	const row = await trx("anubis_sample").where({ id }).first();
	return row ? JSON.parse(row.data) : null;
};
const setState = async (trx, id, time, data) =>
	trx("anubis_sample")
		.insert({ id, time, data: JSON.stringify(data) })
		.onConflict("id")
		.merge();

// Keep individual series baselines: a disappearing ASN/method series or restart
// must not be mistaken for a counter increase. Missing families stay unknown.
const recordMetrics = async (text, time, now = Date.now()) => {
	time = Math.trunc(time);
	if (!Number.isSafeInteger(time) || time < 0) throw new Error("Invalid Anubis sample time");
	if (now - time > GAP || time > now + 5000) throw new Error("Stale Anubis metrics");
	const samples = parsePrometheusText(text);
	const epoch = samples.find((sample) => sample.name === "process_start_time_seconds")?.value;
	if (!Number.isFinite(epoch) || epoch <= 0) throw new Error("Missing Anubis process epoch");
	const series = {};
	for (const [key, name] of Object.entries(METRICS)) {
		const matches = samples.filter((sample) => sample.name === name);
		if (matches.length > 2000) throw new Error("Too many Anubis metric series");
		series[key] = Object.fromEntries(
			matches.map((sample) => {
				if (!Number.isSafeInteger(sample.value) || sample.value < 0) throw new Error("Invalid Anubis counter");
				return [hash(JSON.stringify(Object.entries(sample.labels).sort())), sample.value];
			}),
		);
	}
	await db().transaction(async (trx) => {
		const previous = await getState(trx, "metrics");
		if (previous && time <= previous.time) return;
		const bucket = String(Math.floor(time / BUCKET) * BUCKET);
		const value = (await getState(trx, bucket)) ?? { totals: {}, covered: {}, incomplete: false };
		const continuous = previous && previous.epoch === epoch && time - previous.time <= GAP;
		for (const key of Object.keys(METRICS)) {
			const old = previous?.series[key] ?? {};
			const current = series[key];
			const valid =
				continuous &&
				Object.keys(current).length &&
				Object.keys(old).length &&
				Object.keys(old).every((id) => current[id] >= old[id]);
			if (valid) {
				const delta = Object.entries(current).reduce((sum, [id, count]) => sum + count - (old[id] ?? 0), 0);
				value.totals[key] = (value.totals[key] ?? 0) + delta;
				if (!Number.isSafeInteger(value.totals[key])) throw new Error("Anubis counter overflow");
				value.covered[key] = (value.covered[key] ?? 0) + time - previous.time;
			} else value.incomplete = true;
		}
		await setState(trx, bucket, time, value);
		await setState(trx, "metrics", time, { time, epoch, series });
	});
};

// Store first observation time, never an invented Anubis hit timestamp. Persist
// the complete prefix fingerprint and cursor in the same transaction as events.
const recordAddresses = async (text, now = Date.now()) => {
	const complete = text.slice(0, text.lastIndexOf("\n") + 1);
	await db().transaction(async (trx) => {
		const previous = await getState(trx, "addresses");
		const reset =
			previous &&
			(complete.length < previous.offset || hash(complete.slice(0, previous.offset)) !== previous.hash);
		const generation = reset || !previous ? randomUUID() : previous.generation;
		let offset = previous && !reset ? previous.offset : 0;
		const lines = complete.slice(offset).split("\n").slice(0, -1);
		const gap = Boolean(reset || (previous && now - previous.time > GAP));
		// Initial content is a baseline, not a burst of newly timed catches.
		if (previous) {
			for (const line of lines.slice(0, 1000)) {
				const ip = canonicalIp(line.trim());
				if (ip)
					await trx("anubis_event")
						.insert({ id: hash(`${generation}:${offset}`), time: now, ip, kind: "observed" })
						.onConflict("id")
						.ignore();
				offset += line.length + 1;
			}
		} else offset = complete.length;
		await setState(trx, "addresses", now, {
			time: now,
			generation,
			offset,
			hash: hash(complete.slice(0, offset)),
			gapAt: gap ? now : (previous?.gapAt ?? null),
			pending: offset < complete.length,
		});
	});
};
const recordAttempts = async (text, now = Date.now()) => {
	await db().transaction(async (trx) => {
		for (const line of text
			.slice(0, text.lastIndexOf("\n") + 1)
			.split("\n")
			.slice(-2001, -1)) {
			const match = /^(\d{13}) (accepted|failed) ([0-9a-fA-F.:]{2,45}) [a-f0-9-]{36}$/.exec(line);
			if (!match) continue;
			const time = Number(match[1]);
			const ip = canonicalIp(match[3]);
			if (!ip || time > now + 5000 || time < now - RETENTION) continue;
			await trx("anubis_event")
				.insert({ id: hash(line), time, ip, kind: match[2] })
				.onConflict("id")
				.ignore();
		}
		await setState(trx, "attempts", now, { time: now });
	});
};

const hostCoverage = async (page = 1) => {
	const query = ProxyHost.query().where("is_deleted", 0).where("enabled", 1);
	const count = await query.clone().resultSize();
	const hosts = await query
		.select("id", "domain_names", "npmplus_auth_request", "npmplus_auth_request_upstream", "locations")
		.orderBy("id")
		.limit(25)
		.offset((page - 1) * 25);
	return {
		total: count,
		page,
		items: hosts.map((host) => {
			const locations = (Array.isArray(host.locations) ? host.locations : []).map((location) => {
				const provider =
					!location.npmplus_auth_request || location.npmplus_auth_request === "none"
						? host.npmplus_auth_request
						: location.npmplus_auth_request;
				return {
					path: String(location.path ?? "/").slice(0, 200),
					anubis: provider === "anubis",
					customUpstream: Boolean(location.npmplus_auth_request_upstream),
				};
			});
			return {
				id: host.id,
				domains: host.domain_names.slice(0, 10),
				anubis: host.npmplus_auth_request === "anubis",
				customUpstream: Boolean(host.npmplus_auth_request_upstream),
				locations: locations.slice(0, 25),
				locationsTruncated: locations.length > 25,
			};
		}),
	};
};
const readReport = async (hours = 24, page = 1, hostPage = 1, now = Date.now()) => {
	const end = Math.floor(now / BUCKET) * BUCKET;
	const start = end - hours * 3600_000;
	const baseline = await getState(db(), "metrics");
	const addresses = await getState(db(), "addresses");
	const attempts = await getState(db(), "attempts");
	const rows = await db()("anubis_sample")
		.where("time", ">=", start)
		.where("time", "<", end)
		.whereNotIn("id", ["metrics", "addresses", "attempts"])
		.limit(2017);
	const totals = Object.fromEntries(Object.keys(METRICS).map((key) => [key, null]));
	const covered = {};
	for (const row of rows) {
		const data = JSON.parse(row.data);
		for (const key of Object.keys(METRICS)) {
			if (typeof data.totals[key] !== "number") continue;
			totals[key] = (totals[key] ?? 0) + data.totals[key];
			covered[key] = (covered[key] ?? 0) + data.covered[key];
		}
	}
	const eventsQuery = db()("anubis_event")
		.where("time", ">=", now - hours * 3600_000)
		.where("time", "<=", now);
	const count = Number((await eventsQuery.clone().count({ total: "id" }).first()).total);
	const events = await eventsQuery
		.clone()
		.orderBy("time", "desc")
		.orderBy("id")
		.limit(25)
		.offset((page - 1) * 25);
	return {
		metrics: {
			status: baseline
				? now - baseline.time > GAP || baseline.time > now + 5000
					? "stale"
					: "observed"
				: "unavailable",
			observedAt: baseline ? new Date(baseline.time).toISOString() : null,
			start: new Date(start).toISOString(),
			end: new Date(end).toISOString(),
			totals,
			partial: Object.keys(METRICS).some((key) => (covered[key] ?? 0) < end - start),
		},
		ledger: {
			status: addresses
				? now - addresses.time > GAP || addresses.time > now + 5000
					? "stale"
					: "observed"
				: "unavailable",
			attemptsStatus: attempts
				? now - attempts.time > GAP || attempts.time > now + 5000
					? "stale"
					: "observed"
				: "unavailable",
			observedAt: addresses ? new Date(addresses.time).toISOString() : null,
			gap: Boolean(addresses?.gapAt && addresses.gapAt >= now - hours * 3600_000),
			pending: addresses?.pending ?? false,
			total: count,
			page,
			items: events.map((event) => ({ ...event, time: new Date(Number(event.time)).toISOString() })),
		},
		coverage: await hostCoverage(hostPage),
	};
};
let running = false;
const collectAnubis = async () => {
	if (running) return;
	running = true;
	try {
		for (const [name, ingest, tail] of [
			["anubis-metrics.prom", recordMetrics, false],
			["honeypot.addrs", recordAddresses, false],
			["honeypot-attempts.log", recordAttempts, true],
		]) {
			try {
				const file = await readFile(name, tail);
				await ingest(file.text, name === "anubis-metrics.prom" ? file.time : Date.now());
			} catch (err) {
				debug(logger, `Anubis reporting ${name}: ${err.message}`);
			}
		}
		await db()("anubis_event")
			.where("time", "<", Date.now() - RETENTION)
			.delete();
		const boundary = await db()("anubis_event").orderBy("time", "desc").orderBy("id", "desc").offset(19999).first();
		if (boundary)
			await db()("anubis_event")
				.where((query) =>
					query
						.where("time", "<", boundary.time)
						.orWhere((same) => same.where("time", boundary.time).where("id", "<", boundary.id)),
				)
				.delete();
		await db()("anubis_sample")
			.whereNotIn("id", ["metrics", "addresses", "attempts"])
			.where("time", "<", Date.now() - RETENTION - BUCKET)
			.delete();
	} catch (err) {
		debug(logger, `Anubis reporting collection: ${err.message}`);
	} finally {
		running = false;
	}
};

export { canonicalIp, collectAnubis, hostCoverage, readReport, recordAddresses, recordAttempts, recordMetrics };
