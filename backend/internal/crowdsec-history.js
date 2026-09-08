import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { filterCrowdsecAlerts, isAttackAlert, normalizeCrowdsecAlerts } from "../lib/crowdsec-contract.js";
import { lapiMachineFetch, publicError, readCrowdsecJson } from "./crowdsec.js";

const secret = randomBytes(32);
const sign = (text) => createHmac("sha256", secret).update(text).digest("base64url");
const encode = (value) => {
	const text = Buffer.from(JSON.stringify(value)).toString("base64url");
	return `${text}.${sign(text)}`;
};
// Preserve sub-millisecond CreatedAt ordering from the LAPI's RFC3339 timestamps.
const timestamp = (value) => {
	const millis = Date.parse(value);
	if (!Number.isFinite(millis)) throw publicError("crowdsec.invalid-response", 502);
	const fraction = /\.(\d+)(?:Z|[+-]\d\d:\d\d)$/.exec(value)?.[1] ?? "";
	return BigInt(millis) * 1_000_000n + BigInt(fraction.slice(3, 9).padEnd(6, "0"));
};
const decode = (cursor, binding, now) => {
	try {
		if (typeof cursor !== "string" || cursor.length > 2048) throw new Error("cursor");
		const parts = cursor.split(".");
		if (parts.length !== 2) throw new Error("cursor");
		const [text, mac] = parts;
		if (!mac || !timingSafeEqual(Buffer.from(mac), Buffer.from(sign(text)))) throw new Error("signature");
		const value = JSON.parse(Buffer.from(text, "base64url").toString("utf8"));
		if (value.binding !== binding || now - value.end > 3600_000 || now < value.end || value.step >= 100)
			throw new Error("expired");
		return value;
	} catch {
		throw publicError("crowdsec.history.cursor-invalid", 400);
	}
};

// One user-requested batch, no unbounded loop or background alert database.
const scanAlertHistory = async ({ windowHours, filters, cursor = "", now = Date.now() }) => {
	const binding = sign(JSON.stringify({ windowHours, filters }));
	const state = cursor
		? decode(cursor, binding, now)
		: {
				start: now - windowHours * 3600_000,
				end: now,
				before: String(BigInt(now) * 1_000_000n),
				id: Number.MAX_SAFE_INTEGER,
				step: 0,
				binding,
			};
	let limit = 101;
	const params = new URLSearchParams({
		since: `${now - state.start + 1000}ms`,
		// LAPI accepts durations, not an absolute timestamp. Deliberately overlap
		// one second, then enforce the exact cursor locally. Never skip ties.
		created_before: `${Math.max(0, now - Number(BigInt(state.before) / 1_000_000n) - 1000)}ms`,
		limit: String(limit),
		sort: "DESC",
		with_decisions: "false",
	});
	const read = () =>
		lapiMachineFetch(`/v1/alerts?${params}`, "GET", true, {
			readJson: (response) => readCrowdsecJson(response, limit === 101 ? 12 * 1024 * 1024 : 4 * 1024 * 1024),
		});
	let payload;
	try {
		payload = await read();
	} catch (err) {
		if (err?.message !== "crowdsec.invalid-response") throw err;
		limit = 25;
		params.set("limit", String(limit));
		payload = await read();
	}
	let raw;
	try {
		raw = normalizeCrowdsecAlerts(payload);
	} catch {
		throw publicError("crowdsec.invalid-response", 502);
	}
	if (raw.length > limit) throw publicError("crowdsec.invalid-response", 502);
	const before = BigInt(state.before);
	const candidates = raw
		.map((alert) => ({ alert, time: timestamp(alert.created_at) }))
		.filter(({ alert, time }) => time < before || (time === before && alert.id < state.id))
		.sort((a, b) => (a.time === b.time ? b.alert.id - a.alert.id : a.time > b.time ? -1 : 1));
	const batch = candidates.slice(0, 25);
	const more = candidates.length > batch.length || raw.length === limit;
	const blocked = more && (batch.length === 0 || state.step + 1 >= 100);
	const last = batch.at(-1);
	const next =
		more && !blocked && last
			? encode({ ...state, before: String(last.time), id: last.alert.id, step: state.step + 1 })
			: null;
	const items = filterCrowdsecAlerts(
		batch
			.map(({ alert }) => alert)
			.filter(isAttackAlert)
			.filter((alert) => {
				const time = Date.parse(alert.start_at || alert.created_at || alert.stop_at);
				return time >= state.start && time <= state.end;
			}),
		filters,
	);
	return {
		items,
		page_size: 25,
		matched: items.length,
		has_next: next !== null,
		next_cursor: next,
		window_hours: windowHours,
		truncated: blocked,
		scanned: batch.length,
		scan_mode: true,
		start: new Date(state.start).toISOString(),
		end: new Date(state.end).toISOString(),
	};
};

export { scanAlertHistory };
