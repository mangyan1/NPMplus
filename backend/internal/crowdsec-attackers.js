import { randomUUID } from "node:crypto";
import { canonicalIp } from "./anubis-reporting.js";
import { publicError } from "./crowdsec.js";
import { scanAlertHistory } from "./crowdsec-history.js";

// Short-lived, bounded summaries only; LAPI remains the history source of truth.
export const createAttackerCatalog = (scan = scanAlertHistory) => {
	const sessions = new Map();
	return async ({ session = "", advance = "", windowHours = 24, page = 1, search = "", sort = "last" }) => {
		const now = Date.now();
		for (const [key, value] of sessions) if (now - value.created > 600_000) sessions.delete(key);
		let state = sessions.get(session);
		const fresh = !session;
		if (session && (!state || state.windowHours !== windowHours))
			throw publicError("crowdsec.attackers.expired", 400);
		if (!state) {
			if (sessions.size >= 8) sessions.delete(sessions.keys().next().value);
			session = randomUUID();
			state = {
				created: now,
				windowHours,
				groups: new Map(),
				cursor: "",
				revision: "",
				scanned: 0,
				complete: false,
				truncated: false,
			};
			sessions.set(session, state);
		}
		// Repeated/parallel requests for the same revision do not advance twice.
		if (!state.pending && !state.complete && !state.truncated && (fresh || advance === state.revision)) {
			state.pending = (async () => {
				for (let batch = 0; batch < 4; batch++) {
					const result = await scan({ windowHours, filters: {}, cursor: state.cursor });
					for (const alert of result.items) {
						const ip = canonicalIp(alert.source.ip || alert.source.value);
						if (!ip) continue;
						const time = alert.start_at || alert.created_at;
						const lastTime = Number.isFinite(Date.parse(alert.stop_at)) ? alert.stop_at : time;
						let group = state.groups.get(ip);
						if (!group) {
							group = {
								ip,
								country: alert.source.country.slice(0, 8),
								as_name: alert.source.as_name.slice(0, 256),
								as_number: alert.source.as_number.slice(0, 32),
								first_seen: time,
								last_seen: lastTime,
								alerts: 0,
								events: 0,
								scenarios: new Set(),
								targets: new Set(),
							};
							state.groups.set(ip, group);
						}
						group.alerts++;
						group.events += alert.events_count;
						if (Date.parse(time) < Date.parse(group.first_seen)) group.first_seen = time;
						if (Date.parse(lastTime) > Date.parse(group.last_seen)) group.last_seen = lastTime;
						if (group.scenarios.size < 30) group.scenarios.add(alert.scenario.slice(0, 256));
						for (const event of alert.events)
							for (const meta of event.meta)
								if (["target_host", "target_fqdn"].includes(meta.key) && group.targets.size < 30)
									group.targets.add(meta.value);
					}
					state.scanned += result.scanned;
					state.start = result.start;
					state.end = result.end;
					state.cursor = result.next_cursor;
					state.truncated = result.truncated;
					state.complete = !result.has_next && !result.truncated;
					state.revision = randomUUID();
					if (state.complete || state.truncated) break;
				}
			})();
			try {
				await state.pending;
			} finally {
				state.pending = null;
			}
		} else if (state.pending) await state.pending;
		const needle = search.toLowerCase();
		const rows = [...state.groups.values()].filter((row) =>
			[
				row.ip,
				row.country,
				row.as_name,
				row.as_number,
				`AS${row.as_number}`,
				...row.scenarios,
				...row.targets,
			].some((value) => value.toLowerCase().includes(needle)),
		);
		rows.sort(
			(a, b) =>
				(sort === "alerts" ? b.alerts - a.alerts : Date.parse(b.last_seen) - Date.parse(a.last_seen)) ||
				a.ip.localeCompare(b.ip),
		);
		return {
			session,
			revision: state.revision,
			scanned: state.scanned,
			complete: state.complete,
			truncated: state.truncated,
			start: state.start,
			end: state.end,
			matched: rows.length,
			page,
			has_next: rows.length > page * 25,
			items: rows
				.slice((page - 1) * 25, page * 25)
				.map((row) => ({ ...row, scenarios: [...row.scenarios], targets: [...row.targets] })),
		};
	};
};

export const readAttackerCatalog = createAttackerCatalog();
