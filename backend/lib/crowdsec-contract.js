const optionalString = (value) => (typeof value === "string" ? value : "");

// manual ban input: an ip or a cidr range, the same targets crowdsec accepts
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^\[?[0-9a-fA-F:]+\]?$/;
const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^(\[?[0-9a-fA-F:]+\]?\/\d{1,3})$/;
const DURATION_RE = /^[1-9][0-9]*(ns|us|µs|ms|s|m|h|d)$/;
const BAN_TYPES = new Set(["ban", "captcha"]);
const REASONS_RE = /^[\w .,:;#@-]{1,64}$/;

const parseCrowdsecDecisionId = (value) => {
	const id = typeof value === "number" ? value : Number(value);
	return Number.isSafeInteger(id) && id > 0 ? id : null;
};

const validateManualBan = ({ value, duration, type = "ban", reason = "" }) => {
	const errors = [];
	if (typeof value !== "string" || !(IPV4_RE.test(value) || IPV6_RE.test(value) || CIDR_RE.test(value))) {
		errors.push("value");
	}
	if (typeof duration !== "string" || !DURATION_RE.test(duration)) {
		errors.push("duration");
	}
	if (typeof type !== "string" || !BAN_TYPES.has(type)) {
		errors.push("type");
	}
	if (reason && !REASONS_RE.test(reason)) {
		errors.push("reason");
	}
	return errors;
};

// per-event meta keys that are safe and useful to show an operator: they
// describe the attacker and the request, never payloads or secrets
const EVENT_META_KEYS = new Set([
	"source_ip",
	"source_rdns",
	"source_as_number",
	"source_as_name",
	"source_range",
	"source_country",
	"target_uri",
	"target_fqdn",
	"target_host",
	"method",
	"http_user_agent",
	"service",
	"log_type",
]);

const EVENT_LIMIT = 10;

const normalizeEvent = (event) => {
	if (!event || typeof event !== "object") return null;
	const meta = [];
	if (Array.isArray(event.meta)) {
		for (const item of event.meta) {
			if (!item || typeof item !== "object") continue;
			const key = typeof item.key === "string" ? item.key : "";
			const value = typeof item.value === "string" ? item.value : "";
			if (!EVENT_META_KEYS.has(key) || !value) continue;
			// hard cap each value: long user agents or uris must not bloat the page
			meta.push({ key, value: value.slice(0, 512) });
		}
	}
	const timestamp = typeof event.timestamp === "string" ? event.timestamp : "";
	return { timestamp, meta };
};

const normalizeCrowdsecDecisions = (payload) => {
	if (payload === null || typeof payload === "undefined") return [];
	if (!Array.isArray(payload)) throw new TypeError("CrowdSec decisions response is not an array");

	return payload.map((decision) => {
		if (!decision || typeof decision !== "object") {
			throw new TypeError("CrowdSec decision is not an object");
		}
		const id = parseCrowdsecDecisionId(decision.id);
		if (!id || typeof decision.value !== "string" || decision.value.length === 0) {
			throw new TypeError("CrowdSec decision is missing its id or value");
		}

		return {
			id,
			uuid: optionalString(decision.uuid),
			scope: optionalString(decision.scope) || "Ip",
			value: decision.value,
			type: optionalString(decision.type),
			origin: optionalString(decision.origin),
			scenario: optionalString(decision.scenario),
			duration: optionalString(decision.duration),
		};
	});
};

const normalizeCrowdsecAlerts = (payload) => {
	if (payload === null || typeof payload === "undefined") return [];
	if (!Array.isArray(payload)) throw new TypeError("CrowdSec alerts response is not an array");

	return payload.map((alert) => {
		if (!alert || typeof alert !== "object") {
			throw new TypeError("CrowdSec alert is not an object");
		}
		const id = parseCrowdsecDecisionId(alert.id);
		if (!id) throw new TypeError("CrowdSec alert is missing its id");

		const eventsCount = Number(alert.events_count);
		const events = [];
		if (Array.isArray(alert.events)) {
			for (const event of alert.events.slice(0, EVENT_LIMIT)) {
				const normalized = normalizeEvent(event);
				if (normalized) events.push(normalized);
			}
		}
		return {
			id,
			scenario: optionalString(alert.scenario),
			message: optionalString(alert.message),
			start_at: optionalString(alert.start_at),
			stop_at: optionalString(alert.stop_at),
			events_count: Number.isSafeInteger(eventsCount) && eventsCount >= 0 ? eventsCount : 0,
			// attacker identity as recorded by the local agent: geo/ASN only
			source: {
				country: optionalString(alert.source?.cn),
				as_number: optionalString(alert.source?.as_number),
				as_name: optionalString(alert.source?.as_name),
				range: optionalString(alert.source?.range),
				rdns: optionalString(alert.source?.rdns),
			},
			events,
		};
	});
};

const hasCrowdsecAdminAccess = (permission) => Boolean(permission);

export {
	hasCrowdsecAdminAccess,
	normalizeCrowdsecAlerts,
	normalizeCrowdsecDecisions,
	parseCrowdsecDecisionId,
	validateManualBan,
};
