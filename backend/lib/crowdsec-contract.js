const optionalString = (value) => (typeof value === "string" ? value : "");

export const parseCrowdsecDecisionId = (value) => {
	const id = typeof value === "number" ? value : Number(value);
	return Number.isSafeInteger(id) && id > 0 ? id : null;
};

export const normalizeCrowdsecDecisions = (payload) => {
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

export const normalizeCrowdsecAlerts = (payload) => {
	if (payload === null || typeof payload === "undefined") return [];
	if (!Array.isArray(payload)) throw new TypeError("CrowdSec alerts response is not an array");

	return payload.map((alert) => {
		if (!alert || typeof alert !== "object") {
			throw new TypeError("CrowdSec alert is not an object");
		}
		const id = parseCrowdsecDecisionId(alert.id);
		if (!id) throw new TypeError("CrowdSec alert is missing its id");

		const eventsCount = Number(alert.events_count);
		return {
			id,
			scenario: optionalString(alert.scenario),
			message: optionalString(alert.message),
			start_at: optionalString(alert.start_at),
			stop_at: optionalString(alert.stop_at),
			events_count: Number.isSafeInteger(eventsCount) && eventsCount >= 0 ? eventsCount : 0,
		};
	});
};

export const hasCrowdsecAdminAccess = (permission) => Boolean(permission);
