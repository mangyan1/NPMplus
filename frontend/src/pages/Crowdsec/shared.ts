import type { AnubisStatus, CrowdsecMetrics } from "src/api/backend";

export type DashboardTab = "attackers" | "overview" | "activity" | "bans" | "waf" | "system";
export type KpiKind = "attacks" | "local" | "community" | "anubis";

export const boundedCount = (value?: number | null, truncated = false) =>
	typeof value !== "number" ? "—" : truncated ? `${value}+` : value;

// Announcement precedence: a LAPI outage hides the insight signals, and a spike
// matters more than an ongoing ban count.
export const NOTIFICATION_TYPES = ["lapi", "attack-spike", "active-bans"] as const;

export interface NotificationPlan {
	// the type to announce now, or null when there is nothing new
	announce: string | null;
	// dedupe markers to drop: the signal is gone, so a later recurrence should
	// notify again instead of staying silent forever
	forget: string[];
}

// A signal is announced once per contiguous occurrence, and `seen` reports
// whether a type was already announced. Deliberately keyed on the type and never
// on a count or a bucket, or an ongoing attack would re-notify on every poll
// that observes a different number.
export const notificationPlan = (
	signals: { type: string }[] | undefined,
	lapiUnavailable: boolean,
	seen: (type: string) => boolean,
): NotificationPlan => {
	const present: readonly string[] = lapiUnavailable
		? ["lapi"]
		: NOTIFICATION_TYPES.filter((type) => signals?.some((signal) => signal.type === type));
	return {
		announce: NOTIFICATION_TYPES.find((type) => present.includes(type) && !seen(type)) ?? null,
		// during an outage the insight signals are unknown, so leave them alone
		forget: lapiUnavailable ? [] : NOTIFICATION_TYPES.filter((type) => !present.includes(type) && seen(type)),
	};
};

export interface StatusPresentation {
	label: string;
	tone: "green" | "orange" | "red" | "secondary";
}

export const anubisServiceStatus = (anubis?: AnubisStatus): StatusPresentation => {
	if (!anubis) return { label: "crowdsec.status.checking", tone: "orange" };
	if (!anubis.configured) return { label: "crowdsec.anubis.service-disabled", tone: "secondary" };
	if (anubis.container.up === true) return { label: "crowdsec.anubis.container-up", tone: "green" };
	if (anubis.container.up === false) return { label: "crowdsec.anubis.container-down", tone: "red" };
	return { label: "crowdsec.status.checking", tone: "orange" };
};

export const honeypotStatus = (anubis?: AnubisStatus): StatusPresentation => {
	if (!anubis) return { label: "crowdsec.anubis.honeypot-checking", tone: "orange" };
	if (!anubis.configured || anubis.honeypot.status === "disabled")
		return { label: "crowdsec.anubis.honeypot-disabled", tone: "secondary" };
	if (anubis.container.up === false || anubis.honeypot.status === "unavailable")
		return { label: "crowdsec.anubis.honeypot-unavailable", tone: "red" };
	if (anubis.honeypot.status === "waiting") return { label: "crowdsec.anubis.honeypot-waiting", tone: "orange" };
	return { label: "crowdsec.anubis.honeypot-ready", tone: "green" };
};

export const appsecStatus = (metrics?: CrowdsecMetrics, stale = false): StatusPresentation => {
	if (!metrics) return { label: "crowdsec.appsec.status-checking", tone: "orange" };
	if (stale) return { label: "crowdsec.status.stale", tone: "orange" };
	if (!metrics.available) return { label: "crowdsec.appsec.status-monitoring-unavailable", tone: "orange" };
	if (metrics.appsecConfigured === false) return { label: "crowdsec.appsec.status-disabled", tone: "secondary" };
	if (metrics.appsecMetricsPresent) return { label: "crowdsec.appsec.status-active", tone: "green" };
	if (metrics.appsecConfigured === true) return { label: "crowdsec.appsec.status-ready", tone: "orange" };
	return { label: "crowdsec.appsec.status-unknown", tone: "secondary" };
};

export const appsecTrafficAvailable = (metrics?: CrowdsecMetrics) =>
	Boolean(
		metrics?.available &&
			metrics.appsecMetricsPresent &&
			typeof metrics.appsecRequests === "number" &&
			typeof metrics.appsecBlocked === "number" &&
			typeof metrics.appsecPassed === "number",
	);
