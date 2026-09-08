import * as api from "./base";

export interface HttpCounters {
	checks: number;
	inspected: number;
	errors: number;
	unreadable: number;
	bans: number;
	wafBans: number;
	challenges: number;
}
interface Layer {
	status: "unavailable" | "stale" | "observed";
	observedAt: string | null;
	coveredMs: number;
	incomplete: boolean;
}
export interface SecurityTelemetry {
	windowHours: number;
	start: string;
	end: string;
	nginx: Layer & {
		totals: HttpCounters;
		hostsTruncated: boolean;
		hosts: { id: number; domains: string[]; counters: HttpCounters }[];
	};
	firewall: Layer & {
		totals: { inputPackets: number; forwardPackets: number };
		serviceActive: boolean | null;
		inputRule: boolean | null;
		forwardRule: boolean | null;
	};
}
export const getSecurityTelemetry = async (windowHours: number, signal?: AbortSignal): Promise<SecurityTelemetry> =>
	await api.get({ url: "/crowdsec/telemetry", params: { windowHours } }, signal);
