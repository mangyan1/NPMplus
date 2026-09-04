import * as api from "./base";
import type { CrowdsecDecision } from "./getCrowdsecDecisions";

export type AnubisHoneypotBan = CrowdsecDecision;

export interface AnubisStatus {
	configured: boolean;
	honeypot: {
		status: "ready" | "waiting" | "unavailable" | "disabled";
		decisionsAvailable: boolean;
		activeCount: number | null;
		truncated: boolean;
		items: AnubisHoneypotBan[];
	};
	container: {
		up: boolean | null;
		error: string | null;
	};
	recent: string[];
}

export async function getAnubisStatus(signal?: AbortSignal): Promise<AnubisStatus> {
	return await api.get({ url: "/crowdsec/anubis" }, signal);
}
