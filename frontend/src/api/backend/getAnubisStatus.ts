import * as api from "./base";
import type { CrowdsecDecision } from "./getCrowdsecDecisions";

export type AnubisHoneypotBan = CrowdsecDecision;

export interface AnubisStatus {
	checkedAt?: string;
	log?: { modifiedAt: string; sizeBytes: number; truncated: boolean; entries: number; uniqueIps: number } | null;
	bridge?: {
		status: "waiting" | "idle" | "applied" | "failed" | "stale" | "unavailable";
		checkedAt: string | null;
		applied?: number;
		failed?: number;
		invalid?: number;
		pendingBytes?: number;
	};
	configured: boolean;
	honeypot: {
		status: "ready" | "waiting" | "unavailable" | "disabled";
		decisionsAvailable: boolean;
		activeCount: number | null;
		truncated: boolean;
		itemsTruncated?: boolean;
		items: AnubisHoneypotBan[];
	};
	container: {
		httpStatus?: number;
		up: boolean | null;
		error: string | null;
	};
	recent: string[];
}

export async function getAnubisStatus(signal?: AbortSignal): Promise<AnubisStatus> {
	return await api.get({ url: "/crowdsec/anubis" }, signal);
}
