import * as api from "./base";

export interface AnubisReport {
	metrics: {
		status: "observed" | "stale" | "unavailable";
		observedAt: string | null;
		start: string;
		end: string;
		partial: boolean;
		totals: { issued: number | null; validated: number | null; failed: number | null };
	};
	ledger: {
		status: "observed" | "stale" | "unavailable";
		attemptsStatus: "observed" | "stale" | "unavailable";
		observedAt: string | null;
		gap: boolean;
		pending: boolean;
		total: number;
		page: number;
		items: {
			id: string;
			time: string;
			ip: string;
			kind: "observed" | "accepted" | "failed";
			activeBan: boolean | null;
		}[];
	};
	coverage: {
		total: number;
		page: number;
		items: {
			id: number;
			domains: string[];
			anubis: boolean;
			customUpstream: boolean;
			locationsTruncated: boolean;
			locations: { path: string; anubis: boolean; customUpstream: boolean }[];
		}[];
	};
}
export const getAnubisReport = async (
	hours: number,
	page: number,
	hostPage: number,
	signal?: AbortSignal,
): Promise<AnubisReport> =>
	api.get({ url: `/crowdsec/anubis-report?window=${hours}&page=${page}&host_page=${hostPage}` }, signal);
