import * as api from "./base";

export interface CrowdsecDecision {
	id: number;
	uuid?: string;
	scope?: string;
	value?: string;
	type?: string;
	origin?: string;
	scenario?: string;
	duration?: string;
	until?: string;
	simulated?: boolean;
}

export interface CrowdsecAlert {
	id?: number;
	message?: string;
	scenario?: string;
	startedAt?: string;
	stoppedAt?: string;
	eventsCount?: number;
	events?: Record<string, unknown>[];
}

export async function getCrowdsecDecisions(): Promise<CrowdsecDecision[]> {
	return await api.get({ url: "/crowdsec/decisions" });
}

export async function getCrowdsecAlerts(scope: string, value: string): Promise<CrowdsecAlert[]> {
	return await api.get({ url: "/crowdsec/alerts", params: { scope, value } });
}

export async function unbanCrowdsecDecision(scope: string, value: string): Promise<{ nbDeleted: string }> {
	return await api.post({ url: "/crowdsec/decisions/delete", data: { scope, value } });
}
