import * as api from "./base";

export interface CrowdsecDecision {
	id: number;
	uuid: string;
	scope: string;
	value: string;
	type: string;
	origin: string;
	scenario: string;
	duration: string;
}

export interface CrowdsecDecisionPage {
	items: CrowdsecDecision[];
	limit: number;
	truncated: boolean;
}

export interface CrowdsecEventMeta {
	key: string;
	value: string;
}

export interface CrowdsecEvent {
	timestamp: string;
	meta: CrowdsecEventMeta[];
}

export interface CrowdsecAlert {
	id: number;
	message: string;
	scenario: string;
	startAt: string;
	stopAt: string;
	eventsCount: number;
	source: {
		country: string;
		asNumber: string;
		asName: string;
		range: string;
		rdns: string;
	};
	events: CrowdsecEvent[];
}

export interface CrowdsecUnbanResult {
	nbDeleted: string;
	auditLogged: boolean;
}

export async function getCrowdsecDecisions(signal?: AbortSignal): Promise<CrowdsecDecisionPage> {
	return await api.get({ url: "/crowdsec/decisions" }, signal);
}

export async function getCrowdsecAlerts(scope: string, value: string, signal?: AbortSignal): Promise<CrowdsecAlert[]> {
	return await api.get({ url: "/crowdsec/alerts", params: { scope, value } }, signal);
}

export async function unbanCrowdsecDecision(id: number): Promise<CrowdsecUnbanResult> {
	return await api.post({ url: "/crowdsec/decisions/delete", data: { id } });
}
