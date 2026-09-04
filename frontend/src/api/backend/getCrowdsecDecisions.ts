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

export interface CrowdsecBanInput {
	value: string;
	duration: string;
	type: string;
	reason?: string;
}

export interface CrowdsecBanResult {
	created: boolean;
	auditLogged: boolean;
}

export interface CrowdsecInsightsItem {
	name: string;
	count: number;
}

export interface CrowdsecInsights {
	windowHours: number;
	alertCount: number;
	topScenarios: CrowdsecInsightsItem[];
	topCountries: CrowdsecInsightsItem[];
	topAsns: CrowdsecInsightsItem[];
}

export async function createCrowdsecBan(data: CrowdsecBanInput): Promise<CrowdsecBanResult> {
	return await api.post({ url: "/crowdsec/decisions", data });
}

export async function getCrowdsecInsights(signal?: AbortSignal): Promise<CrowdsecInsights> {
	return await api.get({ url: "/crowdsec/insights" }, signal);
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
