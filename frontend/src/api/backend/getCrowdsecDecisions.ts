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

export async function getCrowdsecDecisions(): Promise<CrowdsecDecision[]> {
	return await api.get({ url: "/crowdsec/decisions" });
}
