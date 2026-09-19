import * as api from "./base";
import type { CrowdsecAlert, CrowdsecAlertPage, CrowdsecDecision } from "./getCrowdsecDecisions";

export interface Attacker {
	ip: string;
	country: string;
	asName: string;
	asNumber: string;
	firstSeen: string;
	lastSeen: string;
	alerts: number;
	events: number;
	scenarios: string[];
	targets: string[];
}
export interface AttackerPage {
	session: string;
	revision: string;
	items: Attacker[];
	matched: number;
	scanned: number;
	complete: boolean;
	truncated: boolean;
	start: string;
	end: string;
	page: number;
	hasNext: boolean;
}
export interface AttackerParams {
	session: string;
	advance: string;
	page: number;
	search: string;
	sort: string;
	windowHours: number;
}
export const getCrowdsecAttackers = (params: AttackerParams, signal?: AbortSignal): Promise<AttackerPage> =>
	api.get({ url: "/crowdsec/attackers", params: { ...params } }, signal);
export interface AttackerTimeline extends CrowdsecAlertPage {
	decisions: CrowdsecDecision[];
	decisionsAvailable: boolean;
	decisionsCheckedAt?: string;
	decisionsTruncated: boolean;
}
export const getAttackerTimeline = (
	ip: string,
	windowHours: number,
	cursor: string,
	signal?: AbortSignal,
): Promise<AttackerTimeline> =>
	api.get({ url: "/crowdsec/attackers/timeline", params: { ip, windowHours, cursor } }, signal);
export const getAttackerEvents = (
	id: number,
	page: number,
	signal?: AbortSignal,
): Promise<{ alert: CrowdsecAlert; retained: number; page: number; hasNext: boolean; truncated: boolean }> =>
	api.get({ url: `/crowdsec/attackers/events/${id}`, params: { page } }, signal);
