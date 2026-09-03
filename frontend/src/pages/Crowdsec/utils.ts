import type { CrowdsecDecision } from "src/api/backend";

export type CrowdsecSortKey = "id" | "origin" | "scenario" | "target" | "type";
export type CrowdsecSortDirection = "asc" | "desc";

export const decisionTarget = (decision: CrowdsecDecision) =>
	decision.scope === "Ip" || !decision.scope ? decision.value : `${decision.scope}: ${decision.value}`;

export const filterCrowdsecDecisions = (decisions: CrowdsecDecision[], search: string) => {
	const needle = search.trim().toLocaleLowerCase();
	if (!needle) return decisions;

	return decisions.filter((decision) =>
		[decisionTarget(decision), decision.scenario, decision.origin, decision.type].some((field) =>
			field.toLocaleLowerCase().includes(needle),
		),
	);
};

export const sortCrowdsecDecisions = (
	decisions: CrowdsecDecision[],
	key: CrowdsecSortKey,
	direction: CrowdsecSortDirection,
) => {
	const factor = direction === "asc" ? 1 : -1;
	return [...decisions].sort((a, b) => {
		if (key === "id") return (a.id - b.id) * factor;

		const value = (decision: CrowdsecDecision) => {
			switch (key) {
				case "target":
					return decisionTarget(decision);
				case "scenario":
					return decision.scenario;
				case "origin":
					return decision.origin;
				case "type":
					return decision.type;
				default:
					return "";
			}
		};

		const compared = value(a).localeCompare(value(b), undefined, { numeric: true, sensitivity: "base" });
		return (compared || a.id - b.id) * factor;
	});
};
