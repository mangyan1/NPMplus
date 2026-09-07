import type { CrowdsecDecision } from "src/api/backend";
import { scenarioCategory } from "./scenarios.ts";

export const decisionTarget = (decision: CrowdsecDecision) =>
	decision.scope === "Ip" || !decision.scope ? decision.value : `${decision.scope}: ${decision.value}`;

export interface AttackMixSegment {
	// a scenario category key; the empty name marks the residual "other"
	// slice covering alerts not in the top list
	name: string;
	count: number;
	share: number;
	// palette index; -1 marks the residual slice rendered in secondary grey
	color: number;
}

// donut segments group the top-scenario counts by attack type, because raw
// scenario lists produce five near-identical slices on vpatch-heavy boxes.
// alerts not covered by the top list collapse into a residual "other" slice
// so the shares always sum to 1
export const attackMixSegments = (items: { name: string; count: number }[], total: number): AttackMixSegment[] => {
	if (total <= 0) return [];
	const categories = new Map<string, number>();
	for (const item of items) {
		if (!item.name || item.count <= 0) continue;
		const category = scenarioCategory(item.name);
		categories.set(category, (categories.get(category) ?? 0) + item.count);
	}
	const segments: AttackMixSegment[] = [...categories.entries()]
		.filter(([name]) => name !== "")
		.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
		.map(([name, count], index) => ({ name, count, share: count / total, color: index }));
	const named = segments.reduce((sum, item) => sum + item.count, 0);
	const other = total - named;
	if (other > 0) segments.push({ name: "", count: other, share: other / total, color: -1 });
	return segments;
};
