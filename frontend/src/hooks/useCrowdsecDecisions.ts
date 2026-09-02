import { useQuery } from "@tanstack/react-query";
import { type CrowdsecDecision, getCrowdsecDecisions } from "src/api/backend";

const useCrowdsecDecisions = (options = {}) =>
	useQuery<CrowdsecDecision[], Error>({
		queryKey: ["crowdsec-decisions"],
		queryFn: () => getCrowdsecDecisions(),
		// live view: keep the ban list moving without a manual refresh
		refetchInterval: 10 * 1000,
		staleTime: 10 * 1000,
		...options,
	});

export { useCrowdsecDecisions };
