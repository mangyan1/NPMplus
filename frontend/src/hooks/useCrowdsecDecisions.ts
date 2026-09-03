import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	type CrowdsecAlert,
	type CrowdsecDecisionPage,
	getCrowdsecAlerts,
	getCrowdsecDecisions,
	unbanCrowdsecDecision,
} from "src/api/backend";

const useCrowdsecDecisions = (options = {}) =>
	useQuery<CrowdsecDecisionPage, Error>({
		queryKey: ["crowdsec-decisions"],
		queryFn: ({ signal }) => getCrowdsecDecisions(signal),
		// live view: keep the ban list moving without a manual refresh
		refetchInterval: 10 * 1000,
		staleTime: 10 * 1000,
		retry: 1,
		...options,
	});

// the alert that produced a ban, fetched on demand when a row is expanded
const useCrowdsecAlerts = (
	decisionId: number,
	scope: string | undefined,
	value: string | undefined,
	enabled: boolean,
) =>
	useQuery<CrowdsecAlert[], Error>({
		queryKey: ["crowdsec-alerts", decisionId, scope, value],
		queryFn: ({ signal }) => getCrowdsecAlerts(scope as string, value as string, signal),
		enabled,
		staleTime: 60 * 1000,
		retry: false,
	});

const useUnbanCrowdsecDecision = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (id: number) => unbanCrowdsecDecision(id),
		onSuccess: async () => {
			await queryClient.invalidateQueries({ queryKey: ["crowdsec-decisions"] });
			await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
		},
	});
};

export { useCrowdsecAlerts, useCrowdsecDecisions, useUnbanCrowdsecDecision };
