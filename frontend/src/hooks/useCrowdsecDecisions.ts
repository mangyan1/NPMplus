import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	type CrowdsecAlert,
	type CrowdsecDecision,
	getCrowdsecAlerts,
	getCrowdsecDecisions,
	unbanCrowdsecDecision,
} from "src/api/backend";

const useCrowdsecDecisions = (options = {}) =>
	useQuery<CrowdsecDecision[], Error>({
		queryKey: ["crowdsec-decisions"],
		queryFn: () => getCrowdsecDecisions(),
		// live view: keep the ban list moving without a manual refresh
		refetchInterval: 10 * 1000,
		staleTime: 10 * 1000,
		...options,
	});

// the alert that produced a ban, fetched on demand when a row is expanded
const useCrowdsecAlerts = (scope: string | undefined, value: string | undefined, enabled: boolean) =>
	useQuery<CrowdsecAlert[], Error>({
		queryKey: ["crowdsec-alerts", scope, value],
		queryFn: () => getCrowdsecAlerts(scope as string, value as string),
		enabled,
		staleTime: 60 * 1000,
	});

const useUnbanCrowdsecDecision = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: ({ scope, value }: { scope: string; value: string }) => unbanCrowdsecDecision(scope, value),
		onSuccess: async () => {
			await queryClient.invalidateQueries({ queryKey: ["crowdsec-decisions"] });
			await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
		},
	});
};

export { useCrowdsecAlerts, useCrowdsecDecisions, useUnbanCrowdsecDecision };
