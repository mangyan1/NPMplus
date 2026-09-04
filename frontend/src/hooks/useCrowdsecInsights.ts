import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	type CrowdsecBanInput,
	type CrowdsecHistoryParams,
	createCrowdsecBan,
	getCrowdsecAlertHistory,
	getCrowdsecInsights,
	getCrowdsecMetrics,
} from "src/api/backend";

// manual ban: invalidates the ban list after creating a decision so the new
// row appears on the next live refresh
const useCreateCrowdsecBan = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (input: CrowdsecBanInput) => createCrowdsecBan(input),
		onSuccess: async () => {
			await queryClient.invalidateQueries({ queryKey: ["crowdsec-decisions"] });
			await queryClient.invalidateQueries({ queryKey: ["crowdsec-insights"] });
			await queryClient.invalidateQueries({ queryKey: ["crowdsec-alert-history"] });
			await queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
		},
	});
};

// 24h insights: refreshed with the page but less often than the ban list -
// the aggregation does not change every 10 seconds
const useCrowdsecInsights = (windowHours = 24, options = {}) =>
	useQuery({
		queryKey: ["crowdsec-insights", windowHours],
		queryFn: ({ signal }) => getCrowdsecInsights(windowHours, signal),
		refetchInterval: 60 * 1000,
		staleTime: 60 * 1000,
		retry: 1,
		...options,
	});

const useCrowdsecAlertHistory = (params: CrowdsecHistoryParams, options = {}) =>
	useQuery({
		queryKey: ["crowdsec-alert-history", params],
		queryFn: ({ signal }) => getCrowdsecAlertHistory(params, signal),
		refetchInterval: 60 * 1000,
		staleTime: 30 * 1000,
		retry: 1,
		...options,
	});

const useCrowdsecMetrics = (options = {}) =>
	useQuery({
		queryKey: ["crowdsec-metrics"],
		queryFn: ({ signal }) => getCrowdsecMetrics(signal),
		refetchInterval: 60 * 1000,
		staleTime: 60 * 1000,
		retry: false,
		...options,
	});

export { useCreateCrowdsecBan, useCrowdsecAlertHistory, useCrowdsecInsights, useCrowdsecMetrics };
