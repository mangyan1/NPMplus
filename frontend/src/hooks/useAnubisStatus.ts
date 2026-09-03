import { useQuery } from "@tanstack/react-query";
import { getAnubisStatus } from "src/api/backend";

// the anubis section mirrors the decision list: live view, admin-gated on the
// backend, tolerant of partial failures by design
export const useAnubisStatus = (options = {}) =>
	useQuery({
		queryKey: ["anubis-status"],
		queryFn: ({ signal }) => getAnubisStatus(signal),
		refetchInterval: 10 * 1000,
		staleTime: 10 * 1000,
		retry: 1,
		...options,
	});
