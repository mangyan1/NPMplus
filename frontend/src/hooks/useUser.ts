import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createUser, getUser, type User, updateUser } from "src/api/backend";
import type { ApiError } from "src/api/backend/base";

const fetchUser = (id: number | string) => {
	if (id === "new") {
		return Promise.resolve({
			id: 0,
			createdOn: "",
			modifiedOn: "",
			isDisabled: false,
			email: "",
			name: "",
			nickname: "",
			roles: [],
			avatar: "",
		} as User);
	}
	return getUser(id, ["permissions"]);
};

const useUser = (id: string | number, options = {}) => {
	return useQuery<User, Error>({
		queryKey: ["user", id],
		queryFn: () => fetchUser(id),
		staleTime: 60 * 1000, // 1 minute
		retry: (failureCount, error) => {
			const status = (error as ApiError).status;
			// Retrying permission/session errors or throttling cannot repair them.
			if (id === "me" && status && status >= 400 && status < 500) return false;
			return failureCount < 3;
		},
		...options,
	});
};

const useSetUser = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (values: User) => (values.id ? updateUser(values) : createUser(values)),
		onMutate: (values: User) => {
			if (!values.id) {
				return;
			}
			const previousObject = queryClient.getQueryData(["user", values.id]);
			queryClient.setQueryData(["user", values.id], (old: User) => ({
				...old,
				...values,
			}));
			return () => queryClient.setQueryData(["user", values.id], previousObject);
		},
		onError: (_, __, rollback: any) => rollback(),
		onSuccess: async ({ id }: User) => {
			await Promise.all([
				queryClient.invalidateQueries({ queryKey: ["user", id] }),
				queryClient.invalidateQueries({ queryKey: ["users"] }),
				queryClient.invalidateQueries({ queryKey: ["audit-logs"] }),
			]);
		},
	});
};

export { useSetUser, useUser };
