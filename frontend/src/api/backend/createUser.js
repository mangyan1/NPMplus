import * as api from "./base";

export async function createUser(item, setupToken) {
	return await api.post({
		url: "/users",
		data: item,
		headers: setupToken ? { "X-NPMplus-Setup-Token": setupToken } : undefined,
	});
}
