interface Credential {
	username: string;
	password?: string;
}

export const hasMissingAccessPassword = (items: Credential[], existing: Credential[] = []): boolean => {
	const usernames = new Set(existing.map((item) => item.username));
	return items.some((item) => !item.password && !usernames.has(item.username));
};
