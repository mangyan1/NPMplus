export const ADMIN = "admin";
export const PROXY_HOSTS = "proxyHosts";
export const REDIRECTION_HOSTS = "redirectionHosts";
export const DEAD_HOSTS = "deadHosts";
export const STREAMS = "streams";
export const CERTIFICATES = "certificates";
export const ACCESS_LISTS = "accessLists";

export const MANAGE = "manage";
export const VIEW = "view";
const HIDDEN = "hidden";

const hasPermission = (section, perm, userPerms, roles) => {
	// The admin role grants access before optional per-user permissions are
	// evaluated, so a missing legacy permissions expansion cannot hide the UI.
	if (isAdmin(roles)) return true;
	if (!userPerms) return false;
	const acceptable = [MANAGE, perm];
	// @ts-expect-error 7053
	const v = typeof userPerms[section] !== "undefined" ? userPerms[section] : HIDDEN;
	return acceptable.indexOf(v) !== -1;
};

const isAdmin = (roles) => roles?.includes("admin") || false;

export { hasPermission, isAdmin };
