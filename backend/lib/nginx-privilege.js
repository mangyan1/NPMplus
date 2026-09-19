import { posix } from "node:path";
import { isDeepStrictEqual } from "node:util";
import errs from "./error.js";

const nonEmpty = (value) => typeof value === "string" && value.trim() !== "";
const nginxSyntaxPattern = /[;{}$#"'\\]/;
const socketPrefix = /^unix:/i;
const managementSockets = new Set([
	"/run/nginx-control.sock",
	"/run/npmplus.sock",
	"/run/npmplus-telemetry.sock",
	"/run/goaccess.sock",
]);

// Named upstreams can hide a socket target too; only an administrator can
// authorize either kind of local service connection.
const privilegedDestination = (data) => {
	const host = data.forward_host ?? data.forwarding_host;
	return typeof host === "string" && (socketPrefix.test(host) || host.startsWith("cu_"))
		? { host, scheme: data.forward_scheme, port: data.forward_port ?? data.forwarding_port }
		: null;
};

const privilegedProjection = (data = {}) => {
	const projection = {};
	const destination = privilegedDestination(data);
	if (destination) projection.localService = destination;

	for (const key of ["advanced_config", "npmplus_location_config", "npmplus_advanced_config"]) {
		if (nonEmpty(data[key])) projection[key] = data[key];
	}

	if (data.forward_scheme === "path") {
		projection.localPath = {
			forward_scheme: data.forward_scheme,
			forward_host: data.forward_host,
			// the local-path fastcgi target renders from forward_port
			// (fastcgi_pass unix:/run/php{{ forward_port }}.sock): changing it
			// must trip the guard, not just scheme/host
			forward_port: data.forward_port,
		};
	}

	const locations = (data.locations || [])
		.map((location) => {
			const privileged = {};
			const locationDestination = privilegedDestination(location);
			if (locationDestination) privileged.localService = locationDestination;
			if (nonEmpty(location.advanced_config)) privileged.advanced_config = location.advanced_config;
			if (nonEmpty(location.npmplus_location_config)) {
				privileged.npmplus_location_config = location.npmplus_location_config;
			}
			if (location.forward_scheme === "path") {
				privileged.localPath = {
					forward_scheme: location.forward_scheme,
					forward_host: location.forward_host,
					// same fastcgi target as the host-level snapshot above
					forward_port: location.forward_port,
				};
			}
			if (nginxSyntaxPattern.test(location.path || "")) privileged.nginxSyntaxPath = location.path;
			return Object.keys(privileged).length > 0
				? { id: location.id ?? null, path: location.path, privileged }
				: null;
		})
		.filter(Boolean);
	if (locations.length > 0) projection.locations = locations;

	return projection;
};

/**
 * Raw Nginx snippets and local filesystem proxy targets are equivalent to
 * container-level code/data access. Only administrators may introduce or
 * alter them. Delegated managers may still update ordinary host settings.
 */
export const assertPrivilegedNginxFields = (access, data, existing = null) => {
	const proposed = existing ? { ...existing, ...data } : data;
	for (const target of [proposed, ...(proposed.locations || [])]) {
		const host = target.forward_host ?? target.forwarding_host;
		if (typeof host === "string" && socketPrefix.test(host)) {
			const socket = posix.normalize(host.slice(5));
			if (managementSockets.has(socket)) {
				throw new errs.PermissionError("Internal management sockets cannot be published as proxy destinations");
			}
		}
	}
	// canAdmin throws for non-admins; the try/catch turns it into a plain check
	// for the comparison below. can() is synchronous in the merged permission
	// model, so no promise handling here.
	let isAdmin = true;
	try {
		access.canAdmin();
	} catch {
		isAdmin = false;
	}
	if (isAdmin) return;

	if (!isDeepStrictEqual(privilegedProjection(existing || {}), privilegedProjection(proposed))) {
		throw new errs.PermissionError(
			"Administrator access is required for raw Nginx configuration or local services",
		);
	}
};

export { privilegedProjection };
