import { isDeepStrictEqual } from "node:util";
import errs from "./error.js";

const nonEmpty = (value) => typeof value === "string" && value.trim() !== "";
const nginxSyntaxPattern = /[;{}$#"'\\]/;

const privilegedProjection = (data = {}) => {
	const projection = {};

	for (const key of ["advanced_config", "npmplus_location_config", "npmplus_advanced_config"]) {
		if (nonEmpty(data[key])) projection[key] = data[key];
	}

	if (data.forward_scheme === "path") {
		projection.localPath = {
			forward_scheme: data.forward_scheme,
			forward_host: data.forward_host,
		};
	}

	const locations = (data.locations || [])
		.map((location) => {
			const privileged = {};
			if (nonEmpty(location.advanced_config)) privileged.advanced_config = location.advanced_config;
			if (nonEmpty(location.npmplus_location_config)) {
				privileged.npmplus_location_config = location.npmplus_location_config;
			}
			if (location.forward_scheme === "path") {
				privileged.localPath = {
					forward_scheme: location.forward_scheme,
					forward_host: location.forward_host,
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
export const assertPrivilegedNginxFields = async (access, data, existing = null) => {
	if (
		await access
			.can("admin:access")
			.then(() => true)
			.catch(() => false)
	)
		return;

	const proposed = existing ? { ...existing, ...data } : data;
	if (!isDeepStrictEqual(privilegedProjection(existing || {}), privilegedProjection(proposed))) {
		throw new errs.PermissionError("Administrator access is required for raw Nginx configuration or local paths");
	}
};

export { privilegedProjection };
