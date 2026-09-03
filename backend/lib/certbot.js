import dnsPlugins from "../certbot/dns-plugins.json" with { type: "json" };
import { certbot as logger } from "../logger.js";
import errs from "./error.js";
import utils from "./utils.js";

/**
 * Installs a cerbot plugin given the key for the object from
 * ../certbot/dns-plugins.json
 *
 * @param   {string}  pluginKey
 * @returns {Object}
 */
const installPlugin = async (pluginKey) => {
	if (typeof dnsPlugins[pluginKey] === "undefined") {
		// throw Error(`Certbot plugin ${pluginKey} not found`);
		throw new errs.ItemNotFoundError(pluginKey);
	}

	const plugin = dnsPlugins[pluginKey];
	try {
		await utils.execFile("python3", [
			"-c",
			"import importlib.metadata,sys; importlib.metadata.version(sys.argv[1])",
			plugin.package_name,
		]);
		logger.info(`Certbot plugin ${pluginKey} is already installed`);
		return "";
	} catch {
		// Installation is intentionally disabled below unless the operator
		// explicitly accepts mutable code in the live privileged container.
	}

	if (process.env.ALLOW_RUNTIME_CERTBOT_PLUGIN_INSTALL !== "true") {
		throw new errs.ConfigurationError(
			`Certbot plugin ${pluginKey} is not included in this image. Build it into a custom image, or explicitly set ALLOW_RUNTIME_CERTBOT_PLUGIN_INSTALL=true.`,
		);
	}

	logger.start(`Installing ${pluginKey}...`);

	const result = await utils.execFile("pip", [
		"install",
		"--upgrade",
		"--no-cache-dir",
		"--disable-pip-version-check",
		"--no-input",
		plugin.package_name,
	]);

	logger.complete(`Installed ${pluginKey}`);
	return result;
};

/**
 * @param {array} pluginKeys
 */
const installPlugins = async (pluginKeys) => {
	if (pluginKeys.length === 0) {
		return;
	}

	let hasErrors = false;

	for (const pluginKey of pluginKeys) {
		try {
			await installPlugin(pluginKey);
		} catch (err) {
			hasErrors = true;
			logger.error(err.message);
			break;
		}
	}

	if (hasErrors) {
		throw new errs.CommandError("Some plugins failed to install. Please check the logs above", 1);
	}
};

export { installPlugin, installPlugins };
