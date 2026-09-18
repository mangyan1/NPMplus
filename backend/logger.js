const createLogger = (scope) =>
	Object.fromEntries(
		["info", "warn", "error", "success", "start", "complete", "fatal", "debug"].map((type) => [
			type,
			(...args) => console.log(`[${scope}] › ${type.padEnd(9)}`, ...args),
		]),
	);

const global = createLogger("Global        ");
const migrate = createLogger("Migrate       ");
const express = createLogger("Express       ");
const access = createLogger("Access        ");
const nginx = createLogger("Nginx         ");
const ssl = createLogger("TLS           ");
const certbot = createLogger("Certbot       ");
const setup = createLogger("Setup         ");
const ipRanges = createLogger("IP Ranges     ");
const remoteVersion = createLogger("Remote Version");
const gravatar = createLogger("Gravatar      ");
const oidc = createLogger("OIDC          ");

const debug = (logger, ...args) => {
	if (logger !== express) logger.debug(...args);
};

// Everything below runs on a timer: the telemetry collectors every 60s, the
// dashboard routes on the poll interval. A source that is absent or down fails
// on every one of those ticks, so a plain debug() there fills the log with one
// identical line a minute. These two keep the first line of an outage and stay
// quiet until a read succeeds again - the recovery re-arms the report, so the
// next outage is seen too. `key` identifies the source, not the message.
const outages = new Set();
const reportOutage = (key, logger, ...args) => {
	if (outages.has(key)) return;
	outages.add(key);
	debug(logger, ...args);
};
const clearOutage = (key) => outages.delete(key);

export {
	access,
	certbot,
	clearOutage,
	debug,
	express,
	global,
	gravatar,
	ipRanges,
	migrate,
	nginx,
	oidc,
	remoteVersion,
	reportOutage,
	setup,
	ssl,
};
