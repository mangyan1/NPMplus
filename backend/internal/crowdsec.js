// The CrowdSec LAPI client: key-file and machine-token authentication, bounded
// fetches, and the local config/log readers the dashboard routes build on.
// Routes own presentation; this module owns every outbound CrowdSec call.
import { createHash } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import { isIP } from "node:net";
import nodePath from "node:path";
import process from "node:process";
import { fetchWithTimeout, readBoundedJson } from "../lib/bounded-fetch.js";
import { debug, express as logger } from "../logger.js";
import PACKAGE from "../package.json" with { type: "json" };

export const publicError = (message, status) => Object.assign(new Error(message), { public: true, status });

const LAPI_KEY_FILE = process.env.CROWDSEC_LAPI_KEY_FILE || "/data/crowdsec/lapi-ui.key";
const LAPI_URL = process.env.CROWDSEC_LAPI_URL || "http://127.0.0.1:8080";
const LAPI_MACHINE_ID = process.env.CROWDSEC_LAPI_MACHINE_ID || "npmplus-ui";
const LAPI_MACHINE_KEY_FILE = process.env.CROWDSEC_LAPI_MACHINE_KEY_FILE || "/data/crowdsec/lapi-ui-machine.key";
const CROWDSEC_BOUNCER_CONFIG_FILE = process.env.CROWDSEC_BOUNCER_CONFIG_FILE || "/data/crowdsec/crowdsec.conf";
const MACHINE_TOKEN_TTL_MS = 30 * 1000;
// crowdsec's lapi validates the client user agent against the registered
// machine (a bare "node" agent is rejected as "bad user agent"), so every
// request this backend makes identifies itself like the other bouncers do
export const LAPI_USER_AGENT = `npmplus-ui-backend/${PACKAGE.version}`;
const configuredTimeout = Number.parseInt(process.env.CROWDSEC_LAPI_TIMEOUT_MS || "5000", 10);
const LAPI_TIMEOUT_MS = Number.isFinite(configuredTimeout) && configuredTimeout > 0 ? configuredTimeout : 5000;
const LAPI_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const HONEYPOT_LOG_PATH = process.env.ANUBIS_HONEYPOT_LOG_FILE || "/data/anubis/honeypot.addrs";
const HONEYPOT_LOG_MAX_BYTES = 256 * 1024;

export const fetchCrowdsec = async (url, options = {}, timeoutMs = LAPI_TIMEOUT_MS) => {
	try {
		return await fetchWithTimeout(url, options, timeoutMs);
	} catch (err) {
		debug(logger, `CrowdSec request failed: ${err}`);
		throw publicError("crowdsec.unavailable", 502);
	}
};

export const readCrowdsecJson = async (response, maxBytes = LAPI_MAX_RESPONSE_BYTES) => {
	try {
		return await readBoundedJson(response, maxBytes);
	} catch (err) {
		debug(logger, `CrowdSec response was invalid: ${err}`);
		throw publicError("crowdsec.invalid-response", 502);
	}
};

// The dashboard needs to distinguish a quiet WAF from a disabled one. Read only
// non-secret switches from the local bouncer config; never return its API key or
// endpoint. A missing legacy file degrades to unknown instead of failing metrics.
export const readAppsecConfiguration = async () => {
	try {
		const text = (await readFile(CROWDSEC_BOUNCER_CONFIG_FILE, "utf8")).slice(0, 64 * 1024);
		const setting = (name) => text.match(new RegExp(`^${name}=(.*)$`, "m"))?.[1]?.trim() ?? "";
		const url = setting("APPSEC_URL");
		const failureAction = setting("APPSEC_FAILURE_ACTION");
		const unreadableBody = setting("APPSEC_DROP_UNREADABLE_BODY");
		return {
			appsec_configured: Boolean(url),
			appsec_failure_action: ["deny", "passthrough"].includes(failureAction) ? failureAction : null,
			appsec_drop_unreadable_body: ["true", "false"].includes(unreadableBody) ? unreadableBody === "true" : null,
		};
	} catch (err) {
		debug(logger, `CrowdSec bouncer config unavailable for AppSec status: ${err}`);
		return {
			appsec_configured: null,
			appsec_failure_action: null,
			appsec_drop_unreadable_body: null,
		};
	}
};

// the honeypot log lives on the anubis data volume, readable by the backend;
// newest-last per the writer (anubis appends), capped at the configured size
export const readRecentHoneypotIps = async () => {
	let content;
	let log;
	try {
		const file = await open(HONEYPOT_LOG_PATH, "r");
		try {
			const { size, mtime } = await file.stat();
			log = { modifiedAt: mtime.toISOString(), sizeBytes: size, truncated: size > HONEYPOT_LOG_MAX_BYTES };
			const start = Math.max(0, size - HONEYPOT_LOG_MAX_BYTES);
			const buffer = Buffer.alloc(Math.min(size, HONEYPOT_LOG_MAX_BYTES));
			const { bytesRead } = await file.read(buffer, 0, buffer.length, start);
			content = buffer.toString("utf8", 0, bytesRead);
			// The bounded tail may start halfway through an address.
			if (start > 0) content = content.includes("\n") ? content.slice(content.indexOf("\n") + 1) : "";
			// Do not display a still-being-written address as a completed catch.
			content = content.slice(0, content.lastIndexOf("\n") + 1);
		} finally {
			await file.close();
		}
	} catch (err) {
		if (err?.code === "ENOENT") return { status: "waiting", items: [] };
		debug(logger, `Anubis honeypot log is unreadable: ${err}`);
		return { status: "unavailable", items: [] };
	}
	const items = content
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && line.length <= 45)
		.filter((line) => isIP(line) !== 0);
	return { status: "ready", items, log: { ...log, entries: items.length, uniqueIps: new Set(items).size } };
};

export const readHoneypotBridge = async () => {
	try {
		const file = await open(nodePath.join(nodePath.dirname(HONEYPOT_LOG_PATH), "honeypot-bridge.json"), "r");
		let value;
		try {
			const buffer = Buffer.alloc(4097);
			const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
			if (bytesRead > 4096) throw new Error("Bridge status too large");
			value = JSON.parse(buffer.toString("utf8", 0, bytesRead));
		} finally {
			await file.close();
		}
		const counters = ["applied", "failed", "invalid", "pending_bytes"];
		if (
			!Number.isSafeInteger(value.checked_at) ||
			value.checked_at < 0 ||
			!["waiting", "idle", "applied", "failed"].includes(value.status) ||
			counters.some((key) => !Number.isSafeInteger(value[key]) || value[key] < 0)
		)
			throw new Error("Invalid bridge status");
		const age = Date.now() - value.checked_at;
		return {
			status: age > 450_000 || age < -5000 ? "stale" : value.status,
			checkedAt: new Date(value.checked_at).toISOString(),
			applied: value.applied,
			failed: value.failed,
			invalid: value.invalid,
			pendingBytes: value.pending_bytes,
		};
	} catch {
		return { status: "unavailable", checkedAt: null };
	}
};

export const lapiFetch = async (path) => {
	let key = "";
	try {
		key = (await readFile(LAPI_KEY_FILE, "utf8")).trim();
	} catch {
		// Handled below with a stable, localizable error code.
	}
	if (!key) throw publicError("crowdsec.not-wired", 503);

	const response = await fetchCrowdsec(`${LAPI_URL}${path}`, { headers: { "X-Api-Key": key } });
	if (!response.ok) {
		throw publicError(
			response.status === 401 || response.status === 403 ? "crowdsec.bad-key" : "crowdsec.lapi-error",
			502,
		);
	}
	return readCrowdsecJson(response);
};

let machineTokenCache = null;

const lapiLogin = async () => {
	let machineKey = "";
	try {
		machineKey = (await readFile(LAPI_MACHINE_KEY_FILE, "utf8")).trim();
	} catch {
		// Handled below with a stable, localizable error code.
	}
	if (!machineKey) throw publicError("crowdsec.not-wired-machine", 503);

	// sha256 here is only an in-memory cache fingerprint to notice key-file
	// changes between requests; the key itself is never stored or compared
	// against persisted verifiers.
	const fingerprint = createHash("sha256").update(machineKey).digest("hex");
	if (
		machineTokenCache?.fingerprint === fingerprint &&
		machineTokenCache.expiresAt > Date.now() &&
		machineTokenCache.token
	) {
		return machineTokenCache.token;
	}

	const response = await fetchCrowdsec(`${LAPI_URL}/v1/watchers/login`, {
		method: "POST",
		headers: { "Content-Type": "application/json", "User-Agent": LAPI_USER_AGENT },
		body: JSON.stringify({ machine_id: LAPI_MACHINE_ID, password: machineKey }),
	});
	if (!response.ok) {
		throw publicError(
			response.status === 401 || response.status === 403 ? "crowdsec.bad-machine-key" : "crowdsec.lapi-error",
			502,
		);
	}
	const body = await readCrowdsecJson(response, 64 * 1024);
	if (typeof body?.token !== "string" || !body.token) throw publicError("crowdsec.invalid-response", 502);

	machineTokenCache = {
		fingerprint,
		token: body.token,
		expiresAt: Date.now() + MACHINE_TOKEN_TTL_MS,
	};
	return body.token;
};

export const lapiMachineFetch = async (
	path,
	method = "GET",
	mayRetry = true,
	{ body = null, readJson = readCrowdsecJson } = {},
) => {
	const token = await lapiLogin();
	const options = {
		method,
		headers: { Authorization: `Bearer ${token}`, "User-Agent": LAPI_USER_AGENT },
	};
	if (body !== null) {
		options.headers["Content-Type"] = "application/json";
		options.body = JSON.stringify(body);
	}
	const response = await fetchCrowdsec(`${LAPI_URL}${path}`, options);
	if (response.status === 401 || response.status === 403) {
		machineTokenCache = null;
		if (mayRetry) return lapiMachineFetch(path, method, false, { body, readJson });
		throw publicError("crowdsec.bad-machine-key", 502);
	}
	if (!response.ok) throw publicError("crowdsec.lapi-error", 502);
	return readJson(response);
};
