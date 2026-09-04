import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";
import express from "express";
import internalAuditLog from "../internal/audit-log.js";
import { fetchWithTimeout, readBoundedJson, readBoundedText } from "../lib/bounded-fetch.js";
import {
	hasCrowdsecAdminAccess,
	normalizeCrowdsecAlerts,
	normalizeCrowdsecDecisions,
	parseCrowdsecDecisionId,
	validateManualBan,
} from "../lib/crowdsec-contract.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

const LAPI_KEY_FILE = process.env.CROWDSEC_LAPI_KEY_FILE || "/data/crowdsec/lapi-ui.key";
const LAPI_URL = process.env.CROWDSEC_LAPI_URL || "http://127.0.0.1:8080";
const LAPI_MACHINE_ID = process.env.CROWDSEC_LAPI_MACHINE_ID || "npmplus-ui";
const LAPI_MACHINE_KEY_FILE = process.env.CROWDSEC_LAPI_MACHINE_KEY_FILE || "/data/crowdsec/lapi-ui-machine.key";
const LAPI_DECISION_LIMIT = 200;
const LAPI_ALERT_LIMIT = 5;
const LAPI_HONEYPOT_LIMIT = 25;
const INSIGHTS_WINDOW_HOURS = 24;
const INSIGHTS_ALERT_LIMIT = 100;
const INSIGHTS_TOP_N = 5;
const MANUAL_BAN_SCENARIO = "manual/web-ui";
const MACHINE_TOKEN_TTL_MS = 30 * 1000;
const SCOPE_PATTERN = /^[a-zA-Z]{1,32}$/;
const configuredTimeout = Number.parseInt(process.env.CROWDSEC_LAPI_TIMEOUT_MS || "5000", 10);
const LAPI_TIMEOUT_MS = Number.isFinite(configuredTimeout) && configuredTimeout > 0 ? configuredTimeout : 5000;
const LAPI_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const ANUBIS_UPSTREAM = process.env.AUTH_REQUEST_ANUBIS_UPSTREAM || "";
const ANUBIS_TIMEOUT_MS = 3000;
const ANUBIS_MAX_RESPONSE_BYTES = 64 * 1024;
const HONEYPOT_SCENARIO = "anubis-honeypot";
const HONEYPOT_IP_PATTERN = /^[0-9a-fA-F.:]+$/;
const HONEYPOT_LOG_PATH = process.env.ANUBIS_HONEYPOT_LOG_FILE || "/data/anubis/honeypot.addrs";
const HONEYPOT_LOG_MAX_BYTES = 256 * 1024;

const publicError = (message, status) => Object.assign(new Error(message), { public: true, status });

const fetchCrowdsec = async (url, options = {}, timeoutMs = LAPI_TIMEOUT_MS) => {
	try {
		return await fetchWithTimeout(url, options, timeoutMs);
	} catch (err) {
		debug(logger, `CrowdSec request failed: ${err}`);
		throw publicError("crowdsec.unavailable", 502);
	}
};

const readCrowdsecJson = async (response, maxBytes = LAPI_MAX_RESPONSE_BYTES) => {
	try {
		return await readBoundedJson(response, maxBytes);
	} catch (err) {
		debug(logger, `CrowdSec response was invalid: ${err}`);
		throw publicError("crowdsec.invalid-response", 502);
	}
};

// the honeypot log lives on the anubis data volume, readable by the backend;
// newest-last per the writer (anubis appends), capped at the configured size
const readRecentHoneypotIps = async () => {
	let content;
	try {
		content = await readFile(HONEYPOT_LOG_PATH, "utf8");
	} catch (err) {
		if (err?.code === "ENOENT") return [];
		debug(logger, `Anubis honeypot log is unreadable: ${err}`);
		return [];
	}
	if (content.length > HONEYPOT_LOG_MAX_BYTES) {
		content = content.slice(-HONEYPOT_LOG_MAX_BYTES);
	}
	return content
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && line.length <= 45)
		.filter((line) => HONEYPOT_IP_PATTERN.test(line));
};

const lapiFetch = async (path) => {
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
	let password = "";
	try {
		password = (await readFile(LAPI_MACHINE_KEY_FILE, "utf8")).trim();
	} catch {
		// Handled below with a stable, localizable error code.
	}
	if (!password) throw publicError("crowdsec.not-wired-machine", 503);

	const fingerprint = createHash("sha256").update(password).digest("hex");
	if (
		machineTokenCache?.fingerprint === fingerprint &&
		machineTokenCache.expiresAt > Date.now() &&
		machineTokenCache.token
	) {
		return machineTokenCache.token;
	}

	const response = await fetchCrowdsec(`${LAPI_URL}/v1/watchers/login`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ machine_id: LAPI_MACHINE_ID, password }),
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

const lapiMachineFetch = async (path, method = "GET", mayRetry = true, body = null) => {
	const token = await lapiLogin();
	const options = {
		method,
		headers: { Authorization: `Bearer ${token}` },
	};
	if (body !== null) {
		options.headers["Content-Type"] = "application/json";
		options.body = JSON.stringify(body);
	}
	const response = await fetchCrowdsec(`${LAPI_URL}${path}`, options);
	if (response.status === 401 || response.status === 403) {
		machineTokenCache = null;
		if (mayRetry) return lapiMachineFetch(path, method, false, body);
		throw publicError("crowdsec.bad-machine-key", 502);
	}
	if (!response.ok) throw publicError("crowdsec.lapi-error", 502);
	return readCrowdsecJson(response);
};

const requireAdmin = async (res) => {
	const permission = await res.locals.access.can("admin:access").catch(() => null);
	return hasCrowdsecAdminAccess(permission);
};

const sendError = (req, res, next, err) => {
	debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
	if (err.public && err.status) {
		res.status(err.status).send({ error: { message: err.message } });
		return;
	}
	next(err);
};

router
	.route("/anubis")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const response = {
				configured: Boolean(ANUBIS_UPSTREAM),
				honeypot: { activeCount: 0, truncated: false, items: [] },
				container: { up: null, error: null },
				recent: [],
			};

			// 1. active honeypot bans straight from the LAPI, filtered by scenario.
			//    run in parallel with the other probes; a LAPI outage must not hide
			//    the container state and vice versa.
			const probes = [];
			probes.push(
				lapiFetch(`/v1/decisions?scenarios_containing=${HONEYPOT_SCENARIO}&limit=${LAPI_HONEYPOT_LIMIT + 1}`)
					.then((payload) => {
						const decisions = normalizeCrowdsecDecisions(payload);
						response.honeypot = {
							activeCount: decisions.length,
							truncated: decisions.length > LAPI_HONEYPOT_LIMIT,
							items: decisions.slice(0, LAPI_HONEYPOT_LIMIT),
						};
					})
					.catch((err) => {
						debug(logger, `Anubis honeypot decisions unavailable: ${err.message}`);
						throw err;
					}),
			);

			// 2. container health (only when wired up). anubis' /healthz lives on
			//    its separate metrics listener (:9090 by default) which this
			//    stack does not publish, so probing the auth_request upstream
			//    (the main :8923 listener) must treat ANY http response - even
			//    a 401/403 policy rejection or a redirect - as "the container is
			//    serving". only a network error/timeout means it is actually
			//    down, so follow no redirects and never throw on them.
			if (ANUBIS_UPSTREAM) {
				probes.push(
					fetchCrowdsec(ANUBIS_UPSTREAM, { method: "GET", redirect: "manual" }, ANUBIS_TIMEOUT_MS)
						.then(async (upstreamResponse) => {
							// discard the body but keep it bounded: it is a challenge page
							await readBoundedText(upstreamResponse, ANUBIS_MAX_RESPONSE_BYTES);
							response.container.up = true;
						})
						.catch((err) => {
							debug(logger, `Anubis upstream probe failed: ${err.message}`);
							response.container.up = false;
							response.container.error = "crowdsec.anubis-unreachable";
						}),
				);
			}

			// 3. recent honeypot catches from the log anubis writes on the shared
			//    data volume. the backend never writes it, it only reads.
			probes.push(
				readRecentHoneypotIps().then((ips) => {
					// newest-last from the log writer; the view wants newest-first
					response.recent = ips.slice(-20).reverse();
				}),
			);

			// the LAPI query is the only probe that must succeed; container state
			// and recent IPs degrade to neutral values instead of failing the page
			await Promise.all(probes);
			res.status(200).send(response);
		} catch (err) {
			sendError(req, res, next, err);
		}
	});

router
	.route("/decisions")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			// Ask for one extra row so the frontend receives an accurate cap signal.
			const payload = await lapiFetch(`/v1/decisions?limit=${LAPI_DECISION_LIMIT + 1}`);
			let decisions;
			try {
				decisions = normalizeCrowdsecDecisions(payload);
			} catch (err) {
				debug(logger, `CrowdSec decisions contract mismatch: ${err}`);
				throw publicError("crowdsec.invalid-response", 502);
			}
			res.status(200).send({
				items: decisions.slice(0, LAPI_DECISION_LIMIT),
				limit: LAPI_DECISION_LIMIT,
				truncated: decisions.length > LAPI_DECISION_LIMIT,
			});
		} catch (err) {
			sendError(req, res, next, err);
		}
	});

router
	.route("/decisions/delete")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const id = parseCrowdsecDecisionId(req.body?.id);
			if (!id) {
				res.status(400).send({ error: { message: "crowdsec.invalid-target" } });
				return;
			}

			// Record the operator's intent before changing CrowdSec. If this insert
			// fails, the external delete is not attempted.
			const auditEntry = await internalAuditLog.add(res.locals.access, {
				action: "delete-requested",
				object_type: "crowdsec-decision",
				object_id: id,
				meta: { decisionId: id, status: "requested" },
			});

			let result;
			try {
				result = await lapiMachineFetch(`/v1/decisions/${id}`, "DELETE");
			} catch (err) {
				try {
					await auditEntry.$query().patch({
						action: "delete-failed",
						meta: {
							decisionId: id,
							status: "failed",
							error: err.public ? err.message : "crowdsec.lapi-error",
						},
					});
				} catch (auditErr) {
					logger.warn(`Could not finalize failed CrowdSec audit entry ${auditEntry.id}: ${auditErr}`);
				}
				throw err;
			}

			const nbDeleted = String(result?.nbDeleted ?? "0");
			let auditLogged = true;
			try {
				await auditEntry.$query().patch({
					action: "deleted",
					meta: { decisionId: id, status: "deleted", nbDeleted },
				});
			} catch (auditErr) {
				auditLogged = false;
				logger.warn(`Could not finalize successful CrowdSec audit entry ${auditEntry.id}: ${auditErr}`);
			}

			res.status(200).send({ nbDeleted, audit_logged: auditLogged });
		} catch (err) {
			sendError(req, res, next, err);
		}
	});

router
	.route("/alerts")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const { scope, value } = req.query;
			if (
				typeof scope !== "string" ||
				!SCOPE_PATTERN.test(scope) ||
				typeof value !== "string" ||
				value.length === 0 ||
				value.length > 512
			) {
				res.status(400).send({ error: { message: "crowdsec.invalid-target" } });
				return;
			}

			const query = new URLSearchParams({
				scope,
				value,
				limit: String(LAPI_ALERT_LIMIT),
				with_decisions: "false",
			});
			const payload = await lapiMachineFetch(`/v1/alerts?${query}`);
			let alerts;
			try {
				alerts = normalizeCrowdsecAlerts(payload);
			} catch (err) {
				debug(logger, `CrowdSec alerts contract mismatch: ${err}`);
				throw publicError("crowdsec.invalid-response", 502);
			}
			res.status(200).send(alerts);
		} catch (err) {
			sendError(req, res, next, err);
		}
	});

// manual ban: the LAPI accepts an alert wrapper whose decision carries
// origin "cscli", so the ban appears like a cscli decisions add - the same
// pattern the crowdsec cli and other dashboards use
router
	.route("/decisions")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const { value, duration, type, reason } = req.body ?? {};
			const errors = validateManualBan({ value, duration, type, reason });
			if (errors.length > 0) {
				res.status(400).send({ error: { message: "crowdsec.invalid-ban-input", fields: errors } });
				return;
			}

			// Record the operator's intent before changing CrowdSec.
			const auditEntry = await internalAuditLog.add(res.locals.access, {
				action: "create",
				object_type: "crowdsec-decision",
				object_id: 0,
				meta: { value, duration, type, reason, status: "requested", manual: true },
			});

			const now = new Date().toISOString();
			// ip scope for plain addresses, range scope for cidr targets
			const scope = value.includes("/") ? "range" : "ip";
			const payload = [
				{
					scenario: MANUAL_BAN_SCENARIO,
					message: reason ? `Manual ban from NPMplus: ${reason}` : "Manual ban from NPMplus",
					events_count: 1,
					start_at: now,
					stop_at: now,
					capacity: 0,
					leakspeed: "0",
					simulated: false,
					events: [],
					scenario_hash: "",
					scenario_version: "",
					source: { scope, value },
					decisions: [
						{
							type,
							duration,
							value,
							scope,
							origin: "cscli",
							scenario: MANUAL_BAN_SCENARIO,
						},
					],
				},
			];

			let result;
			try {
				result = await lapiMachineFetch("/v1/alerts", "POST", true, payload);
			} catch (err) {
				try {
					await auditEntry.$query().patch({
						action: "create-failed",
						meta: { value, duration, type, reason, status: "failed", error: err.message },
					});
				} catch (auditErr) {
					logger.warn(`Could not finalize failed CrowdSec audit entry ${auditEntry.id}: ${auditErr}`);
				}
				throw err;
			}

			let auditLogged = true;
			try {
				await auditEntry.$query().patch({
					action: "created",
					object_id: 0,
					meta: { value, duration, type, reason, status: "created", manual: true },
				});
			} catch (auditErr) {
				auditLogged = false;
				logger.warn(`Could not finalize successful CrowdSec audit entry ${auditEntry.id}: ${auditErr}`);
			}

			res.status(200).send({ created: true, audit_logged: auditLogged, result });
		} catch (err) {
			sendError(req, res, next, err);
		}
	});

// insights: a live 24h aggregation over recent alerts - top countries,
// ASNs and scenarios plus the alert count. computed per request, no cache
router
	.route("/insights")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const query = new URLSearchParams({
				since: `${INSIGHTS_WINDOW_HOURS}h`,
				limit: String(INSIGHTS_ALERT_LIMIT),
			});
			const payload = await lapiMachineFetch(`/v1/alerts?${query}`);
			const alerts = normalizeCrowdsecAlerts(payload);

			const top = (counts) =>
				Object.entries(counts)
					.sort((a, b) => b[1] - a[1])
					.slice(0, INSIGHTS_TOP_N)
					.map(([name, count]) => ({ name, count }));

			const countries = {};
			const asns = {};
			const scenarios = {};
			for (const alert of alerts) {
				if (alert.scenario) scenarios[alert.scenario] = (scenarios[alert.scenario] ?? 0) + 1;
				const country = alert.source?.country;
				if (country) countries[country] = (countries[country] ?? 0) + 1;
				const asn = alert.source?.as_name || (alert.source?.as_number ? `AS${alert.source.as_number}` : "");
				if (asn) asns[asn] = (asns[asn] ?? 0) + 1;
			}

			res.status(200).send({
				window_hours: INSIGHTS_WINDOW_HOURS,
				alert_count: alerts.length,
				top_scenarios: top(scenarios),
				top_countries: top(countries),
				top_asns: top(asns),
			});
		} catch (err) {
			sendError(req, res, next, err);
		}
	});

export default router;
