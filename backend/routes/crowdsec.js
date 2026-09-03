import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";
import express from "express";
import internalAuditLog from "../internal/audit-log.js";
import { fetchWithTimeout, readBoundedJson } from "../lib/bounded-fetch.js";
import {
	hasCrowdsecAdminAccess,
	normalizeCrowdsecAlerts,
	normalizeCrowdsecDecisions,
	parseCrowdsecDecisionId,
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
const MACHINE_TOKEN_TTL_MS = 30 * 1000;
const SCOPE_PATTERN = /^[a-zA-Z]{1,32}$/;
const configuredTimeout = Number.parseInt(process.env.CROWDSEC_LAPI_TIMEOUT_MS || "5000", 10);
const LAPI_TIMEOUT_MS = Number.isFinite(configuredTimeout) && configuredTimeout > 0 ? configuredTimeout : 5000;
const LAPI_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

const publicError = (message, status) => Object.assign(new Error(message), { public: true, status });

const fetchCrowdsec = async (url, options) => {
	try {
		return await fetchWithTimeout(url, options, LAPI_TIMEOUT_MS);
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

const lapiMachineFetch = async (path, method = "GET", mayRetry = true) => {
	const token = await lapiLogin();
	const response = await fetchCrowdsec(`${LAPI_URL}${path}`, {
		method,
		headers: { Authorization: `Bearer ${token}` },
	});
	if (response.status === 401 || response.status === 403) {
		machineTokenCache = null;
		if (mayRetry) return lapiMachineFetch(path, method, false);
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

export default router;
