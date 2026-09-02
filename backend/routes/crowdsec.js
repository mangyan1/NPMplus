import { readFile } from "node:fs/promises";
import process from "node:process";
import express from "express";
import internalAuditLog from "../internal/audit-log.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

// the setup script registers a dedicated bouncer and writes its key here,
// so the admin UI can read the local api without a machine account
const LAPI_KEY_FILE = process.env.CROWDSEC_LAPI_KEY_FILE || "/data/crowdsec/lapi-ui.key";
const LAPI_URL = process.env.CROWDSEC_LAPI_URL || "http://127.0.0.1:8080";

// deleting decisions and reading alerts is machine-only in the lapi, so the
// setup script also registers a machine and stores its password here
const LAPI_MACHINE_ID = process.env.CROWDSEC_LAPI_MACHINE_ID || "npmplus-ui";
const LAPI_MACHINE_KEY_FILE = process.env.CROWDSEC_LAPI_MACHINE_KEY_FILE || "/data/crowdsec/lapi-ui-machine.key";

// cap on how many decisions one poll pulls: keeps the 10s live view light on
// busy installs. the frontend notes when the list is at the cap.
const LAPI_DECISION_LIMIT = 200;

// live decisions need a fresh key read: the file is rotated on re-runs
const lapiFetch = async (path) => {
	let key;
	try {
		key = (await readFile(LAPI_KEY_FILE, "utf8")).trim();
	} catch {
		key = "";
	}
	if (!key) {
		// missing or empty key file: same hint as not wired at all,
		// the message doubles as an i18n key for the page's alert
		const err = new Error("crowdsec.not-wired");
		err.status = 503;
		throw err;
	}
	const response = await fetch(`${LAPI_URL}${path}`, { headers: { "X-Api-Key": key } });
	if (!response.ok) {
		// a rejected key means the bouncer was deleted or the file is stale,
		// anything else is a real lapi problem worth seeing the status of
		const err = new Error(
			response.status === 401 || response.status === 403
				? "crowdsec.bad-key"
				: `crowdsec LAPI answered ${response.status}`,
		);
		err.status = 502;
		throw err;
	}
	return response.json();
};

// machine login for the endpoints a bouncer key cannot serve (alerts, deletes).
// unbans and context views are rare operator actions, so no token caching:
// one login per request keeps the credentials always-fresh from the file
const lapiLogin = async () => {
	let password;
	try {
		password = (await readFile(LAPI_MACHINE_KEY_FILE, "utf8")).trim();
	} catch {
		password = "";
	}
	if (!password) {
		const err = new Error("crowdsec.not-wired-machine");
		err.status = 503;
		throw err;
	}
	const response = await fetch(`${LAPI_URL}/v1/watchers/login`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ machine_id: LAPI_MACHINE_ID, password }),
	});
	if (!response.ok) {
		const err = new Error(
			response.status === 401 || response.status === 403
				? "crowdsec.bad-machine-key"
				: `crowdsec LAPI login answered ${response.status}`,
		);
		err.status = 502;
		throw err;
	}
	const body = await response.json();
	if (!body?.token) {
		const err = new Error("crowdsec LAPI login returned no token");
		err.status = 502;
		throw err;
	}
	return body.token;
};

// any request the machine jwt serves
const lapiMachineFetch = async (path, method = "GET") => {
	const token = await lapiLogin();
	const response = await fetch(`${LAPI_URL}${path}`, {
		method,
		headers: { Authorization: `Bearer ${token}` },
	});
	if (!response.ok) {
		const err = new Error(
			response.status === 401 || response.status === 403
				? "crowdsec.bad-machine-key"
				: `crowdsec LAPI answered ${response.status}`,
		);
		err.status = 502;
		throw err;
	}
	return response.json();
};

// the admin gate every crowdsec endpoint shares, mirrors the audit log's
const requireAdmin = async (res) => {
	const permission = await res.locals.access.can("admin:access").catch(() => null);
	if (!permission) {
		return false;
	}
	return true;
};

/**
 * /api/crowdsec
 *
 * Read-only view over the local crowdsec api: what is currently banned
 * (active decisions), by which scenario, until when. Admin only.
 */
router
	.route("/decisions")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/crowdsec/decisions
	 *
	 * Active decisions, newest first. Includes everything the bouncers see:
	 * scenario bans, honeypot bans (origin cscli, scenario anubis-honeypot)
	 * and community/capi blocks.
	 */
	.get(async (req, res, next) => {
		try {
			// crowdsec intel is admin territory, same gate as the audit log
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const decisions = await lapiFetch(`/v1/decisions?limit=${LAPI_DECISION_LIMIT}`);
			res.status(200).send(decisions ?? []);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
			if (err.status) {
				res.status(err.status).send({ error: { message: err.message } });
				return;
			}
			next(err);
		}
	});

/**
 * POST /api/crowdsec/decisions/delete
 *
 * Unban: delete the active decision(s) for one scope/value pair, the same
 * thing `cscli decisions delete` does. Admin only, and every unban lands in
 * the audit log so lifted bans leave a trail.
 */
router
	.route("/decisions/delete")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			if (!(await requireAdmin(res))) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const { scope, value } = req.body ?? {};
			// scope comes from the lapi's own decision rows, but this endpoint
			// is still a trust boundary: keep both to tight shapes and let
			// URLSearchParams do the query encoding
			if (
				typeof scope !== "string" ||
				!/^[a-zA-Z]{1,32}$/.test(scope) ||
				typeof value !== "string" ||
				value.length === 0 ||
				value.length > 512
			) {
				res.status(400).send({ error: { message: "crowdsec.invalid-target" } });
				return;
			}

			const query = new URLSearchParams({ scope, value });
			const result = await lapiMachineFetch(`/v1/decisions?${query}`, "DELETE");

			await internalAuditLog.add(res.locals.access, {
				action: "deleted",
				object_type: "crowdsec-decision",
				object_id: 0,
				meta: { scope, value, nbDeleted: result?.nbDeleted ?? "0" },
			});

			res.status(200).send(result ?? { nbDeleted: "0" });
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
			if (err.status) {
				res.status(err.status).send({ error: { message: err.message } });
				return;
			}
			next(err);
		}
	});

/**
 * GET /api/crowdsec/alerts?scope=..&value=..
 *
 * The alert that produced a decision, with the triggering events, so an
 * operator can judge a false positive before unbanning. Machine-only in
 * the lapi, capped to the newest few alerts for the one target. Admin only.
 */
router
	.route("/alerts")
	.options((_, res) => {
		res.sendStatus(204);
	})
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
				!/^[a-zA-Z]{1,32}$/.test(scope) ||
				typeof value !== "string" ||
				value.length === 0 ||
				value.length > 512
			) {
				res.status(400).send({ error: { message: "crowdsec.invalid-target" } });
				return;
			}

			const query = new URLSearchParams({ scope, value, limit: "5" });
			const alerts = await lapiMachineFetch(`/v1/alerts?${query}`);
			res.status(200).send(alerts ?? []);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
			if (err.status) {
				res.status(err.status).send({ error: { message: err.message } });
				return;
			}
			next(err);
		}
	});

export default router;
