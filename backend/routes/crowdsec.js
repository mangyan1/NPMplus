import { readFile } from "node:fs/promises";
import express from "express";
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
			const permission = await res.locals.access.can("admin:access").catch(() => null);
			if (!permission) {
				res.status(403).send({ error: { message: "access.denied" } });
				return;
			}

			const decisions = await lapiFetch("/v1/decisions");
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

export default router;
