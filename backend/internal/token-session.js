import crypto from "node:crypto";
import db from "../db.js";
import errs from "../lib/error.js";
import TokenModel from "../models/token.js";

const sessions = () => db()("npmplus_token_session");
const now = () => Math.floor(Date.now() / 1000);

export const assertTokenSession = async (sid) => {
	if (typeof sid !== "string" || !(await sessions().where({ id: sid }).where("expires_at", ">", now()).first())) {
		throw new errs.AuthError("Session has expired or been revoked");
	}
};

// Every refresh keeps the same session identity. Updating an existing row
// (never upserting it) prevents a concurrent refresh from undoing logout.
export const issueSessionToken = async (token, payload, sid = null) => {
	const issuedAt = payload.iat ?? now();
	const lifetime = payload.expiresIn === "3m" ? 180 : 3600;
	const id = sid ?? crypto.randomBytes(24).toString("base64url");
	const signed = await token.create({ ...payload, sid: id, iat: issuedAt });
	if (sid) {
		const updated = await sessions()
			.where({ id })
			.where("expires_at", ">", now())
			.update({ expires_at: issuedAt + lifetime });
		if (!updated) throw new errs.AuthError("Session has expired or been revoked");
	} else {
		await sessions().where("expires_at", "<=", now()).delete();
		await sessions().insert({ id, expires_at: issuedAt + lifetime });
	}
	return signed;
};

export const revokeTokenSession = async (cookie) => {
	if (!cookie) return;
	let payload;
	try {
		payload = await TokenModel().load(cookie);
	} catch {
		// Expired/invalid cookies must still be clearable. Database failures below
		// remain errors: do not report successful logout if revocation failed.
		return;
	}
	if (typeof payload.sid === "string") await sessions().where({ id: payload.sid }).delete();
};
