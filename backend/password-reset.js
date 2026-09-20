#!/usr/bin/env node

// based on: https://github.com/jlesage/docker-nginx-proxy-manager/blob/796734a3f9a87e0b1561b47fd418f82216359634/rootfs/opt/nginx-proxy-manager/bin/reset-password

import { existsSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { hash } from "./lib/argon2.js";

function usage() {
	console.log(`usage: ${process.argv[1]} USER_EMAIL [--password-stdin] [--disable-mfa]

	Reset the password and/or disable MFA of a NPMplus user.

	Arguments:
	USER_EMAIL      Email address of the user.
	Options:
	--password-stdin Read the new password from standard input so it is not exposed in the process list.
	--disable-mfa   Disable TOTP and delete the backup codes of the user.`);
	process.exit(1);
}

const args = process.argv.slice(2);
const DISABLE_MFA = args.includes("--disable-mfa");
if (DISABLE_MFA) args.splice(args.indexOf("--disable-mfa"), 1);
const PASSWORD_STDIN = args.includes("--password-stdin");
if (PASSWORD_STDIN) args.splice(args.indexOf("--password-stdin"), 1);
const EMAIL = args[0]?.toLowerCase().trim();
if (args.length > 1 || args.some((arg) => arg.startsWith("--"))) usage();
const PASSWORD = PASSWORD_STDIN ? readFileSync(0, "utf8").replace(/\r?\n$/, "") : undefined;

if (!EMAIL || (PASSWORD_STDIN && !PASSWORD) || (!PASSWORD_STDIN && !DISABLE_MFA)) {
	if (!EMAIL) console.error("ERROR: User email address must be set.");
	if (PASSWORD_STDIN && !PASSWORD) console.error("ERROR: Standard input did not contain a password.");
	if (!PASSWORD_STDIN && !DISABLE_MFA) console.error("ERROR: --password-stdin and/or --disable-mfa must be set.");
	usage();
}

if (!existsSync("/data/npmplus/database.sqlite")) {
	console.error("ERROR: Cannot connect to the sqlite database.");
	process.exit(1);
}

let db;
try {
	db = new DatabaseSync("/data/npmplus/database.sqlite");

	const auth = db
		.prepare(
			"SELECT auth.user_id FROM auth JOIN user ON user.id = auth.user_id WHERE auth.type = 'password' AND auth.is_deleted = 0 AND user.is_deleted = 0 AND user.email = ?",
		)
		.get(EMAIL);

	if (auth) {
		if (PASSWORD) {
			db.prepare(
				"UPDATE auth SET secret = ?, modified_on = datetime('now','localtime') WHERE user_id = ? AND type = 'password'",
			).run(await hash(PASSWORD), auth.user_id);
			db.prepare("UPDATE user SET npmplus_token_valid_after = ? WHERE id = ?").run(
				Math.floor(Date.now() / 1000),
				auth.user_id,
			);
			console.log(`Password for user ${EMAIL} has been reset.`);
		}

		if (DISABLE_MFA) {
			db.prepare("DELETE FROM auth WHERE user_id = ? AND type IN ('totp', 'totp_pending', 'backup_code')").run(
				auth.user_id,
			);
			console.log(`MFA for user ${EMAIL} has been disabled.`);
		}
	} else {
		console.log(`No user found with email ${EMAIL}.`);
		process.exitCode = 1;
	}
} catch (error) {
	console.error(error);
	process.exitCode = 1;
} finally {
	if (db) db.close();
}
