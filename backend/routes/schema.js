import express from "express";
import requireLogin from "../lib/express/require-login.js";
import { compiledSchema } from "../schema/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router
	.route("/")
	.all(requireLogin())

	/**
	 * GET /schema
	 */
	.get((_, res) => {
		res.status(200)
			.type("json")
			.send(JSON.stringify(compiledSchema, null, res.app.get("json spaces")));
	});

export default router;
