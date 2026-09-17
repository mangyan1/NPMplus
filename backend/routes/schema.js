import express from "express";
import requireLogin from "../lib/express/require-login.js";
import PACKAGE from "../package.json" with { type: "json" };
import { getCompiledSchema } from "../schema/index.js";

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
	.get(async (_req, res, _next) => {
		const swaggerJSON = await getCompiledSchema();
		swaggerJSON.info.version = PACKAGE.version;
		swaggerJSON.servers[0].url = "/api";
		res.status(200).send(swaggerJSON);
	});

export default router;
