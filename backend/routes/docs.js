import express from "express";
import swaggerUi from "swagger-ui-express";
import requireLogin from "../lib/express/require-login.js";
import PACKAGE from "../package.json" with { type: "json" };
import { getCompiledSchema } from "../schema/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router.use("/", requireLogin(), swaggerUi.serve);

router
	.route("/")

	/**
	 * GET / (Now serves the Swagger UI interface)
	 */
	.get(async (_req, res, _next) => {
		const swaggerJSON = await getCompiledSchema();
		swaggerJSON.info.version = PACKAGE.version;
		swaggerJSON.servers[0].url = "/api";
		res.status(200).send(swaggerUi.generateHTML(swaggerJSON));
	});

export default router;
