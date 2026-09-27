import crypto from "node:crypto";
import cookieParser from "cookie-parser";
import express from "express";
import multer from "multer";
import { jsonReplacer } from "./lib/helpers.js";
import { debug, express as logger } from "./logger.js";
import mainRoutes from "./routes/main.js";

Object.assign(multer.MulterError.prototype, { public: true, status: 400 });

/**
 * App
 */
const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.set("json spaces", 2);
app.set("json replacer", jsonReplacer);

app.use(cookieParser(process.env.COOKIE_SECRET || crypto.randomBytes(16).toString("hex")));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb", parameterLimit: 1000 }));

/**
 * General Logging, BEFORE routes
 */

app.use((req, res, next) => {
	if (
		req.method === "GET" &&
		req.path === "/api/oidc/callback" &&
		req.get("sec-fetch-mode") === "navigate" &&
		req.get("sec-fetch-dest") === "document"
	) {
		return next();
	}

	if (req.get("origin") && req.get("origin") !== `${req.protocol}://${req.host}`) {
		return res.status(403).json({
			error: { message: "Rejected Origin." },
		});
	}
	if (["same-origin", "none", undefined].includes(req.get("sec-fetch-site"))) {
		return next();
	}

	res.status(403).json({
		error: { message: "Rejected Sec-Fetch-Site Value." },
	});
});

app.use("/", mainRoutes);

// production error handler
// no stacktraces leaked to user
app.use((err, req, res, _) => {
	const status = err.status || 500;
	const exposed = err.public || err.expose;
	const requestId = crypto.randomUUID();
	const payload = {
		error: {
			code: status,
			message: exposed ? err.message : "Internal Error",
			request_id: requestId,
		},
	};

	if (err.message_i18n) {
		payload.error.message_i18n = err.message_i18n;
	}

	// Subprocess failures can contain credentials and paths. Keep diagnostics
	// server-side, including when the public message is deliberately generic.
	// The upstream "error.output" variant would publish raw certbot stdout and
	// stderr to the browser, so it is intentionally not merged here.

	// Not every error is worth logging - but this is good for now until it gets annoying.
	if (typeof err.stack !== "undefined" && err.stack) {
		debug(logger, `[${requestId}] ${err.stack}`);
		if (!exposed) {
			logger.warn(`[${requestId}] ${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
		}
	}

	res.status(err.status || 500).send(payload);
});

export default app;
