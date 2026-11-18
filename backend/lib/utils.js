import { execFile as nodeExecFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Liquid } from "liquidjs";
import { debug, global as logger } from "../logger.js";
import { getEnvironmentHash } from "./environment-hash.js";
import errs from "./error.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const nodeExecFilePromises = promisify(nodeExecFile);

/**
 * @param   {String} cmd
 * @param   {Array}  args
 * @param   {Boolean} [silent]
 * @returns {Promise}
 */
const execFile = async (cmd, args, silent) => {
	if (!silent) debug(logger, `CMD: ${cmd} ${args ? args.join(" ") : ""}`);

	try {
		const { stdout, stderr } = await nodeExecFilePromises(cmd, args);
		return `${stdout || ""}${stderr || ""}`.trim();
	} catch (err) {
		throw new errs.CommandError(`${err.stdout || ""}${err.stderr || ""}`.trim(), { cause: err });
	}
};

const controlCharPattern = /\p{Cc}/u;
const tokenBreakPattern = /[\s;{\\]/u;
const tokenStartPattern = /^[}#"']/u;
const quoteEscapePattern = /["\\]/gu;

const assertNginxValue = (value, quoted = false) => {
	if (
		controlCharPattern.test(value) ||
		(!quoted && (tokenBreakPattern.test(value) || tokenStartPattern.test(value)))
	) {
		throw new errs.ValidationError(`${JSON.stringify(value)} can not be used in the nginx config`);
	}
	return value;
};

const nginxQuote = (value) => `"${assertNginxValue(value, true).replaceAll(quoteEscapePattern, "\\$&")}"`;

const quotedPattern = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/gu;
const commentPattern = /(?:^|\s)#.*/u;

const reindent = (text) => {
	let depth = 0;
	return text
		.split("\n")
		.map((line) => line.trim())
		.filter((line, index, lines) => line !== "" || lines[index - 1] !== "")
		.map((line) => {
			const code = line.replace(quotedPattern, "").replace(commentPattern, "");
			const net = code.split("{").length - code.split("}").length;
			depth += net;
			return line && "  ".repeat(Math.max(0, depth - Math.max(0, net))) + line;
		})
		.join("\n");
};

const renderEngine = new Liquid({
	root: `${import.meta.dirname}/../templates/`,
	outputEscape: assertNginxValue,
	cache: true,
});

/**
 * nginxAccessRule expects the object given to have 2 properties:
 *
 * directive  string
 * address    string
 */
renderEngine.registerFilter("nginxAccessRule", {
	raw: true,
	handler: (v) => {
		if (v.directive && v.address) {
			// legacy rows may carry nginx syntax; drop the rule instead of
			// failing the whole config regeneration (deny-all stays in effect)
			if (accessRuleSyntaxPattern.test(v.address)) return "";
			return `${assertNginxValue(v.directive)} ${assertNginxValue(v.address)};`;
		}
		return "";
	},
});

// nginx metacharacters (incl. whitespace) must never survive into an
// allow/deny address or an auth-request upstream: both render into
// generated nginx configs
const accessRuleSyntaxPattern = /[\s;{}$#"'\\]/u;
const authRequestUpstreamPattern = /^https?:\/\/([^/:]+|\[[a-fA-F0-9:]+\]):[0-9]+$/u;

/**
 * Auth-request upstreams must be a bare scheme://host:port - the same shape
 * envs.sh enforces for AUTH_REQUEST_*_UPSTREAM. Anything else is treated as
 * absent when picking the effective upstream so a stored payload can never
 * reach a config template.
 *
 * @param   {String}  value
 * @returns {Boolean}
 */
const isValidAuthRequestUpstream = (value) => typeof value === "string" && authRequestUpstreamPattern.test(value);

const writeHash = async () => {
	await writeFile("/data/npmplus/env.sha512sum", await getEnvironmentHash());
};

// The fork renders pre-parsed templates through a shared engine. The upstream
// renderEngine above stays for internals that call renderFile directly.
let sharedRenderEngine = null;
const parsedTemplates = new Map();

const getRenderEngine = () => {
	if (sharedRenderEngine === null) {
		sharedRenderEngine = new Liquid({
			root: `${__dirname}/../templates/`,
		});

		sharedRenderEngine.registerFilter("nginxAccessRule", (v) => {
			if (typeof v.directive !== "undefined" && typeof v.address !== "undefined" && v.directive && v.address) {
				// addresses render into generated nginx configs; a row stored
				// before the schema pattern existed may still carry nginx
				// syntax, so drop such rules instead of rendering them
				// (the deny-all default stays in effect)
				if (accessRuleSyntaxPattern.test(v.address)) return "";
				return `${v.directive} ${v.address};`;
			}
			return "";
		});
	}

	return sharedRenderEngine;
};

/**
 * @param   {String}  templatePath
 * @returns {Promise<Object>} parsed Liquid template
 */
const getParsedTemplate = async (templatePath) => {
	let template = parsedTemplates.get(templatePath);
	if (template === undefined) {
		template = getRenderEngine().parse(await readFile(templatePath, { encoding: "utf8" }));
		parsedTemplates.set(templatePath, template);
	}
	return template;
};

export default {
	assertNginxValue,
	execFile,
	getParsedTemplate,
	getRenderEngine,
	isValidAuthRequestUpstream,
	nginxQuote,
	reindent,
	renderEngine,
	writeHash,
};
