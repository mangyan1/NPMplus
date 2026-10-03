import net from "node:net";
import { publicError } from "./crowdsec.js";

const STATES = new Set(["idle", "running", "enabled", "failed", "rollback-failed"]);
const REASONS = new Set(["busy", "unsupported", "cooldown"]);

// Only fixed verbs cross this boundary. The host never receives a command,
// filename, URL, credentials, or user-controlled policy from the web app.
export const createCrsControl = (socketPath = "/run/npmplus-crs-control/control.sock") => {
	const exchange = (verb) =>
		new Promise((resolve, reject) => {
			const socket = net.createConnection(socketPath);
			let body = "";
			const finish = (error, result) => {
				clearTimeout(timer);
				socket.destroy();
				if (error) reject(publicError("crowdsec.crs.control-unavailable", 503));
				else resolve(result);
			};
			const timer = setTimeout(() => finish(true), 3000);
			socket.on("error", () => finish(true));
			socket.on("connect", () => socket.write(`${verb}\n`));
			socket.on("data", (chunk) => {
				body += chunk.toString("utf8");
				if (Buffer.byteLength(body) > 1024) return finish(true);
				if (body.endsWith("\n")) {
					try {
						finish(false, JSON.parse(body));
					} catch {
						finish(true);
					}
				}
			});
			socket.on("end", () => {
				if (!body.endsWith("\n")) finish(true);
			});
		});
	return {
		status: async () => {
			const data = await exchange("STATUS").catch(() => null);
			if (
				data?.version !== 1 ||
				data.available !== true ||
				typeof data.eligible !== "boolean" ||
				typeof data.enabled !== "boolean" ||
				!STATES.has(data.state)
			)
				return { available: false, eligible: false, enabled: false, state: "unavailable" };
			return {
				available: true,
				eligible: data.eligible,
				enabled: data.enabled,
				state: data.state,
				retry_after: Number.isSafeInteger(data.retry_after) ? Math.min(300, Math.max(0, data.retry_after)) : 0,
			};
		},
		enable: async () => {
			const data = await exchange("ENABLE");
			if (data?.accepted === true && ["running", "enabled"].includes(data.state))
				return { accepted: true, state: data.state };
			if (data?.accepted === false && REASONS.has(data.reason))
				throw publicError(`crowdsec.crs.control-${data.reason}`, data.reason === "cooldown" ? 429 : 409);
			throw publicError("crowdsec.crs.control-unavailable", 503);
		},
	};
};

export default createCrsControl();
