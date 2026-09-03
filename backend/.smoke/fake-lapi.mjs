// fake crowdsec LAPI for smoke testing the crowdsec routes.
// serves the four wire shapes the backend talks to, asserts the auth
// headers on every request, and logs what it saw to lapi-requests.json
import { writeFileSync } from "node:fs";
import http from "node:http";

const BOUNCER_KEY = "smoke-bouncer-key-1234567890abcdef";
const MACHINE_ID = "npmplus-ui";
const MACHINE_PASSWORD = "smoke-machine-password-123456";
const JWT = "smoke-machine-jwt";

const requests = [];
const log = (entry) => {
	requests.push(entry);
	writeFileSync(new URL("./lapi-requests.json", import.meta.url), JSON.stringify(requests, null, 2));
};

const in2h = new Date(Date.now() + 2 * 3600 * 1000).toISOString();
const in30s = new Date(Date.now() + 30 * 1000).toISOString();
const past = new Date(Date.now() - 3600 * 1000).toISOString();
const in3d = new Date(Date.now() + 3 * 86400 * 1000).toISOString();

const decisions = [
	{
		id: 4,
		uuid: "d4",
		scope: "Ip",
		value: "203.0.113.9",
		type: "ban",
		origin: "cscli",
		scenario: "anubis-honeypot",
		duration: "24h",
		until: in3d,
		simulated: false,
	},
	{
		id: 3,
		uuid: "d3",
		scope: "Ip",
		value: "198.51.100.7",
		type: "ban",
		origin: "crowdsecurity/http-probing",
		scenario: "crowdsecurity/http-probing",
		duration: "4h",
		until: in2h,
		simulated: false,
	},
	{
		id: 2,
		uuid: "d2",
		scope: "Ip",
		value: "192.0.2.55",
		type: "ban",
		origin: "capi",
		scenario: "crowdsecurity/ssh-bf",
		duration: "1h",
		until: in30s,
		simulated: false,
	},
	{
		id: 1,
		uuid: "d1",
		scope: "Ip",
		value: "192.0.2.10",
		type: "ban",
		origin: "cscli",
		scenario: "manual",
		duration: "1h",
		until: past,
		simulated: true,
	},
];

const alerts = [
	{
		id: 99,
		message: "http-probing from 198.51.100.7",
		scenario: "crowdsecurity/http-probing",
		started_at: new Date(Date.now() - 3600 * 1000).toISOString(),
		events_count: 6,
		events: [{}],
	},
];

const server = http.createServer((req, res) => {
	const url = new URL(req.url, "http://localhost");
	const record = { method: req.method, path: url.pathname, query: url.searchParams.toString() };

	let body = "";
	req.on("data", (c) => (body += c));
	req.on("end", () => {
		const send = (code, data) => {
			record.status = code;
			log(record);
			res.writeHead(code, { "Content-Type": "application/json" });
			res.end(JSON.stringify(data));
		};

		if (url.pathname === "/v1/decisions" && req.method === "GET") {
			if (req.headers["x-api-key"] !== BOUNCER_KEY) return send(403, { message: "bad bouncer key" });
			// the anubis endpoint filters by scenario; emulate the lapi's
			// scenarios_containing filter so both routes see realistic shapes
			const scenarios = url.searchParams.get("scenarios_containing");
			if (scenarios) {
				return send(
					200,
					decisions.filter((d) => d.scenario.includes(scenarios)),
				);
			}
			return send(200, decisions);
		}
		if (url.pathname === "/v1/watchers/login" && req.method === "POST") {
			const creds = JSON.parse(body);
			if (creds.machine_id !== MACHINE_ID || creds.password !== MACHINE_PASSWORD)
				return send(401, { message: "bad machine" });
			return send(200, { code: 200, expire: "1h", token: JWT });
		}
		if (url.pathname === "/v1/decisions" && req.method === "DELETE") {
			if (req.headers.authorization !== `Bearer ${JWT}`) return send(403, { message: "no bearer" });
			return send(200, { nbDeleted: String(1) });
		}
		// id-based delete: the current unban contract (DELETE /v1/decisions/:id)
		if (url.pathname.startsWith("/v1/decisions/") && req.method === "DELETE") {
			if (req.headers.authorization !== `Bearer ${JWT}`) return send(403, { message: "no bearer" });
			const id = Number(url.pathname.split("/").pop());
			const index = decisions.findIndex((d) => d.id === id);
			if (index >= 0) decisions.splice(index, 1);
			return send(200, { nbDeleted: index >= 0 ? "1" : "0" });
		}
		if (url.pathname === "/v1/alerts" && req.method === "GET") {
			if (req.headers.authorization !== `Bearer ${JWT}`) return send(403, { message: "no bearer" });
			return send(
				200,
				alerts.filter((a) => url.searchParams.get("value") === "198.51.100.7"),
			);
		}
		send(404, { message: `unexpected ${req.method} ${url.pathname}` });
	});
});

await new Promise((resolve) => server.listen(18080, "127.0.0.1", resolve));
console.log("fake LAPI on 18080");
