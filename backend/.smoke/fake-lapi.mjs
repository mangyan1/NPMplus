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
		events_count: 2,
		source: {
			ip: "198.51.100.7",
			cn: "DE",
			as_number: "64496",
			as_name: "Example ASN",
			range: "198.51.100.0/24",
			rdns: "host.example.com",
		},
		events: [
			{
				timestamp: new Date(Date.now() - 3600 * 1000).toISOString(),
				meta: [
					{ key: "source_ip", value: "198.51.100.7" },
					{ key: "method", value: "GET" },
					{ key: "target_uri", value: "/.env" },
					{ key: "http_user_agent", value: "python-requests/2.31" },
					{ key: "raw_request", value: "GET /.env HTTP/1.1" },
				],
			},
		],
	},
	// second recent alert: different scenario + country, feeds the insights
	// aggregation with more than one bucket per column
	{
		id: 100,
		message: "ssh brute force from 203.0.113.20",
		scenario: "crowdsecurity/ssh-bf",
		started_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
		events_count: 1,
		source: {
			ip: "203.0.113.20",
			cn: "FR",
			as_number: "64500",
			as_name: "Second ASN",
			range: "203.0.113.0/24",
			rdns: "host2.example.com",
		},
		events: [],
	},
	// old alert beyond the 24h insights window: must not be aggregated
	{
		id: 101,
		message: "stale alert from three days ago",
		scenario: "crowdsecurity/http-bad-user-agent",
		started_at: new Date(Date.now() - 3 * 86400 * 1000).toISOString(),
		events_count: 1,
		source: {
			ip: "192.0.2.99",
			cn: "JP",
			as_number: "64501",
			as_name: "Stale ASN",
			range: "192.0.2.0/24",
			rdns: "stale.example.com",
		},
		events: [],
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
			// crowdsec's lapi validates the client user agent against the machine
			// registration (a bare "node" agent is rejected); enforce the same rule
			// here so the backend can never regress to an anonymous login
			if (!/^npmplus-ui-backend\//.test(req.headers["user-agent"] || "")) {
				return send(401, { code: 401, message: "incorrect Username or Password" });
			}
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
			let matches = alerts;
			const value = url.searchParams.get("value");
			if (value) {
				matches = matches.filter((a) => a.source?.ip === value || a.source?.value === value);
			}
			const since = url.searchParams.get("since");
			if (since) {
				// parse the crowdsec duration syntax: 24h, 1h, 30m, 7d...
				const match = /^([1-9][0-9]*)(s|m|h|d)$/.exec(since);
				if (!match) return send(400, { message: `bad since: ${since}` });
				const unitSeconds = { s: 1, m: 60, h: 3600, d: 86400 }[match[2]];
				const cutoff = Date.now() - Number(match[1]) * unitSeconds * 1000;
				matches = matches.filter((a) => new Date(a.started_at).getTime() >= cutoff);
			}
			return send(200, matches);
		}
		if (url.pathname === "/v1/alerts" && req.method === "POST") {
			if (req.headers.authorization !== `Bearer ${JWT}`) return send(403, { message: "no bearer" });
			const payload = JSON.parse(body);
			if (!Array.isArray(payload) || payload.length !== 1) {
				return send(400, { message: "alerts payload must be a single-element array" });
			}
			const alert = payload[0];
			const capacity = Number(alert.capacity);
			const leaks = Number(alert.leakspeed);
			if (alert.scenario !== "manual/web-ui" || !Number.isFinite(capacity) || !Number.isFinite(leaks)) {
				return send(422, { message: "bad manual alert shape" });
			}
			const decision = alert.decisions?.[0];
			if (
				!decision ||
				typeof decision.value !== "string" ||
				typeof decision.duration !== "string" ||
				typeof decision.scope !== "string" ||
				!decision.scope
			) {
				return send(422, { message: "missing decision fields" });
			}
			// simulate what cscli manual bans do: allocate an id, mark origin cscli
			const id = decisions.length + 100;
			decisions.push({
				id,
				uuid: `manual-${id}`,
				scope: decision.scope,
				value: decision.value,
				type: decision.type || "ban",
				origin: "cscli",
				scenario: "manual/web-ui",
				duration: decision.duration,
				until: new Date(Date.now() + 4 * 3600 * 1000).toISOString(),
				simulated: false,
			});
			return send(200, {
				nbAlerts: 1,
				nbDecisions: decision.type === "captcha" ? "0" : "1",
			});
		}
		send(404, { message: `unexpected ${req.method} ${url.pathname}` });
	});
});

await new Promise((resolve) => server.listen(18080, "127.0.0.1", resolve));
console.log("fake LAPI on 18080");
