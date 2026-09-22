// biome-ignore-all lint/suspicious/noMisplacedAssertion: standalone API smoke assertions
// Use only a disposable, seeded local Docker instance; all users are synthetic.
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { generate } from "otplib";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const base = process.env.SMOKE_BASE_URL || "https://127.0.0.1:28181";
assert.ok(["127.0.0.1", "localhost"].includes(new URL(base).hostname));
const client = () => {
	const cookies = new Map();
	return {
		cookie: () => [...cookies.values()].join("; "),
		async request(method, path, body, override) {
			const response = await fetch(`${base}/api${path}`, {
				method,
				headers: { "content-type": "application/json", cookie: override ?? [...cookies.values()].join("; ") },
				body: body === undefined ? undefined : JSON.stringify(body),
				signal: AbortSignal.timeout(20000),
			});
			if (override === undefined) {
				for (const value of response.headers.getSetCookie())
					cookies.set(value.split("=")[0], value.split(";")[0]);
			}
			return { status: response.status, data: await response.json() };
		},
	};
};
const check = (name, actual, expected) => {
	assert.equal(actual, expected, name);
	console.log(`PASS ${name}`);
};
const admin = client();
check(
	"administrator login",
	(
		await admin.request("POST", "/tokens", {
			identity: process.env.SMOKE_ADMIN_EMAIL || "admin@example.test",
			secret: process.env.SMOKE_ADMIN_PASSWORD || "rc5-smoke-password",
		})
	).status,
	200,
);
const suffix = Date.now();
const createUser = async (label) => {
	const email = `${label}-${suffix}@example.test`;
	const result = await admin.request("POST", "/users", {
		email,
		name: label,
		roles: [],
		auth: { type: "password", secret: "Security-Smoke-Password-1" },
	});
	check(`${label} created`, result.status, 201);
	return { id: result.data.id, email };
};
const manager = await createUser("socket-manager");
check(
	"delegated permissions saved",
	(
		await admin.request("PUT", `/users/${manager.id}/permissions`, {
			visibility: "user",
			proxy_hosts: "manage",
			access_lists: "view",
			certificates: "view",
			dead_hosts: "hidden",
			redirection_hosts: "hidden",
			streams: "hidden",
		})
	).status,
	200,
);
const delegated = client();
check(
	"delegated login",
	(await delegated.request("POST", "/tokens", { identity: manager.email, secret: "Security-Smoke-Password-1" }))
		.status,
	200,
);
const host = {
	domain_names: [`audit-${suffix}.example.test`],
	forward_scheme: "http",
	forward_host: "127.0.0.1",
	forward_port: 81,
};
for (const destination of [
	"unix:/run/nginx-control.sock",
	"unix:/run/npmplus.sock",
	"unix:/tmp/app.sock",
	"cu_private",
]) {
	check(
		`delegated destination rejected: ${destination}`,
		(
			await delegated.request("POST", "/nginx/proxy-hosts", {
				...host,
				forward_host: destination,
				forward_port: null,
			})
		).status,
		403,
	);
}
const created = await delegated.request("POST", "/nginx/proxy-hosts", host);
check("normal delegated proxy created", created.status, 201);
check("real nginx accepts normal proxy", created.data.meta.nginx_online, true);
const hostUrl = `/nginx/proxy-hosts/${created.data.id}`;
check(
	"socket update rejected",
	(await delegated.request("PUT", hostUrl, { forward_host: "unix:/run/nginx-control.sock", forward_port: null }))
		.status,
	403,
);
check(
	"socket custom location rejected",
	(
		await delegated.request("PUT", hostUrl, {
			locations: [
				{
					path: "/private",
					forward_scheme: "http",
					forward_host: "unix:/run/nginx-control.sock",
					forward_port: null,
					npmplus_access_list_ids: [],
					npmplus_access_list_type: "global",
				},
			],
		})
	).status,
	403,
);
check(
	"failed update leaves destination intact",
	(await delegated.request("GET", hostUrl)).data.forward_host,
	"127.0.0.1",
);
check("normal proxy removed", (await delegated.request("DELETE", hostUrl)).status, 200);
check(
	"admin cannot publish control socket",
	(
		await admin.request("POST", "/nginx/proxy-hosts", {
			...host,
			forward_host: "unix:/run/../run/nginx-control.sock",
			forward_port: null,
		})
	).status,
	403,
);
const app = await admin.request("POST", "/nginx/proxy-hosts", {
	...host,
	forward_host: "unix:/tmp/audit-application.sock",
	forward_port: null,
});
check("admin application socket remains supported", app.status, 201);
check("nginx accepts application socket", app.data.meta.nginx_online, true);
await admin.request("DELETE", `/nginx/proxy-hosts/${app.data.id}`);
for (const username of ["bad:name", "bad\nname", "bad\rname"]) {
	check(
		"invalid htpasswd username rejected",
		(
			await admin.request("POST", "/nginx/access-lists", {
				name: "audit-invalid",
				items: [{ username, password: "fixture-password" }],
			})
		).status,
		400,
	);
}
const acl = await admin.request("POST", "/nginx/access-lists", {
	name: "audit-valid",
	items: [{ username: "valid@example.test", password: "fixture-password" }],
});
check("ordinary htpasswd username accepted", acl.status, 201);
await admin.request("DELETE", `/nginx/access-lists/${acl.data.id}`);

const account = await createUser("mfa-replay");
const mfa = client();
await mfa.request("POST", "/tokens", { identity: account.email, secret: "Security-Smoke-Password-1" });
const setup = await mfa.request("POST", `/users/${account.id}/mfa/totp`);
check("MFA enrollment starts", setup.status, 200);
const enrollmentCode = await generate({ secret: setup.data.secret });
check(
	"MFA enrollment completes",
	(await mfa.request("POST", `/users/${account.id}/mfa/totp/enable`, { code: enrollmentCode })).status,
	200,
);
const pending = client();
const challenge = await pending.request("POST", "/tokens", {
	identity: account.email,
	secret: "Security-Smoke-Password-1",
});
check("password alone produces challenge", challenge.data.requiresTotp, true);
const challengeCookie = pending.cookie();
check(
	"enrollment code cannot be reused for login",
	(await pending.request("POST", "/tokens/totp", { code: enrollmentCode })).status,
	403,
);
console.log("Waiting for the next authenticator timestep");
await delay(31000 - (Date.now() % 30000));
const code = await generate({ secret: setup.data.secret });
check("new TOTP completes login", (await pending.request("POST", "/tokens/totp", { code })).status, 200);
check(
	"completed challenge cannot be replayed",
	(await pending.request("POST", "/tokens/totp", { code }, challengeCookie)).status,
	401,
);
check("completed session is authorized", (await pending.request("GET", "/users/me")).status, 200);
const other = client();
check(
	"used TOTP rejected in combined password login",
	(await other.request("POST", "/tokens", { identity: account.email, secret: "Security-Smoke-Password-1", code }))
		.status,
	403,
);
const fullCookie = pending.cookie();
check("MFA session logout succeeds", (await pending.request("DELETE", "/tokens")).status, 200);
check(
	"logged-out MFA session cannot be replayed",
	(await pending.request("GET", "/users/me", undefined, fullCookie)).status,
	401,
);
for (const id of [manager.id, account.id])
	check("synthetic user removed", (await admin.request("DELETE", `/users/${id}`)).status, 200);
console.log("ALL LIVE SECURITY REGRESSIONS PASSED");
