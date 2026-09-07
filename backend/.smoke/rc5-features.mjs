// rc.5 install simulation, API layer: runs against a real NPMplus container
// (built from this tree) rather than the in-process harness. Point BASE_URL at
// the container's admin port; the container must have been started with a
// known INITIAL_ADMIN_EMAIL / INITIAL_ADMIN_PASSWORD pair.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // the admin listener ships a self-signed cert
const BASE_URL = process.env.SMOKE_BASE_URL || "https://127.0.0.1:8181";
const EMAIL = process.env.SMOKE_ADMIN_EMAIL || "admin@example.test";
const PASSWORD = process.env.SMOKE_ADMIN_PASSWORD || "rc5-smoke-password";

let failures = 0;
const check = (name, ok, detail = "") => {
	if (!ok) failures++;
	console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` -> ${detail}`}`);
};

let cookie = "";
const request = async (method, path, body) => {
	const response = await fetch(`${BASE_URL}${path}`, {
		method,
		headers: {
			...(body ? { "content-type": "application/json" } : {}),
			...(cookie ? { cookie } : {}),
		},
		body: body ? JSON.stringify(body) : undefined,
	});
	const setCookie = response.headers.get("set-cookie");
	if (setCookie) cookie = setCookie.split(";")[0];
	let json = null;
	try {
		json = await response.json();
	} catch {
		/* non-json body */
	}
	return { status: response.status, json };
};

// 1. stack is up and the seed admin completed setup
const root = await request("GET", "/api");
check(
	"api reports healthy with setup complete",
	root.status === 200 && root.json?.status === "OK" && root.json?.setup === true,
	JSON.stringify(root),
);

// 2. unauthenticated reads are rejected
const anon = await request("GET", "/api/nginx/proxy-hosts");
check("unauthenticated proxy-host read is rejected", anon.status === 401 || anon.status === 403, `got ${anon.status}`);

// 3. seeded admin can log in
const login = await request("POST", "/api/tokens", { identity: EMAIL, secret: PASSWORD });
check(
	"seeded admin login succeeds and sets the auth cookie",
	login.status === 200 && login.json?.expires && cookie.includes("__Host-Http-token="),
	JSON.stringify(login),
);

// 4. own user profile
const me = await request("GET", "/api/users/me");
check(
	"users/me returns the seeded admin",
	me.status === 200 && me.json?.email === EMAIL && me.json?.roles?.includes("admin"),
	JSON.stringify(me.json),
);

// 5. empty inventory reads
for (const [name, path] of [
	["proxy hosts", "/api/nginx/proxy-hosts"],
	["redirection hosts", "/api/nginx/redirection-hosts"],
	["dead hosts", "/api/nginx/dead-hosts"],
	["streams", "/api/nginx/streams"],
	["certificates", "/api/nginx/certificates"],
	["access lists", "/api/nginx/access-lists"],
]) {
	const list = await request("GET", path);
	check(`empty ${name} list reads clean`, list.status === 200 && Array.isArray(list.json), `got ${list.status}`);
}

// 6. proxy-host lifecycle: create, list, update, delete
const createBody = {
	domain_names: ["rc5-sim.example.test"],
	forward_scheme: "http",
	forward_host: "127.0.0.1",
	forward_port: 9999,
	certificate_id: 0,
	block_exploits: true,
};
const created = await request("POST", "/api/nginx/proxy-hosts", createBody);
check("proxy host is created", created.status === 200 || created.status === 201, JSON.stringify(created));
const hostId = created.json?.id;
const listAfterCreate = await request("GET", "/api/nginx/proxy-hosts");
const createdMeta = listAfterCreate.json?.find((item) => item.id === hostId)?.meta;
check(
	"created host appears in the list with online meta and a reachability probe",
	listAfterCreate.json?.some((item) => item.id === hostId && item.meta) &&
		createdMeta?.nginx_online === true &&
		createdMeta?.reach_ok === false,
	JSON.stringify(createdMeta),
);

const updated = await request("PUT", `/api/nginx/proxy-hosts/${hostId}`, {
	...createBody,
	forward_port: 9998,
});
check(
	"proxy host updates its forward port",
	updated.status === 200 && updated.json?.forward_port === 9998,
	JSON.stringify(updated),
);

const deleted = await request("DELETE", `/api/nginx/proxy-hosts/${hostId}`);
check("proxy host is deleted", deleted.status === 200, JSON.stringify(deleted));
const listAfterDelete = await request("GET", "/api/nginx/proxy-hosts");
check(
	"deleted host is gone and nginx stays healthy",
	listAfterDelete.json?.length === 0 && (await request("GET", "/api")).json?.status === "OK",
	JSON.stringify(listAfterDelete.json),
);

// 7. crowdsec routes degrade honestly without a wired LAPI
const decisions = await request("GET", "/api/crowdsec/decisions");
check(
	"crowdsec decisions report not-wired without a LAPI",
	decisions.status === 503 && decisions.json?.error?.message === "crowdsec.not-wired",
	JSON.stringify(decisions),
);
const anubis = await request("GET", "/api/crowdsec/anubis");
check(
	"anubis health stays visible without an upstream",
	anubis.status === 200 && anubis.json?.configured === false,
	JSON.stringify(anubis),
);
const metrics = await request("GET", "/api/crowdsec/metrics");
check(
	"crowdsec metrics report the unconfigured state",
	metrics.status === 200 && metrics.json?.available === false,
	JSON.stringify(metrics),
);
const adminCookie = cookie;
cookie = "";
const anonBan = await request("POST", "/api/crowdsec/decisions", { value: "192.0.2.50", duration: "4h", type: "ban" });
cookie = adminCookie;
check(
	"crowdsec manual ban is rejected without a session",
	anonBan.status === 401 || anonBan.status === 403,
	`got ${anonBan.status}`,
);

// 8. audit trail recorded the proxy-host lifecycle
const audit = await request("GET", "/api/audit-log?sort=object_type");
check(
	"audit log records created and deleted proxy hosts",
	audit.status === 200 &&
		(audit.json ?? []).some((row) => row.action === "created" && row.object_type === "proxy-host") &&
		(audit.json ?? []).some((row) => row.action === "deleted" && row.object_type === "proxy-host"),
	JSON.stringify(audit.json?.slice(0, 3)),
);

// 9. default public site: an unmatched request reaches the default server,
//    which closes the connection (444) instead of serving content
const publicSite = await fetch("http://127.0.0.1:8080", { redirect: "manual" }).catch((err) => {
	const cause = err?.cause?.code ?? err?.code ?? String(err);
	return { refused: cause === "ECONNREFUSED", cause };
});
check(
	"public http listener answers unmatched requests with the hardened default",
	publicSite && !publicSite.refused,
	`got ${publicSite?.cause ?? publicSite?.status}`,
);

console.log(failures === 0 ? "ALL RC5 API FEATURE CHECKS PASSED" : `${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
