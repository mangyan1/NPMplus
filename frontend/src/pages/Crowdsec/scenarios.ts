// CrowdSec scenario IDs are machine identifiers ("crowdsecurity/http-probing");
// operators think in attack types. One mapping turns every ID into a short
// human label plus a coarse category used to group the attack-mix donut.
// Unknown scenarios fall back to the unprefixed ID, never to a wrong guess.

export interface ScenarioPresentation {
	// exact identifier - still used for filtering and tooltips
	raw: string;
	// short human-readable label
	label: string;
	// one of the category keys below, for donut grouping
	category: string;
}

export const SCENARIO_CATEGORIES = [
	"brute-force",
	"probing",
	"injection",
	"waf",
	"suspicious-client",
	"flooding",
	"manual",
	"honeypot",
	"sync",
	"other",
] as const;

export type ScenarioCategory = (typeof SCENARIO_CATEGORIES)[number];

// acronyms that must not be sentence-cased by the generic humanizer
const ACRONYMS = new Set([
	"bf",
	"cve",
	"http",
	"https",
	"ip",
	"sqli",
	"ssh",
	"rce",
	"lfi",
	"xxe",
	"xss",
	"ua",
	"dns",
	"ftp",
	"smb",
	"tcp",
	"udp",
	"wp",
]);

const communityBlocklistSyncRe = /^update : \+\d+\/-\d+ IPs$/;

// strip the hub author ("crowdsecurity/", "firewallservices/", ...) from a
// scenario id; plain names and manual/sync strings pass through untouched
const stripAuthor = (id: string) => {
	const slash = id.indexOf("/");
	return slash > 0 ? id.slice(slash + 1) : id;
};

const humanizeToken = (token: string) => (ACRONYMS.has(token) ? token.toUpperCase() : token);

// generic readable form: "http-crawl-non-statics" -> "HTTP crawl non statics"
const humanize = (rest: string) =>
	rest
		.split(/[-_]+/)
		.filter(Boolean)
		.map(humanizeToken)
		.join(" ")
		.replace(/^./, (char) => char.toUpperCase());

const present = (raw: string, label: string, category: ScenarioCategory): ScenarioPresentation => ({
	raw,
	label,
	category,
});

const presentScenario = (raw: string): ScenarioPresentation => {
	// blocklist sync bookkeeping keeps its own bucket everywhere
	if (communityBlocklistSyncRe.test(raw)) return present(raw, "Community blocklist sync", "sync");

	if (raw.startsWith("manual/")) return present(raw, "Manual ban", "manual");

	const rest = stripAuthor(raw);

	// the anubis bridge's trap catches get their own bucket, matching the
	// dashboard's dedicated honeypot card
	if (rest === "anubis-honeypot") return present(raw, "Anubis honeypot", "honeypot");

	// vpatch-cve-2024-1234 -> "vPatch CVE-2024-1234"
	if (/^vpatch-/i.test(rest)) return present(raw, `vPatch ${humanize(rest.slice(7))}`, "waf");
	// appsec rules and engine blocks
	if (/^appsec/i.test(rest))
		return present(raw, `WAF rule ${humanize(rest.replace(/^appsec-?/i, ""))}`.trim(), "waf");
	// exploit probe scenarios name their CVE
	const cve = /^http-cve-(\d{4}-\d+)$/i.exec(rest);
	if (cve) return present(raw, `Exploit probe CVE-${cve[1]}`, "injection");
	// <service>-bf is the hub's brute force naming convention
	const bf = /^(.*)-bf$/i.exec(rest);
	if (bf) return present(raw, `${humanize(bf[1])} brute force`, "brute-force");

	const label = humanize(rest);
	if (/(^|\s)(bf|brute\s?force)(\s|$)/i.test(rest)) return present(raw, label, "brute-force");
	// injection patterns win over probing: "http-sqli-probing" is an injection
	if (/sqli|sql|xss|traversal|rce|lfi|xxe|xpath|inject/i.test(rest)) return present(raw, label, "injection");
	if (/probing|crawl|scan|enum|fpath|glob/i.test(rest)) return present(raw, label, "probing");
	if (/bad-user-agent|http-ua|user-agent/i.test(rest)) return present(raw, label, "suspicious-client");
	if (/flood|dos\b/i.test(rest)) return present(raw, label, "flooding");
	return present(raw, label, "other");
};

const cache = new Map<string, ScenarioPresentation>();

export const presentScenarioId = (id: string): ScenarioPresentation => {
	const existing = cache.get(id);
	if (existing) return existing;
	const next = presentScenario(id);
	cache.set(id, next);
	return next;
};

export const scenarioLabel = (id: string) => presentScenarioId(id).label;

export const scenarioCategory = (id: string) => presentScenarioId(id).category;

// keep both ends visible when a name must fit a narrow column:
// "crowdsecurity/http-crawl-non-statics" -> "crowdsecuri…non-statics"
export const midTruncate = (value: string, max = 24) => {
	if (value.length <= max) return value;
	const tail = Math.floor((max - 1) / 2);
	const head = max - 1 - tail;
	return `${value.slice(0, head)}…${value.slice(-tail)}`;
};
