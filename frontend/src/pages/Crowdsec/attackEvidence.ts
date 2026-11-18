// Classifications describe the detector's claim, never a successful compromise.
const ATTACK_TYPES: [RegExp, string][] = [
	[/honeypot/u, "honeypot"],
	[/^manual\//u, "manual"],
	[/sql[-_ ]?injection|sqli/u, "sql"],
	[/xss|cross[-_ ]site[-_ ]scripting/u, "xss"],
	[/traversal|\blfi\b|\brfi\b/u, "file"],
	[/\brce\b|remote[-_ ]code|command[-_ ]injection/u, "execution"],
	[/cve-\d{4}-\d+/u, "cve"],
	[/env-access|git-config|sensitive[-_ ]file/u, "exposure"],
	[/brute|[-_/]bf(?:$|-)/u, "brute"],
	[/probing|scan|crawl|enum/u, "probing"],
	[/flood|(?:^|[-_/])(?:d?dos)(?:$|-)/u, "flood"],
];
export const attackType = (name: string): string =>
	ATTACK_TYPES.find(([pattern]) => pattern.test(name.toLowerCase()))?.[1] ?? "unknown";

// Only explicit client claims qualify. A path, IP, or scenario cannot identify a tool.
const CLIENT_HINTS: [RegExp, string][] = [
	[/\bsqlmap(?:\/|\b)/iu, "sqlmap"],
	[/\bnikto(?:\/|\b)/iu, "Nikto"],
	[/\bnuclei(?:\/|\b)/iu, "Nuclei"],
	[/\bnmap(?:\/|\b)/iu, "Nmap"],
	[/\bgobuster(?:\/|\b)/iu, "Gobuster"],
	[/\bffuf(?:\/|\b)/iu, "ffuf"],
	[/\bcurl\//iu, "curl"],
	[/\bpython-requests\//iu, "Python Requests"],
	[/\bwget\//iu, "Wget"],
];

export const toolHints = (userAgent: string): string[] =>
	CLIENT_HINTS.filter(([pattern]) => pattern.test(userAgent.slice(0, 512))).map(([, name]) => name);
