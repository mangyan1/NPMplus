// Classifications describe the detector's claim, never a successful compromise.
const ATTACK_TYPES: [RegExp, string][] = [
	[/honeypot/, "honeypot"],
	[/^manual\//, "manual"],
	[/sql[-_ ]?injection|sqli/, "sql"],
	[/xss|cross[-_ ]site[-_ ]scripting/, "xss"],
	[/traversal|\blfi\b|\brfi\b/, "file"],
	[/\brce\b|remote[-_ ]code|command[-_ ]injection/, "execution"],
	[/cve-\d{4}-\d+/, "cve"],
	[/env-access|git-config|sensitive[-_ ]file/, "exposure"],
	[/brute|[-_/]bf(?:$|-)/, "brute"],
	[/probing|scan|crawl|enum/, "probing"],
	[/flood|(?:^|[-_/])(?:d?dos)(?:$|-)/, "flood"],
];
export const attackType = (name: string): string =>
	ATTACK_TYPES.find(([pattern]) => pattern.test(name.toLowerCase()))?.[1] ?? "unknown";

// Only explicit client claims qualify. A path, IP, or scenario cannot identify a tool.
const CLIENT_HINTS: [RegExp, string][] = [
	[/\bsqlmap(?:\/|\b)/i, "sqlmap"],
	[/\bnikto(?:\/|\b)/i, "Nikto"],
	[/\bnuclei(?:\/|\b)/i, "Nuclei"],
	[/\bnmap(?:\/|\b)/i, "Nmap"],
	[/\bgobuster(?:\/|\b)/i, "Gobuster"],
	[/\bffuf(?:\/|\b)/i, "ffuf"],
	[/\bcurl\//i, "curl"],
	[/\bpython-requests\//i, "Python Requests"],
	[/\bwget\//i, "Wget"],
];

export const toolHints = (userAgent: string): string[] =>
	CLIENT_HINTS.filter(([pattern]) => pattern.test(userAgent.slice(0, 512))).map(([, name]) => name);
