import { readFile } from "node:fs/promises";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const failures = JSON.parse(process.argv[2]);
const counts = { reload: 0, listen: 0, timers: 0, telemetry: 0 };
const pending = [];
const failedAttempts = [];
const noop = () => {};
const context = createContext({
	process: { env: {}, pid: 1, on: noop, exit: noop },
	setTimeout(callback) {
		failedAttempts.push({ ...counts });
		pending.push(callback);
	},
});
const exportsByPath = {
	"./app.js": {
		default: {
			listen(_path, callback) {
				counts.listen++;
				if (counts.listen <= failures.listen) throw new Error("Socket unavailable");
				callback();
				return { close: noop };
			},
		},
	},
	"./internal/certificate.js": { default: { initTimer: () => counts.timers++ } },
	"./internal/ip_ranges.js": { default: { generateConfig: async () => {} } },
	"./internal/nginx.js": {
		default: {
			async reload() {
				counts.reload++;
				if (counts.reload <= failures.reload) throw new Error("Nginx unavailable");
			},
		},
	},
	"./internal/security-telemetry.js": { startTelemetry: () => counts.telemetry++ },
	"./logger.js": { global: { info: noop, error: noop, fatal: noop } },
	"./migrate.js": { migrateUp: async () => {} },
	"./schema/index.js": { getCompiledSchema: async () => {} },
	"./setup.js": { default: async () => {} },
};
const entry = new SourceTextModule(await readFile(new URL("../../index.js", import.meta.url), "utf8"), {
	context,
});
await entry.link((specifier) => {
	const values = exportsByPath[specifier];
	if (!values) throw new Error(`Unexpected startup dependency: ${specifier}`);
	return new SyntheticModule(
		Object.keys(values),
		function () {
			for (const [name, value] of Object.entries(values)) this.setExport(name, value);
		},
		{ context },
	);
});
await entry.evaluate();
while (pending.length > 0) {
	if (failedAttempts.length > 10) throw new Error("Startup never recovered");
	await pending.shift()();
}
console.log(JSON.stringify({ counts, failedAttempts }));
