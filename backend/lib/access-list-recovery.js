import { readdir, readFile, rm, stat, writeFile } from "node:fs/promises";

// Different lists can share a proxy host's merged password file.
let pendingUpdate = Promise.resolve();
export const serializeAccessListUpdate = (operation) => {
	const result = pendingUpdate.then(operation);
	pendingUpdate = result.catch(() => {});
	return result;
};

export const snapshotAccessListFiles = async (list, hosts) => {
	const prefixes = hosts.map((host) => `host-${host.id}`);
	const hostFiles = async () =>
		(await readdir("/data/access"))
			.filter((name) => prefixes.some((prefix) => name === prefix || name.startsWith(`${prefix}-`)))
			.map((name) => `/data/access/${name}`);
	const filenames = new Set([
		`/data/access/${list.id}`,
		...(await hostFiles()),
		...hosts.flatMap((host) => [
			`/data/nginx/proxy_host/${host.id}.conf`,
			`/data/nginx/proxy_host/${host.id}.conf.err`,
		]),
	]);
	const snapshots = new Map();
	for (const filename of filenames) {
		try {
			snapshots.set(filename, { content: await readFile(filename), mode: (await stat(filename)).mode });
		} catch (error) {
			if (error.code !== "ENOENT") throw error;
			snapshots.set(filename, null);
		}
	}
	return async () => {
		for (const filename of new Set([...snapshots.keys(), ...(await hostFiles())])) {
			const previous = snapshots.get(filename);
			await rm(filename, { force: true });
			if (previous) await writeFile(filename, previous.content, { mode: previous.mode });
		}
	};
};
