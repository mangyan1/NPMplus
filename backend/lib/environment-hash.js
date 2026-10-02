import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const templateDirectory = fileURLToPath(new URL("../templates/", import.meta.url));

// Both container startup and backend persistence use this one byte format.
// Names and JSON boundaries prevent different environments sharing a digest.
const getEnvironmentHash = async () => {
	const names = new Set();
	for (const filename of await readdir(templateDirectory)) {
		const content = await readFile(`${templateDirectory}/${filename}`, "utf8");
		for (const match of content.match(/env\.[A-Z0-9_]+/g) || []) names.add(match.slice(4));
	}
	const entries = [...names].sort().map((name) => [name, process.env[name] || ""]);
	const serialized = JSON.stringify(["npmplus-env-v2", process.env.TV || "", entries]);
	return `v2:${createHash("sha512").update(serialized).digest("hex")}`;
};

if (import.meta.main) console.log(await getEnvironmentHash());

export { getEnvironmentHash };
