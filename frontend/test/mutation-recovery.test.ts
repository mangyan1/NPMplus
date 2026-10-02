// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import assert from "node:assert/strict";
// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import { readFile } from "node:fs/promises";
// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import test from "node:test";
import { type MutationOptions, QueryClient } from "@tanstack/react-query";

for (const resource of ["User", "AccessList", "ProxyHost", "RedirectionHost", "DeadHost", "Stream"]) {
	test(`${resource} create and update failures preserve the API error and settle safely`, async () => {
		const source = await readFile(new URL(`../src/hooks/use${resource}.js`, import.meta.url), "utf8");
		const hook = `useSet${resource}`;
		const hookSource = source.slice(source.indexOf(`const ${hook} =`), source.indexOf("\nexport "));
		assert.ok(hookSource.startsWith(`const ${hook} =`));
		const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
		const failure = new Error("API rejected the fixture request");
		const fail = () => Promise.reject(failure);
		// Capture the repository hook's exact options without mounting React, then
		// execute them through the installed TanStack mutation implementation.
		const capture = new Function(
			"useMutation",
			"useQueryClient",
			`create${resource}`,
			`update${resource}`,
			`${hookSource}; return ${hook}();`,
		);
		const options = capture(
			(value: unknown) => value,
			() => client,
			fail,
			fail,
		) as MutationOptions<unknown, Error, { id?: number; name: string }, (() => void) | undefined>;
		for (const values of [{ name: "Create fixture" }, { id: 42, name: "Update fixture" }]) {
			const key = [
				resource === "AccessList" ? "access-list" : resource.replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase(),
				42,
			];
			const original = { id: 42, name: "Previous value" };
			client.setQueryData(key, original);
			let settled = false;
			const mutation = client.getMutationCache().build(client, {
				...options,
				onSettled: () => {
					settled = true;
				},
			});
			// biome-ignore lint/performance/noAwaitInLoops: update follows create against the same isolated query cache.
			await assert.rejects(mutation.execute(values), (error) => error === failure);
			await new Promise<void>((resolve) => setTimeout(resolve, 0));
			assert.equal(settled, true);
			assert.deepEqual(client.getQueryData(key), original);
		}
		client.clear();
	});
}
