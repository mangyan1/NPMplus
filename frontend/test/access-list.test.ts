// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import assert from "node:assert/strict";
// biome-ignore lint/correctness/noNodejsModules: this file is executed by Node's test runner.
import it from "node:test";
import { hasMissingAccessPassword } from "../src/modules/AccessListValidation.ts";

it("masked access passwords only preserve a matching saved username", () => {
	const existing = [{ username: "original", password: "" }];
	assert.equal(hasMissingAccessPassword([{ username: "original", password: "" }], existing), false);
	assert.equal(hasMissingAccessPassword([{ username: "renamed", password: "" }], existing), true);
	assert.equal(hasMissingAccessPassword([{ username: "renamed", password: "new-password" }], existing), false);
	assert.equal(hasMissingAccessPassword([{ username: "new", password: "" }]), true);
});
