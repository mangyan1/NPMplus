// Fail-closed shape tests for the merged permission model. can()/canUser()
// are synchronous and need no token or database row, so the module can be
// exercised directly: `new Access(null)` is the anonymous shape (no
// permissions, not admin) and load(true) is the synthetic-admin path the
// setup route uses.
import assert from "node:assert/strict";
import test from "node:test";
import Access from "../lib/access.js";

test("can() fails closed on a permission string without a type:level shape", () => {
	const access = new Access(null);
	assert.throws(
		() => access.can("proxy_hosts"),
		(error) => error.status === 403,
	);

	// even a synthetic admin must not grant a malformed permission string
	const admin = new Access(null);
	admin.load(true);
	assert.throws(
		() => admin.can("proxy_hosts"),
		(error) => error.status === 403,
	);
	assert.equal(admin.can("proxy_hosts:manage"), true);
});

test("canUser() rejects the anonymous-session sentinel and non-ids", () => {
	const access = new Access(null);
	// 0 is the anonymous sentinel (Token.getUserId(0)), not a real user id
	assert.throws(
		() => access.canUser(0),
		(error) => error.status === 403,
	);
	assert.throws(
		() => access.canUser("0"),
		(error) => error.status === 403,
	);
	assert.throws(
		() => access.canUser("abc"),
		(error) => error.status === 403,
	);
	assert.throws(
		() => access.canUser(-1),
		(error) => error.status === 403,
	);
	assert.throws(
		() => access.canUser(2.5),
		(error) => error.status === 403,
	);

	// a synthetic admin still passes the well-formed checks
	const admin = new Access(null);
	admin.load(true);
	assert.equal(admin.canUser(1), true);
});
