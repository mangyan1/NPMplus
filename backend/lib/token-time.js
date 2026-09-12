import { setTimeout } from "node:timers/promises";

// Timers may wake before the wall clock reaches the revocation boundary.
// Recheck after each wake; never return a future-dated issuance timestamp.
export const issuedAfter = async (cutoff) => {
	const boundary = (Number(cutoff || 0) + 1) * 1000;
	let now = Date.now();
	while (now < boundary) {
		await setTimeout(boundary - now);
		now = Date.now();
	}
	return Math.floor(now / 1000);
};
