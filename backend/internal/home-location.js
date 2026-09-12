import process from "node:process";
import { fetchWithTimeout, readBoundedJson } from "../lib/bounded-fetch.js";
import { debug, global as logger } from "../logger.js";
import pjson from "../package.json" with { type: "json" };

// Where the attack map's meteors land: the instance's own location. An explicit
// HOME_LATITUDE/HOME_LONGITUDE env pair wins. Otherwise the instance's public
// IP is geolocated through ipwho.is, which receives the public source address
// and NPMplus User-Agent. HOME_GEOLOCATION=false disables this external lookup.
// The result is cached for a day
// and failures back off for an hour, so dashboard polling never hammers the
// service; any failure just leaves the map without a destination.

const HOME_CACHE_MS = 24 * 60 * 60 * 1000;
const HOME_FAILURE_MS = 60 * 60 * 1000;

let cached = null;
let cachedAt = 0;
let failedAt = 0;
let pending = null;

const coordinate = (value, min, max) => {
	if (value === null || value === undefined || String(value).trim() === "") return null;
	const number = Number(value);
	return Number.isFinite(number) && number >= min && number <= max ? number : null;
};

const lookupHomeLocation = async () => {
	const response = await fetchWithTimeout(
		"https://ipwho.is/",
		{ headers: { "User-Agent": `NPMplus/${pjson.version}` } },
		5_000,
	);
	if (!response.ok) throw new Error(`Status code: ${response.status}`);
	const data = await readBoundedJson(response, 16 * 1024);
	if (data.success === false) throw new Error(data.message || "geolocation refused");
	const latitude = coordinate(data.latitude, -90, 90);
	const longitude = coordinate(data.longitude, -180, 180);
	if (latitude === null || longitude === null) throw new Error("unusable coordinates");
	return { latitude, longitude };
};

const getHomeLocation = async () => {
	const envLatitude = coordinate(process.env.HOME_LATITUDE, -90, 90);
	const envLongitude = coordinate(process.env.HOME_LONGITUDE, -180, 180);
	if (envLatitude !== null && envLongitude !== null) {
		return { latitude: envLatitude, longitude: envLongitude };
	}
	if (process.env.HOME_GEOLOCATION === "false") return null;

	const now = Date.now();
	if (cached && now - cachedAt < HOME_CACHE_MS) return cached;
	if (now - failedAt < HOME_FAILURE_MS) return null;

	// Polling tabs share one cold lookup and one bounded response allocation.
	pending ??= lookupHomeLocation()
		.then((location) => {
			cached = location;
			cachedAt = Date.now();
			return cached;
		})
		.catch((err) => {
			failedAt = Date.now();
			debug(logger, `Could not geolocate the instance location: ${err.message}`);
			return null;
		})
		.finally(() => {
			pending = null;
		});
	return await pending;
};

export { getHomeLocation };
