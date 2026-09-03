import { remoteVersion as logger } from "../logger.js";
import pjson from "../package.json" with { type: "json" };

const COMMIT_PATTERN = /^[0-9a-f]{7,40}$/i;
const isCommitUpdateAvailable = (currentVersion, latestVersion) =>
	COMMIT_PATTERN.test(currentVersion) &&
	COMMIT_PATTERN.test(latestVersion) &&
	!currentVersion.startsWith(latestVersion);

const internalRemoteVersion = {
	cache_timeout: 1000 * 60 * 60, // 1 hour
	last_result: null,
	last_fetch_time: null,

	/**
	 * Fetch the latest version info, using a cached result if within the cache timeout period.
	 * @return {Promise<{current: string, latest: string, update_available: boolean}>} Version info
	 */
	get: async () => {
		try {
			if (
				!internalRemoteVersion.last_result ||
				!internalRemoteVersion.last_fetch_time ||
				Date.now() - internalRemoteVersion.last_fetch_time > internalRemoteVersion.cache_timeout
			) {
				const repository = process.env.NPMPLUS_GITHUB_REPOSITORY || "mangyan1/NPMplus";
				const branch = process.env.NPMPLUS_GITHUB_BRANCH || "develop";
				const response = await fetch(`https://api.github.com/repos/${repository}/commits/${branch}`, {
					headers: {
						"User-Agent": `NPMplus/${pjson.version}`,
					},
					signal: AbortSignal.timeout(10_000),
				});

				if (!response.ok) {
					throw new Error(`Status code: ${response.status}`);
				}

				const data = await response.json();

				internalRemoteVersion.last_result = data;
				internalRemoteVersion.last_fetch_time = Date.now();
			}
		} catch (error) {
			logger.error("Failed to fetch remote version:", error.message);
			if (!internalRemoteVersion.last_result) {
				return {
					current: pjson.version,
					latest: "unknown",
					update_available: false,
				};
			}
		}

		const latestVersion = internalRemoteVersion.last_result?.sha?.slice(0, 7) || "unknown";
		const currentVersion = pjson.version;
		return {
			current: currentVersion,
			latest: latestVersion,
			update_available: isCommitUpdateAvailable(currentVersion, latestVersion),
		};
	},
};

export { isCommitUpdateAvailable };
export default internalRemoteVersion;
