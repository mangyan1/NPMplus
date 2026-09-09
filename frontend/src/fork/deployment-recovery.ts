// A tab left open during an update can still reference lazy-loaded chunks from
// the previous image. Keep this fork behavior outside the shared entry point.
const installDeploymentRecovery = () => {
	const preloadReloadKey = "npmplus-preload-reload";
	window.addEventListener("vite:preloadError", (event) => {
		if (!sessionStorage.getItem(preloadReloadKey)) {
			event.preventDefault();
			sessionStorage.setItem(preloadReloadKey, Date.now().toString());
			window.location.reload();
		}
	});
	window.setTimeout(() => sessionStorage.removeItem(preloadReloadKey), 10_000);
};

export default installDeploymentRecovery;
