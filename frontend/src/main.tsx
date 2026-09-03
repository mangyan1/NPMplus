import React from "react";
import ReactDOM from "react-dom/client";
import App from "src/App.tsx";

import "@tabler/core/dist/css/tabler.min.css";
import "@tabler/core/dist/js/tabler.min.js";
import "./App.css";

// A tab left open during an update can still reference lazy-loaded chunks from
// the previous image. Vite reports that deployment skew through this event.
// Reload once so the browser obtains the current index and chunk manifest.
const preloadReloadKey = "npmplus-preload-reload";
window.addEventListener("vite:preloadError", (event) => {
	if (!sessionStorage.getItem(preloadReloadKey)) {
		event.preventDefault();
		sessionStorage.setItem(preloadReloadKey, Date.now().toString());
		window.location.reload();
	}
});
window.setTimeout(() => sessionStorage.removeItem(preloadReloadKey), 10_000);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
	<React.StrictMode>
		<App />
	</React.StrictMode>,
);
