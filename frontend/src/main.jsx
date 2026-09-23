import React from "react";
import ReactDOM from "react-dom/client";
import App from "src/App.jsx";
import installDeploymentRecovery from "src/fork/deployment-recovery";
import { getLocale, isRTLLocale } from "src/locale";

import "@tabler/core/dist/css/tabler.min.css";
import "@tabler/core/dist/js/tabler.min.js";
import "./App.css";

installDeploymentRecovery();

const renderApp = () => {
	ReactDOM.createRoot(document.getElementById("root")).render(
		<React.StrictMode>
			<App />
		</React.StrictMode>,
	);
};

// RTL locales need tabler's flipped stylesheet layered over the LTR one. The LTR
// sheet stays a static import (before App.css) because the fork's ui-vendor
// code-splitting group would otherwise merge both tabler stylesheets into a
// single always-loaded asset, applying RTL rules to LTR pages.
if (isRTLLocale(getLocale())) {
	void import("@tabler/core/dist/css/tabler.rtl.min.css").then(renderApp);
} else {
	renderApp();
}
