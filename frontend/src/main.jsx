import React from "react";
import ReactDOM from "react-dom/client";
import App from "src/App.jsx";
import installDeploymentRecovery from "src/fork/deployment-recovery";

import "@tabler/core/dist/js/tabler.min.js";

installDeploymentRecovery();

// document.dir is set at src/locale module init, so it is readable before
// these awaits run. The fork's vite config keeps tabler.rtl out of the
// ui-vendor group, so importing either stylesheet resolves to a distinct
// asset instead of both collapsing into the always-loaded sheet.
await (document.dir === "rtl"
	? import("@tabler/core/dist/css/tabler.rtl.min.css")
	: import("@tabler/core/dist/css/tabler.min.css"));
await import("./App.css");

ReactDOM.createRoot(document.getElementById("root")).render(
	<React.StrictMode>
		<App />
	</React.StrictMode>,
);
