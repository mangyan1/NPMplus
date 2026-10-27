import React from "react";
import ReactDOM from "react-dom/client";
import App from "src/App.jsx";
import { Page } from "src/components";
import installDeploymentRecovery from "src/fork/deployment-recovery";

import "@tabler/core";

installDeploymentRecovery();

// document.dir is set at src/locale module init, so it is readable before
// these awaits run. The fork's vite config keeps tabler.rtl out of the
// ui-vendor group, so importing either stylesheet resolves to a distinct
// asset instead of both collapsing into the always-loaded sheet.
await (document.dir === "rtl"
	? import("@tabler/core/dist/css/tabler.rtl.min.css")
	: import("@tabler/core/dist/css/tabler.min.css"));

const root = ReactDOM.createRoot(document.querySelector("#root"), {
	onUncaughtError: (error) =>
		root.render(
			<Page className="page-center">
				<div className="container-tight py-4">
					<div className="empty">
						<div className="empty-img">
							<img src="/images/unhealthy.svg" alt="" />
						</div>
						<div className="alert alert-danger text-break text-start w-100 mb-0">{error.message}</div>
					</div>
				</div>
			</Page>,
		),
});

root.render(
	<React.StrictMode>
		<App />
	</React.StrictMode>,
);
