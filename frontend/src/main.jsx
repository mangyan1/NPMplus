import React from "react";
import ReactDOM from "react-dom/client";
import App from "src/App.jsx";
import installDeploymentRecovery from "src/fork/deployment-recovery";

import "@tabler/core/dist/css/tabler.min.css";
import "@tabler/core/dist/js/tabler.min.js";
import "./App.css";

installDeploymentRecovery();

ReactDOM.createRoot(document.getElementById("root")).render(
	<React.StrictMode>
		<App />
	</React.StrictMode>,
);
