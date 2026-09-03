import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [react()],
	build: {
		rolldownOptions: {
			output: {
				codeSplitting: {
					groups: [
						{
							name: "react-vendor",
							test: /node_modules[\\/](react|react-dom|react-router|@tanstack)[\\/]/,
							priority: 30,
						},
						{
							name: "ui-vendor",
							test: /node_modules[\\/](@tabler|react-bootstrap|react-select)[\\/]/,
							priority: 20,
						},
					],
				},
			},
		},
	},
	define: {
		global: "globalThis",
	},
	resolve: {
		tsconfigPaths: true,
	},
});
