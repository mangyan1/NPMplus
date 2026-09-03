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
						{
							name: "vendor",
							test: /node_modules/,
							maxSize: 450 * 1024,
							priority: 10,
						},
						{
							name: "app",
							test: /[\\/]src[\\/]/,
							maxSize: 400 * 1024,
							priority: 5,
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
