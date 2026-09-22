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
							// tabler.rtl must stay out of this group: the group emits one
							// css asset, and merging the RTL sheet into it would apply
							// RTL rules to LTR pages.
							test: /node_modules[\\/](@tabler|react-bootstrap|react-select)[\\/](?!.*tabler\.rtl\.min\.css)/,
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
		alias: {
			src: "/src",
			translations: "/translations",
		},
	},
});
