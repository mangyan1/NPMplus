import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import localeList from "./translations/lang-list.json" with { type: "json" };

export default defineConfig({
	plugins: [react()],
	build: {
		assetsInlineLimit: 0,
		rolldownOptions: {
			output: {
				codeSplitting: {
					groups: [
						{
							name: "react-vendor",
							test: /node_modules[\\/](react|react-dom|react-router|@tanstack)[\\/]/u,
							priority: 30,
						},
						{
							name: "ui-vendor",
							// tabler.rtl must stay out of this group: the group emits one
							// css asset, and merging the RTL sheet into it would apply
							// RTL rules to LTR pages.
							test: /node_modules[\\/](@tabler|react-bootstrap|react-select)[\\/](?!.*tabler\.rtl\.min\.css)/u,
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
	css: {
		postcss: {
			plugins: [
				{
					postcssPlugin: "used-flags-only",
					Rule: (rule) => {
						const flag = rule.selector.split(".flag-country-")[1];
						if (flag && !Object.values(localeList).some((locale) => locale.flag === flag)) rule.remove();
					},
				},
			],
		},
	},
});
