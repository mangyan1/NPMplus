import type { JSX as ReactJSX } from "react";

// NiceModal 1.2.13 still references the pre-React-19 JSX namespace. Map that
// single legacy name to React's actual elements while checking library types.
declare global {
	// biome-ignore lint/style/noNamespace: NiceModal requires this ambient legacy JSX name.
	namespace JSX {
		type IntrinsicElements = ReactJSX.IntrinsicElements;
	}
}
