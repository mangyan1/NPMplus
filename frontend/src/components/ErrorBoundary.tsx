import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "src/components";
import { T } from "src/locale";

interface Props {
	children: ReactNode;
}

interface State {
	error: Error | null;
}

// A failed lazy import (chunk 404 after an update, offline moment, dev server
// restart) unmounts the whole React tree without a boundary and leaves a blank
// page. Recover by reloading the SPA once: a fresh index.html points at the
// current chunk names. If the reload does not help (the error re-occurs),
// keep the boundary up so the operator can retry manually instead of staring
// at an empty dashboard.
const RELOAD_KEY = "npmplus-error-boundary-reload";
const CHUNK_FAILURE_PATTERN = /import|Failed to fetch|Loading chunk|dynamically imported module/i;

class ErrorBoundary extends Component<Props, State> {
	state: State = { error: null };

	static getDerivedStateFromError(error: Error): State {
		return { error };
	}

	componentDidCatch(error: Error, info: ErrorInfo) {
		// Import failures carry a distinct message; reload once for those (and
		// any other render error) so a stale deployment heals itself.
		const chunkFailure = CHUNK_FAILURE_PATTERN.test(`${error?.message} ${info?.componentStack ?? ""}`);
		if (chunkFailure && !sessionStorage.getItem(RELOAD_KEY)) {
			sessionStorage.setItem(RELOAD_KEY, Date.now().toString());
			window.location.reload();
		}
	}

	componentDidMount() {
		// The reload marker is only meaningful across one navigation; drop it so a
		// later failure in a healthy session can still self-heal.
		window.setTimeout(() => sessionStorage.removeItem(RELOAD_KEY), 10_000);
	}

	reload = () => {
		sessionStorage.removeItem(RELOAD_KEY);
		window.location.reload();
	};

	render() {
		if (!this.state.error) return this.props.children;
		return (
			<div className="container-tight py-4">
				<div className="empty">
					<p className="empty-title">
						<T id="error-boundary.title" />
					</p>
					<p className="empty-subtitle text-secondary">
						<T id="error-boundary.subtitle" />
					</p>
					<div className="empty-action">
						<Button type="button" size="md" onClick={this.reload}>
							<T id="error-boundary.reload" />
						</Button>
					</div>
				</div>
			</div>
		);
	}
}

export default ErrorBoundary;
