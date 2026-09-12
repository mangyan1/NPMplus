import { type ReactNode, useState } from "react";
import type { ApiError } from "src/api/backend/base";
import { LoadingPage } from "src/components/LoadingPage";
import { useAuthState } from "src/context";
import { useUser } from "src/hooks";
import { T } from "src/locale";

// A failed profile fetch is not evidence that the account lacks permissions.
export function AccountGate({ children }: { children: ReactNode }) {
	const { data, error, isLoading, isFetching, refetch } = useUser("me");
	const { logout } = useAuthState();
	const [logoutFailed, setLogoutFailed] = useState(false);
	const [loggingOut, setLoggingOut] = useState(false);
	if (isLoading) return <LoadingPage />;
	if (error || !data) {
		const status = (error as ApiError | null)?.status;
		return (
			<main className="container-tight px-3 py-5">
				<section className="card border-danger" role="alert">
					<div className="card-body">
						<h1 className="h3">
							<T id="account.load-failed" />
						</h1>
						<p>
							<T id="account.load-failed.description" />
						</p>
						{status && <p>HTTP {status}</p>}
						{logoutFailed && (
							<p>
								<T id="account.logout-failed" />
							</p>
						)}
						<div className="d-flex flex-wrap gap-2">
							<button
								type="button"
								className="btn btn-primary"
								disabled={isFetching}
								onClick={() => void refetch()}
							>
								<T id="account.retry" />
							</button>
							<button
								type="button"
								className="btn btn-outline-secondary"
								disabled={loggingOut}
								onClick={async () => {
									setLoggingOut(true);
									setLogoutFailed(false);
									try {
										await logout();
									} catch {
										setLogoutFailed(true);
									} finally {
										setLoggingOut(false);
									}
								}}
							>
								<T id="user.logout" />
							</button>
						</div>
					</div>
				</section>
			</main>
		);
	}
	return <>{children}</>;
}
