import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router";
import {
	ErrorBoundary,
	ErrorNotFound,
	LoadingPage,
	Page,
	SiteContainer,
	SiteFooter,
	SiteHeader,
	SiteMenu,
	Unhealthy,
} from "src/components";
import { useAuthState } from "src/context";
import { useHealth } from "src/hooks";

const Setup = lazy(() => import("src/pages/Setup"));
const Login = lazy(() => import("src/pages/Login"));
const Dashboard = lazy(() => import("src/pages/Dashboard"));
const Settings = lazy(() => import("src/pages/Settings"));
const Certificates = lazy(() => import("src/pages/Certificates"));
const Access = lazy(() => import("src/pages/Access"));
const AuditLog = lazy(() => import("src/pages/AuditLog"));
const Crowdsec = lazy(() => import("src/pages/Crowdsec"));
const Users = lazy(() => import("src/pages/Users"));
const ProxyHosts = lazy(() => import("src/pages/Nginx/ProxyHosts"));
const RedirectionHosts = lazy(() => import("src/pages/Nginx/RedirectionHosts"));
const DeadHosts = lazy(() => import("src/pages/Nginx/DeadHosts"));
const Streams = lazy(() => import("src/pages/Nginx/Streams"));

function Router() {
	const health = useHealth();
	const { authenticated } = useAuthState();

	if (health.isLoading) {
		return <LoadingPage />;
	}

	if (health.isError || health.data?.status !== "OK") {
		return <Unhealthy />;
	}

	if (!health.data?.setup) {
		return (
			<ErrorBoundary>
				<Setup />
			</ErrorBoundary>
		);
	}

	if (!authenticated) {
		return (
			<ErrorBoundary>
				<Suspense fallback={<LoadingPage />}>
					<Login />
				</Suspense>
			</ErrorBoundary>
		);
	}

	return (
		<BrowserRouter>
			<Page>
				<div>
					<SiteHeader />
					<SiteMenu />
				</div>
				<SiteContainer>
					<ErrorBoundary>
						<Suspense fallback={<LoadingPage noLogo />}>
							<Routes>
								<Route path="*" element={<ErrorNotFound />} />
								<Route path="/certificates" element={<Certificates />} />
								<Route path="/access" element={<Access />} />
								<Route path="/audit-log" element={<AuditLog />} />
								<Route path="/crowdsec" element={<Crowdsec />} />
								<Route path="/settings" element={<Settings />} />
								<Route path="/users" element={<Users />} />
								<Route path="/nginx/proxy" element={<ProxyHosts />} />
								<Route path="/nginx/redirection" element={<RedirectionHosts />} />
								<Route path="/nginx/404" element={<DeadHosts />} />
								<Route path="/nginx/stream" element={<Streams />} />
								<Route path="/" element={<Dashboard />} />
							</Routes>
						</Suspense>
					</ErrorBoundary>
				</SiteContainer>
				<SiteFooter />
			</Page>
		</BrowserRouter>
	);
}

export default Router;
