import { IconBell, IconBellOff, IconChevronLeft, IconChevronRight, IconRefresh, IconSearch } from "@tabler/icons-react";
import { Fragment, type ReactNode, useDeferredValue, useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import type {
	AnubisStatus,
	CrowdsecAlert,
	CrowdsecInsights,
	CrowdsecInsightsItem,
	CrowdsecMetrics,
} from "src/api/backend";
import { Button } from "src/components";
import { useLocaleState } from "src/context";
import { useAnubisStatus, useCrowdsecAlertHistory, useCrowdsecInsights, useCrowdsecMetrics } from "src/hooks";
import { formatDateTime, intl, T } from "src/locale";
import { showManualBanModal } from "src/modals";
import ActiveBans from "./ActiveBans";
import AnimatedLogo from "./AnimatedLogo";

const NOTIFICATIONS_KEY = "npmplus.crowdsec.browser-notifications";
const LAST_SIGNAL_KEY = "npmplus.crowdsec.last-signal";
type DashboardTab = "overview" | "activity" | "bans" | "system";
type KpiKind = "attacks" | "local" | "community" | "anubis";

const alertTarget = (alert: CrowdsecAlert) => {
	for (const event of alert.events)
		for (const item of event.meta)
			if (["target_host", "target_fqdn", "target_uri"].includes(item.key)) return item.value;
	return "";
};
const alertSource = (alert: CrowdsecAlert) => alert.source.ip || alert.source.value || alert.source.rdns || "—";

const ActivityChart = ({ items }: { items: { start: string; count: number }[] }) => {
	const width = 720;
	const height = 160;
	const max = Math.max(1, ...items.map((item) => item.count));
	const barWidth = Math.max(1, width / Math.max(1, items.length) - 2);
	return (
		<svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={intl.formatMessage({ id: "crowdsec.activity" })}>
			<title>{intl.formatMessage({ id: "crowdsec.activity" })}</title>
			<line x1="0" y1={height - 1} x2={width} y2={height - 1} stroke="currentColor" opacity="0.2" />
			{items.map((item, index) => {
				const barHeight = (item.count / max) * (height - 18);
				return (
					<rect
						key={item.start}
						x={index * (width / items.length)}
						y={height - barHeight - 1}
						width={barWidth}
						height={barHeight}
						rx="2"
						fill="var(--tblr-azure)"
					>
						<title>{`${formatDateTime(item.start)}: ${item.count}`}</title>
					</rect>
				);
			})}
		</svg>
	);
};

const AttackMap = ({ items }: { items: { latitude: number; longitude: number; country: string; count: number }[] }) => (
	<svg viewBox="0 0 720 320" role="img" aria-label={intl.formatMessage({ id: "crowdsec.attack-map" })}>
		<title>{intl.formatMessage({ id: "crowdsec.attack-map" })}</title>
		<rect width="720" height="320" rx="8" className="fill-secondary-lt" opacity="0.35" />
		{[-60, -30, 0, 30, 60].map((latitude) => (
			<line
				key={latitude}
				x1="0"
				y1={160 - (latitude / 90) * 150}
				x2="720"
				y2={160 - (latitude / 90) * 150}
				stroke="currentColor"
				opacity="0.08"
			/>
		))}
		{[-120, -60, 0, 60, 120].map((longitude) => (
			<line
				key={longitude}
				x1={360 + longitude * 2}
				y1="0"
				x2={360 + longitude * 2}
				y2="320"
				stroke="currentColor"
				opacity="0.08"
			/>
		))}
		{items.map((item) => (
			<circle
				key={`${item.latitude}-${item.longitude}-${item.country}`}
				cx={360 + item.longitude * 2}
				cy={160 - (item.latitude / 90) * 150}
				r={Math.min(18, 4 + Math.sqrt(item.count) * 2)}
				fill="var(--tblr-red)"
				opacity="0.72"
			>
				<title>{`${item.country || "Unknown"}: ${item.count}`}</title>
			</circle>
		))}
	</svg>
);

const QuickFilters = ({ items, onSelect }: { items: CrowdsecInsightsItem[]; onSelect: (value: string) => void }) =>
	items.length === 0 ? (
		<span className="text-secondary small">
			<T id="crowdsec.insights.empty" />
		</span>
	) : (
		<div className="d-flex flex-wrap gap-1">
			{items.map((item) => (
				<button
					type="button"
					key={item.name}
					className="btn btn-sm btn-outline-secondary"
					onClick={() => onSelect(item.name)}
				>
					{item.name} <span className="badge bg-secondary-lt ms-1">{item.count}</span>
				</button>
			))}
		</div>
	);

const Metric = ({
	label,
	value,
	onClick,
	tone = "azure",
}: {
	label: ReactNode;
	value: string | number;
	onClick?: () => void;
	tone?: string;
}) => (
	<div className="col-sm-6 col-xl-3">
		<button
			type="button"
			className="card card-sm h-100 w-100 text-start"
			onClick={onClick}
			aria-haspopup={onClick ? "dialog" : undefined}
		>
			<div className={`card-status-start bg-${tone}`} />
			<div className="card-body">
				<div className="text-secondary text-uppercase small">{label}</div>
				<div className="h2 mb-0 mt-1">{typeof value === "number" ? intl.formatNumber(value) : value}</div>
				{onClick && (
					<div className="text-secondary small mt-2">
						<T id="crowdsec.kpi.open" />
					</div>
				)}
			</div>
		</button>
	</div>
);

const ItemList = ({ title, items }: { title: ReactNode; items: CrowdsecInsightsItem[] }) => (
	<div className="col-md-6">
		<h4>{title}</h4>
		{items.length ? (
			<div className="list-group list-group-flush">
				{items.map((item) => (
					<div key={item.name} className="list-group-item px-0 d-flex justify-content-between">
						<span>{item.name}</span>
						<span className="badge bg-secondary-lt">{item.count}</span>
					</div>
				))}
			</div>
		) : (
			<div className="text-secondary">
				<T id="crowdsec.insights.empty" />
			</div>
		)}
	</div>
);

const KpiDetailsModal = ({
	kind,
	insights,
	metrics,
	anubis,
	onClose,
	onNavigate,
}: {
	kind: KpiKind | null;
	insights?: CrowdsecInsights;
	metrics?: CrowdsecMetrics;
	anubis?: AnubisStatus;
	onClose: () => void;
	onNavigate: (tab: DashboardTab) => void;
}) => {
	const titles: Record<KpiKind, string> = {
		attacks: "crowdsec.kpi.attacks",
		local: "crowdsec.kpi.local",
		community: "crowdsec.kpi.community",
		anubis: "crowdsec.anubis.title",
	};
	const navigate = (tab: DashboardTab) => {
		onClose();
		onNavigate(tab);
	};
	return (
		<Modal show={kind !== null} onHide={onClose} size="lg" centered>
			<Modal.Header closeButton>
				<Modal.Title>{kind ? <T id={titles[kind]} /> : null}</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{kind === "attacks" && (
					<>
						<div className="h2 mb-3">
							{typeof insights?.alertCount === "number" ? intl.formatNumber(insights.alertCount) : "—"}{" "}
							<span className="text-secondary fs-5">
								<T id="crowdsec.insights.alert-count" />
							</span>
						</div>
						<div className="row g-4">
							<ItemList
								title={<T id="crowdsec.insights.scenarios" />}
								items={insights?.topScenarios ?? []}
							/>
							<ItemList
								title={<T id="crowdsec.insights.countries" />}
								items={insights?.topCountries ?? []}
							/>
							<ItemList title={<T id="crowdsec.insights.asns" />} items={insights?.topAsns ?? []} />
							<ItemList title={<T id="crowdsec.insights.targets" />} items={insights?.topTargets ?? []} />
						</div>
					</>
				)}
				{kind === "local" && (
					<>
						<p>
							<T id="crowdsec.kpi.local-help" />
						</p>
						<div className="h1">
							{typeof (metrics?.localActiveDecisions ?? insights?.localActiveDecisions) === "number"
								? intl.formatNumber(
										(metrics?.localActiveDecisions ?? insights?.localActiveDecisions) as number,
									)
								: "—"}
						</div>
					</>
				)}
				{kind === "community" && (
					<>
						<Alert variant="info">
							<T id="crowdsec.kpi.community-help" />
						</Alert>
						<div className="h1">
							{typeof metrics?.communityActiveDecisions === "number"
								? intl.formatNumber(metrics.communityActiveDecisions)
								: "—"}
						</div>
						{metrics?.decisionOrigins
							?.filter((item) => ["capi", "lists"].includes(item.name))
							.map((item) => (
								<div key={item.name} className="d-flex justify-content-between border-top py-2">
									<span>{item.name.toUpperCase()}</span>
									<strong>{intl.formatNumber(item.count)}</strong>
								</div>
							))}
					</>
				)}
				{kind === "anubis" && (
					<>
						<div className="d-flex gap-2 mb-3">
							<span className={`badge ${anubis?.container.up ? "bg-green-lt" : "bg-red-lt"}`}>
								{anubis?.container.up ? (
									<T id="crowdsec.anubis.container-up" />
								) : (
									<T id="crowdsec.anubis.container-down" />
								)}
							</span>
							<span className="badge bg-orange-lt">
								<T id="crowdsec.anubis.active" data={{ count: anubis?.honeypot.activeCount ?? 0 }} />
							</span>
						</div>
						<h4>
							<T id="crowdsec.anubis.recent" />
						</h4>
						{anubis?.recent.length ? (
							<div>
								{anubis.recent.map((ip) => (
									<span key={ip} className="badge bg-secondary-lt me-1 mb-1">
										{ip}
									</span>
								))}
							</div>
						) : (
							<div className="text-secondary">
								<T id="crowdsec.anubis.recent-empty" />
							</div>
						)}
					</>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={onClose}>
					<T id="action.close" />
				</Button>
				{kind === "attacks" && (
					<Button actionType="primary" onClick={() => navigate("activity")}>
						<T id="crowdsec.tabs.activity" />
					</Button>
				)}
				{kind === "local" && (
					<Button actionType="primary" onClick={() => navigate("bans")}>
						<T id="crowdsec.tabs.bans" />
					</Button>
				)}
			</Modal.Footer>
		</Modal>
	);
};

interface HistoryProps {
	windowHours: number;
	page: number;
	setPage: (page: number | ((value: number) => number)) => void;
	search: string;
	setSearch: (value: string) => void;
	scenario: string;
	setScenario: (value: string) => void;
	country: string;
	setCountry: (value: string) => void;
	target: string;
	setTarget: (value: string) => void;
}
const AttackHistory = ({
	windowHours,
	page,
	setPage,
	search,
	setSearch,
	scenario,
	setScenario,
	country,
	setCountry,
	target,
	setTarget,
}: HistoryProps) => {
	const { locale } = useLocaleState();
	const [expanded, setExpanded] = useState<number | null>(null);
	const deferredSearch = useDeferredValue(search);
	const params = useMemo(
		() => ({ page, pageSize: 25, windowHours, search: deferredSearch, scenario, country, target }),
		[page, windowHours, deferredSearch, scenario, country, target],
	);
	const history = useCrowdsecAlertHistory(params, { placeholderData: (previous: unknown) => previous });
	const clear = () => {
		setScenario("");
		setCountry("");
		setTarget("");
		setSearch("");
		setPage(1);
	};
	return (
		<div id="crowdsec-alert-history">
			<div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
				<h3 className="mb-0">
					<T id="crowdsec.history.title" />
				</h3>
				<div className="input-group input-group-flat" style={{ maxWidth: "32rem" }}>
					<span className="input-group-text">
						<IconSearch size={16} />
					</span>
					<input
						id="crowdsec-history-search"
						className="form-control form-control-sm"
						type="search"
						value={search}
						placeholder={intl.formatMessage({ id: "crowdsec.history.search" })}
						onChange={(event) => {
							setSearch(event.target.value);
							setPage(1);
						}}
					/>
				</div>
			</div>
			<div className="d-flex flex-wrap gap-2 mb-3">
				{[scenario, country, target].filter(Boolean).map((value) => (
					<span key={value} className="badge bg-azure-lt">
						{value}
					</span>
				))}
				{(scenario || country || target || search) && (
					<button type="button" className="btn btn-sm btn-outline-secondary" onClick={clear}>
						<T id="crowdsec.filters.clear" />
					</button>
				)}
			</div>
			{history.isError && !history.data ? (
				<Alert variant="danger">
					<T id={history.error?.message || "error.unknown"} />
				</Alert>
			) : !history.data ? (
				<div className="py-5 d-flex justify-content-center">
					<AnimatedLogo />
				</div>
			) : (
				<>
					{history.data.truncated && (
						<Alert variant="info">
							<T id="crowdsec.history.sampled" />
						</Alert>
					)}
					<div className="table-responsive">
						<table className="table table-vcenter table-striped">
							<thead>
								<tr>
									<th>
										<T id="crowdsec.time" />
									</th>
									<th>
										<T id="crowdsec.source" />
									</th>
									<th>
										<T id="crowdsec.reason" />
									</th>
									<th>
										<T id="crowdsec.target" />
									</th>
									<th>
										<T id="crowdsec.events" />
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{history.data.items.length === 0 && (
									<tr>
										<td colSpan={6} className="text-center text-secondary py-5">
											<T id="crowdsec.no-matches" />
										</td>
									</tr>
								)}
								{history.data.items.map((item) => {
									const open = expanded === item.id;
									return (
										<Fragment key={item.id}>
											<tr>
												<td>
													{item.createdAt || item.startAt
														? formatDateTime(item.createdAt || item.startAt, locale)
														: "—"}
												</td>
												<td>{alertSource(item)}</td>
												<td>{item.scenario}</td>
												<td>{alertTarget(item) || "—"}</td>
												<td>{item.eventsCount}</td>
												<td className="text-end">
													<div className="btn-list justify-content-end">
														<button
															type="button"
															className="btn btn-sm btn-outline-secondary"
															aria-expanded={open}
															onClick={() => setExpanded(open ? null : item.id)}
														>
															<T
																id={
																	open
																		? "crowdsec.collapse-details"
																		: "crowdsec.expand-details"
																}
															/>
														</button>
														{item.source.ip && (
															<Button
																size="sm"
																actionType="danger"
																onClick={() =>
																	showManualBanModal({
																		initialTarget: item.source.ip,
																	})
																}
															>
																<T id="crowdsec.ban" />
															</Button>
														)}
													</div>
												</td>
											</tr>
											{open && (
												<tr>
													<td colSpan={6} className="bg-light">
														<div className="small py-2">
															<div className="mb-2">{item.message}</div>
															{item.events.map((event, index) => (
																<div key={`${item.id}-${index}`} className="mb-2">
																	{event.timestamp && (
																		<div className="text-secondary">
																			{formatDateTime(event.timestamp, locale)}
																		</div>
																	)}
																	{event.meta.map((meta) => (
																		<div key={meta.key}>
																			<span className="text-secondary">
																				{meta.key}:
																			</span>{" "}
																			{meta.value}
																		</div>
																	))}
																</div>
															))}
														</div>
													</td>
												</tr>
											)}
										</Fragment>
									);
								})}
							</tbody>
						</table>
					</div>
					<div className="d-flex align-items-center justify-content-between pt-3 border-top">
						<span className="text-secondary">
							<T id="crowdsec.history.page" data={{ page }} />
						</span>
						<div className="btn-list">
							<Button
								actionType="secondary"
								variant="outline"
								disabled={page === 1 || history.isFetching}
								onClick={() => setPage((value) => Math.max(1, value - 1))}
							>
								<IconChevronLeft size={16} />
								<T id="crowdsec.previous" />
							</Button>
							<Button
								actionType="secondary"
								variant="outline"
								disabled={!history.data.hasNext || history.isFetching}
								onClick={() => setPage((value) => value + 1)}
							>
								<T id="crowdsec.next" />
								<IconChevronRight size={16} />
							</Button>
						</div>
					</div>
				</>
			)}
		</div>
	);
};

const SystemMetrics = ({ metrics }: { metrics: ReturnType<typeof useCrowdsecMetrics> }) =>
	!metrics.data ? (
		<div className="py-5 d-flex justify-content-center">
			<AnimatedLogo />
		</div>
	) : !metrics.data.available ? (
		<Alert variant="secondary">
			<T id={metrics.data.error || "crowdsec.metrics-unavailable"} />
		</Alert>
	) : (
		<>
			<h3>
				<T id="crowdsec.metrics.title" />
			</h3>
			<div className="row g-3">
				<Metric label={<T id="crowdsec.metrics.appsec-requests" />} value={metrics.data.appsecRequests ?? 0} />
				<Metric
					label={<T id="crowdsec.metrics.appsec-blocked" />}
					value={metrics.data.appsecBlocked ?? 0}
					tone="red"
				/>
				<Metric
					label={<T id="crowdsec.metrics.bouncer-requests" />}
					value={metrics.data.bouncerRequests ?? 0}
					tone="green"
				/>
				<Metric
					label={<T id="crowdsec.metrics.machine-requests" />}
					value={metrics.data.machineRequests ?? 0}
					tone="orange"
				/>
				<Metric
					label={<T id="crowdsec.metrics.parser-rate" />}
					value={
						metrics.data.parserSuccessRate === null || typeof metrics.data.parserSuccessRate === "undefined"
							? "—"
							: `${(metrics.data.parserSuccessRate * 100).toFixed(1)}%`
					}
				/>
				<Metric
					label={<T id="crowdsec.metrics.lapi-latency" />}
					value={
						metrics.data.averageLapiMs === null || typeof metrics.data.averageLapiMs === "undefined"
							? "—"
							: `${metrics.data.averageLapiMs.toFixed(1)} ms`
					}
				/>
			</div>
		</>
	);

const CrowdsecDashboard = () => {
	const [tab, setTab] = useState<DashboardTab>("overview");
	const [kpi, setKpi] = useState<KpiKind | null>(null);
	const [windowHours, setWindowHours] = useState(24);
	const [page, setPage] = useState(1);
	const [search, setSearch] = useState("");
	const [scenario, setScenario] = useState("");
	const [country, setCountry] = useState("");
	const [target, setTarget] = useState("");
	const [notificationsEnabled, setNotificationsEnabled] = useState(
		() => localStorage.getItem(NOTIFICATIONS_KEY) === "true",
	);
	const insights = useCrowdsecInsights(windowHours);
	const metrics = useCrowdsecMetrics();
	const anubis = useAnubisStatus();

	useEffect(() => {
		if (!notificationsEnabled || typeof Notification === "undefined" || Notification.permission !== "granted")
			return;
		if (!insights.isError) localStorage.removeItem(`${LAST_SIGNAL_KEY}.lapi`);
		const signal = insights.isError
			? undefined
			: (insights.data?.signals.find((item) => item.type === "attack-spike") ??
				insights.data?.signals.find((item) => item.type === "active-bans"));
		const signalId = signal?.id ?? (insights.isError ? "lapi-unavailable" : "");
		const signalType = insights.isError ? "lapi" : (signal?.type ?? "unknown");
		if (!signalId || localStorage.getItem(`${LAST_SIGNAL_KEY}.${signalType}`) === signalId) return;
		const body = insights.isError
			? intl.formatMessage({ id: "crowdsec.notification.unavailable" })
			: signal?.type === "attack-spike"
				? intl.formatMessage({ id: "crowdsec.notification.spike" })
				: intl.formatMessage({ id: "crowdsec.notification.bans" }, { count: signal?.count ?? 0 });
		const notice = new Notification(intl.formatMessage({ id: "crowdsec.title" }), { body, tag: signalId });
		notice.onclick = () => notice.close();
		localStorage.setItem(`${LAST_SIGNAL_KEY}.${signalType}`, signalId);
	}, [notificationsEnabled, insights.data?.signals, insights.isError]);

	const toggleNotifications = async () => {
		if (notificationsEnabled) {
			localStorage.setItem(NOTIFICATIONS_KEY, "false");
			setNotificationsEnabled(false);
			return;
		}
		if (typeof Notification !== "undefined" && (await Notification.requestPermission()) === "granted") {
			localStorage.setItem(NOTIFICATIONS_KEY, "true");
			setNotificationsEnabled(true);
		}
	};
	const quickFilter = (setter: (value: string) => void, value: string) => {
		setter(value);
		setPage(1);
		setTab("activity");
	};
	const refresh = () => Promise.all([insights.refetch(), metrics.refetch(), anubis.refetch()]);
	const tabs: { id: DashboardTab; label: string }[] = [
		{ id: "overview", label: "crowdsec.tabs.overview" },
		{ id: "activity", label: "crowdsec.tabs.activity" },
		{ id: "bans", label: "crowdsec.tabs.bans" },
		{ id: "system", label: "crowdsec.tabs.system" },
	];

	return (
		<>
			<div className="card mt-4 overflow-visible">
				<div className="card-status-top bg-azure" />
				<div className="sticky-top bg-body border-bottom" style={{ zIndex: 20 }}>
					<div className="card-header border-0">
						<div className="row w-100 align-items-center g-2">
							<div className="col">
								<h2 className="card-title d-flex align-items-center gap-2">
									<AnimatedLogo size="compact" />
									<T id="crowdsec.dashboard" />
								</h2>
								<div className="d-flex gap-2 mt-1">
									<span className={`badge ${insights.isError ? "bg-red-lt" : "bg-green-lt"}`}>
										<T id={insights.isError ? "crowdsec.status.down" : "crowdsec.status.up"} />
									</span>
									<span
										className={`badge ${anubis.data?.container.up ? "bg-green-lt" : "bg-orange-lt"}`}
									>
										<T
											id={
												anubis.data?.container.up
													? "crowdsec.anubis.container-up"
													: "crowdsec.anubis.container-down"
											}
										/>
									</span>
								</div>
							</div>
							<div className="col-auto d-flex flex-wrap gap-2">
								<select
									className="form-select form-select-sm w-auto"
									aria-label={intl.formatMessage({ id: "crowdsec.window" })}
									value={windowHours}
									onChange={(event) => {
										setWindowHours(Number(event.target.value));
										setPage(1);
									}}
								>
									<option value={1}>1h</option>
									<option value={6}>6h</option>
									<option value={24}>24h</option>
									<option value={168}>7d</option>
								</select>
								<Button
									actionType="secondary"
									variant="outline"
									disabled={typeof Notification === "undefined"}
									aria-pressed={notificationsEnabled}
									onClick={toggleNotifications}
								>
									{notificationsEnabled ? <IconBell size={16} /> : <IconBellOff size={16} />}
									<span className="ms-1">
										<T
											id={
												notificationsEnabled
													? "crowdsec.notifications.on"
													: "crowdsec.notifications.off"
											}
										/>
									</span>
								</Button>
								<Button actionType="danger" onClick={() => showManualBanModal({})}>
									<T id="crowdsec.ban" />
								</Button>
								<Button
									actionType="secondary"
									variant="outline"
									isLoading={insights.isFetching || metrics.isFetching || anubis.isFetching}
									onClick={refresh}
								>
									<IconRefresh size={16} />
									<span className="visually-hidden">
										<T id="crowdsec.refresh" />
									</span>
								</Button>
							</div>
						</div>
					</div>
					<div className="px-3">
						<ul className="nav nav-tabs card-header-tabs">
							{tabs.map((item) => (
								<li className="nav-item" key={item.id}>
									<button
										type="button"
										role="tab"
										aria-selected={tab === item.id}
										className={`nav-link ${tab === item.id ? "active" : ""}`}
										onClick={() => setTab(item.id)}
									>
										<T id={item.label} />
									</button>
								</li>
							))}
						</ul>
					</div>
				</div>
				<div className="card-body">
					{insights.isError && !insights.data && (
						<Alert variant="danger">
							<T id="crowdsec.insights.error" />: <T id={insights.error?.message || "error.unknown"} />
						</Alert>
					)}
					{tab === "overview" &&
						(!insights.data ? (
							<div className="py-5 d-flex justify-content-center">
								<AnimatedLogo />
							</div>
						) : (
							<>
								{insights.data.signals.some((signal) => signal.type === "attack-spike") && (
									<Alert variant="warning">
										<T id="crowdsec.spike-warning" />
									</Alert>
								)}
								<div className="row g-3 mb-4">
									<Metric
										label={<T id="crowdsec.kpi.attacks" />}
										value={insights.data.alertCount}
										onClick={() => setKpi("attacks")}
									/>
									<Metric
										label={<T id="crowdsec.kpi.local" />}
										value={
											metrics.data?.localActiveDecisions ??
											insights.data.localActiveDecisions ??
											"—"
										}
										tone="red"
										onClick={() => setKpi("local")}
									/>
									<Metric
										label={<T id="crowdsec.kpi.community" />}
										value={metrics.data?.communityActiveDecisions ?? "—"}
										tone="green"
										onClick={() => setKpi("community")}
									/>
									<Metric
										label={<T id="crowdsec.anubis.title" />}
										value={anubis.data?.honeypot.activeCount ?? "—"}
										tone="orange"
										onClick={() => setKpi("anubis")}
									/>
								</div>
								<div className="row g-4">
									<div className="col-lg-7">
										<h3>
											<T id="crowdsec.activity" />
										</h3>
										<ActivityChart items={insights.data.activity} />
									</div>
									<div className="col-lg-5">
										<h3>
											<T id="crowdsec.attack-map" />
										</h3>
										{insights.data.locations.length ? (
											<AttackMap items={insights.data.locations} />
										) : (
											<div className="text-secondary py-5 text-center">
												<T id="crowdsec.location-empty" />
											</div>
										)}
									</div>
								</div>
								<div className="row g-3 mt-1">
									<div className="col-lg-3">
										<div className="text-secondary small mb-2">
											<T id="crowdsec.insights.scenarios" />
										</div>
										<QuickFilters
											items={insights.data.topScenarios}
											onSelect={(value) => quickFilter(setScenario, value)}
										/>
									</div>
									<div className="col-lg-3">
										<div className="text-secondary small mb-2">
											<T id="crowdsec.insights.countries" />
										</div>
										<QuickFilters
											items={insights.data.topCountries}
											onSelect={(value) => quickFilter(setCountry, value)}
										/>
									</div>
									<div className="col-lg-3">
										<div className="text-secondary small mb-2">
											<T id="crowdsec.insights.asns" />
										</div>
										<QuickFilters
											items={insights.data.topAsns}
											onSelect={(value) => quickFilter(setSearch, value)}
										/>
									</div>
									<div className="col-lg-3">
										<div className="text-secondary small mb-2">
											<T id="crowdsec.insights.targets" />
										</div>
										<QuickFilters
											items={insights.data.topTargets}
											onSelect={(value) => quickFilter(setTarget, value)}
										/>
									</div>
								</div>
							</>
						))}
					{tab === "activity" && (
						<AttackHistory
							{...{
								windowHours,
								page,
								setPage,
								search,
								setSearch,
								scenario,
								setScenario,
								country,
								setCountry,
								target,
								setTarget,
							}}
						/>
					)}
					{tab === "bans" && <ActiveBans />}
					{tab === "system" && <SystemMetrics metrics={metrics} />}
				</div>
			</div>
			<KpiDetailsModal
				kind={kpi}
				insights={insights.data}
				metrics={metrics.data}
				anubis={anubis.data}
				onClose={() => setKpi(null)}
				onNavigate={setTab}
			/>
		</>
	);
};

export default CrowdsecDashboard;
