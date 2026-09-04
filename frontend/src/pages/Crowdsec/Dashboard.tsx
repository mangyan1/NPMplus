import {
	IconBell,
	IconBellOff,
	IconChevronLeft,
	IconChevronRight,
	IconRefresh,
	IconSearch,
	IconShieldCheck,
} from "@tabler/icons-react";
import { Fragment, useDeferredValue, useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import type { CrowdsecAlert, CrowdsecInsightsItem } from "src/api/backend";
import { Button } from "src/components";
import { useLocaleState } from "src/context";
import { useCrowdsecAlertHistory, useCrowdsecInsights, useCrowdsecMetrics } from "src/hooks";
import { formatDateTime, intl, T } from "src/locale";
import { showManualBanModal } from "src/modals";
import AnimatedLogo from "./AnimatedLogo";

const NOTIFICATIONS_KEY = "npmplus.crowdsec.browser-notifications";
const LAST_SIGNAL_KEY = "npmplus.crowdsec.last-signal";

const alertTarget = (alert: CrowdsecAlert) => {
	for (const event of alert.events) {
		for (const item of event.meta) {
			if (["target_host", "target_fqdn", "target_uri"].includes(item.key)) return item.value;
		}
	}
	return "";
};

const alertSource = (alert: CrowdsecAlert) => alert.source.ip || alert.source.value || alert.source.rdns || "—";

const ActivityChart = ({ items }: { items: { start: string; count: number }[] }) => {
	const width = 720;
	const height = 160;
	const max = Math.max(1, ...items.map((item) => item.count));
	const gap = 2;
	const barWidth = Math.max(1, width / Math.max(1, items.length) - gap);
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
						className="fill-azure"
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
				className="fill-red"
				opacity="0.72"
			>
				<title>{`${item.country || "Unknown"}: ${item.count}`}</title>
			</circle>
		))}
	</svg>
);

interface QuickFiltersProps {
	items: CrowdsecInsightsItem[];
	onSelect: (value: string) => void;
}

const QuickFilters = ({ items, onSelect }: QuickFiltersProps) =>
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

const Metric = ({ label, value }: { label: React.ReactNode; value: string | number }) => (
	<div className="col-sm-6 col-xl-3">
		<div className="card card-sm h-100">
			<div className="card-body">
				<div className="text-secondary text-uppercase small">{label}</div>
				<div className="h2 mb-0 mt-1">{value}</div>
			</div>
		</div>
	</div>
);

const CrowdsecDashboard = () => {
	const { locale } = useLocaleState();
	const [windowHours, setWindowHours] = useState(24);
	const [page, setPage] = useState(1);
	const [search, setSearch] = useState("");
	const deferredSearch = useDeferredValue(search);
	const [scenario, setScenario] = useState("");
	const [country, setCountry] = useState("");
	const [target, setTarget] = useState("");
	const [expanded, setExpanded] = useState<number | null>(null);
	const [notificationsEnabled, setNotificationsEnabled] = useState(
		() => localStorage.getItem(NOTIFICATIONS_KEY) === "true",
	);
	const insights = useCrowdsecInsights(windowHours);
	const metrics = useCrowdsecMetrics();
	const historyParams = useMemo(
		() => ({ page, pageSize: 25, windowHours, search: deferredSearch, scenario, country, target }),
		[page, windowHours, deferredSearch, scenario, country, target],
	);
	const history = useCrowdsecAlertHistory(historyParams, { placeholderData: (previous: unknown) => previous });

	useEffect(() => {
		if (!notificationsEnabled || typeof Notification === "undefined" || Notification.permission !== "granted")
			return;
		if (!insights.isError) localStorage.removeItem(`${LAST_SIGNAL_KEY}.lapi`);
		if (!insights.data?.signals.some((item) => item.type === "active-bans"))
			localStorage.removeItem(`${LAST_SIGNAL_KEY}.active-bans`);
		const signal = insights.isError
			? undefined
			: (insights.data?.signals.find((item) => item.type === "attack-spike") ??
				insights.data?.signals.find((item) => item.type === "active-bans"));
		const signalId = signal?.id ?? (insights.isError ? "lapi-unavailable" : "");
		const signalType = insights.isError ? "lapi" : (signal?.type ?? "unknown");
		const signalStorageKey = `${LAST_SIGNAL_KEY}.${signalType}`;
		if (!signalId || localStorage.getItem(signalStorageKey) === signalId) return;
		const body = insights.isError
			? intl.formatMessage({ id: "crowdsec.notification.unavailable" })
			: signal?.type === "attack-spike"
				? intl.formatMessage({ id: "crowdsec.notification.spike" })
				: intl.formatMessage({ id: "crowdsec.notification.bans" }, { count: signal?.count ?? 0 });
		const notice = new Notification(intl.formatMessage({ id: "crowdsec.title" }), { body, tag: signalId });
		notice.onclick = () => notice.close();
		localStorage.setItem(signalStorageKey, signalId);
	}, [notificationsEnabled, insights.data?.signals, insights.isError]);

	const toggleNotifications = async () => {
		if (notificationsEnabled) {
			localStorage.setItem(NOTIFICATIONS_KEY, "false");
			setNotificationsEnabled(false);
			return;
		}
		if (typeof Notification === "undefined") return;
		const permission = await Notification.requestPermission();
		if (permission === "granted") {
			localStorage.setItem(NOTIFICATIONS_KEY, "true");
			setNotificationsEnabled(true);
		}
	};

	const applyQuickFilter = (setter: (value: string) => void, value: string) => {
		setter(value);
		setPage(1);
		document.getElementById("crowdsec-alert-history")?.scrollIntoView({ behavior: "smooth", block: "start" });
	};

	return (
		<>
			<div className="card mt-4">
				<div className="card-status-top bg-azure" />
				<div className="card-header">
					<div className="row w-full align-items-center">
						<div className="col">
							<h2 className="card-title d-flex align-items-center gap-2">
								<IconShieldCheck size={22} />
								<T id="crowdsec.dashboard" />
							</h2>
						</div>
						<div className="col-auto d-flex gap-2">
							<select
								className="form-select form-select-sm"
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
							<Button
								actionType="secondary"
								variant="outline"
								isLoading={insights.isFetching}
								onClick={() => insights.refetch()}
							>
								<IconRefresh size={16} />
								<span className="visually-hidden">
									<T id="crowdsec.refresh" />
								</span>
							</Button>
						</div>
					</div>
				</div>
				<div className="card-body">
					{insights.isError && !insights.data && (
						<Alert variant="danger">
							<T id="crowdsec.insights.error" />
							{insights.error?.message ? (
								<>
									: <T id={insights.error.message} />
								</>
							) : null}
						</Alert>
					)}
					{!insights.data ? (
						<div className="py-4 d-flex justify-content-center">
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
									label={<T id="crowdsec.insights.alert-count" />}
									value={insights.data.alertCount}
								/>
								<Metric
									label={<T id="crowdsec.active-bans" />}
									value={insights.data.activeDecisions ?? "—"}
								/>
								<Metric
									label={<T id="crowdsec.metrics.appsec-blocked" />}
									value={metrics.data?.available ? (metrics.data.appsecBlocked ?? 0) : "—"}
								/>
								<Metric
									label={<T id="crowdsec.metrics.parser-rate" />}
									value={
										metrics.data?.available &&
										metrics.data.parserSuccessRate !== null &&
										typeof metrics.data.parserSuccessRate !== "undefined"
											? `${(metrics.data.parserSuccessRate * 100).toFixed(1)}%`
											: "—"
									}
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
										onSelect={(value) => applyQuickFilter(setScenario, value)}
									/>
								</div>
								<div className="col-lg-3">
									<div className="text-secondary small mb-2">
										<T id="crowdsec.insights.countries" />
									</div>
									<QuickFilters
										items={insights.data.topCountries}
										onSelect={(value) => applyQuickFilter(setCountry, value)}
									/>
								</div>
								<div className="col-lg-3">
									<div className="text-secondary small mb-2">
										<T id="crowdsec.insights.asns" />
									</div>
									<QuickFilters
										items={insights.data.topAsns}
										onSelect={(value) => applyQuickFilter(setSearch, value)}
									/>
								</div>
								<div className="col-lg-3">
									<div className="text-secondary small mb-2">
										<T id="crowdsec.insights.targets" />
									</div>
									<QuickFilters
										items={insights.data.topTargets}
										onSelect={(value) => applyQuickFilter(setTarget, value)}
									/>
								</div>
							</div>
						</>
					)}
				</div>
			</div>

			<div className="card mt-4" id="crowdsec-alert-history">
				<div className="card-status-top bg-orange" />
				<div className="card-header">
					<div className="row w-full align-items-center g-2">
						<div className="col">
							<h2 className="card-title">
								<T id="crowdsec.history.title" />
							</h2>
						</div>
						<div className="col-md-auto">
							<div className="input-group input-group-flat">
								<label className="visually-hidden" htmlFor="crowdsec-history-search">
									<T id="crowdsec.history.search" />
								</label>
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
					</div>
				</div>
				<div className="card-body border-bottom py-2">
					<div className="d-flex flex-wrap align-items-center gap-2">
						{scenario && (
							<button
								type="button"
								className="btn btn-sm btn-azure"
								onClick={() => applyQuickFilter(setScenario, "")}
							>
								{scenario} ×
							</button>
						)}
						{country && (
							<button
								type="button"
								className="btn btn-sm btn-azure"
								onClick={() => applyQuickFilter(setCountry, "")}
							>
								{country} ×
							</button>
						)}
						{target && (
							<button
								type="button"
								className="btn btn-sm btn-azure"
								onClick={() => applyQuickFilter(setTarget, "")}
							>
								{target} ×
							</button>
						)}
						{(scenario || country || target || search) && (
							<button
								type="button"
								className="btn btn-sm btn-outline-secondary"
								onClick={() => {
									setScenario("");
									setCountry("");
									setTarget("");
									setSearch("");
									setPage(1);
								}}
							>
								<T id="crowdsec.filters.clear" />
							</button>
						)}
					</div>
				</div>
				{history.isError && !history.data ? (
					<div className="card-body">
						<Alert variant="danger">
							<T id={history.error?.message || "error.unknown"} />
						</Alert>
					</div>
				) : !history.data ? (
					<div className="card-body py-5 d-flex justify-content-center">
						<AnimatedLogo />
					</div>
				) : (
					<div className="table-responsive">
						{history.data.truncated && (
							<div className="alert alert-info rounded-0 mb-0">
								<T id="crowdsec.history.sampled" />
							</div>
						)}
						<table className="table table-vcenter card-table table-striped">
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
									<th>&nbsp;</th>
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
									const source = alertSource(item);
									return (
										<Fragment key={item.id}>
											<tr>
												<td>
													{item.createdAt || item.startAt
														? formatDateTime(item.createdAt || item.startAt, locale)
														: "—"}
												</td>
												<td>{source}</td>
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
																<div
																	key={`${item.id}-${event.timestamp}-${index}`}
																	className="mb-2"
																>
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
				)}
				<div className="card-footer d-flex align-items-center justify-content-between">
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
							disabled={!history.data?.hasNext || history.isFetching}
							onClick={() => setPage((value) => value + 1)}
						>
							<T id="crowdsec.next" />
							<IconChevronRight size={16} />
						</Button>
					</div>
				</div>
			</div>

			<div className="card mt-4">
				<div className="card-status-top bg-green" />
				<div className="card-header">
					<h2 className="card-title">
						<T id="crowdsec.metrics.title" />
					</h2>
				</div>
				<div className="card-body">
					{!metrics.data ? (
						<div className="py-4 d-flex justify-content-center">
							<AnimatedLogo />
						</div>
					) : metrics.data.available ? (
						<div className="row g-3">
							<Metric
								label={<T id="crowdsec.metrics.appsec-requests" />}
								value={metrics.data.appsecRequests ?? 0}
							/>
							<Metric
								label={<T id="crowdsec.metrics.bouncer-requests" />}
								value={metrics.data.bouncerRequests ?? 0}
							/>
							<Metric
								label={<T id="crowdsec.metrics.machine-requests" />}
								value={metrics.data.machineRequests ?? 0}
							/>
							<Metric
								label={<T id="crowdsec.metrics.lapi-latency" />}
								value={
									metrics.data.averageLapiMs === null ||
									typeof metrics.data.averageLapiMs === "undefined"
										? "—"
										: `${metrics.data.averageLapiMs.toFixed(1)} ms`
								}
							/>
						</div>
					) : (
						<Alert variant="secondary" className="mb-0">
							<T id={metrics.data?.error || "crowdsec.metrics-unavailable"} />
						</Alert>
					)}
				</div>
			</div>
		</>
	);
};

export default CrowdsecDashboard;
