import { IconChevronLeft, IconChevronRight, IconSearch } from "@tabler/icons-react";
import { Fragment, useDeferredValue, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import type { CrowdsecAlert } from "src/api/backend";
import { Button } from "src/components";
import { useLocaleState } from "src/context";
import { useCrowdsecAlertHistory } from "src/hooks";
import { formatDateTime, intl, T } from "src/locale";
import { showManualBanModal } from "src/modals";
import { TableSkeleton } from "./LoadingSkeleton";

const alertTarget = (alert: CrowdsecAlert) => {
	for (const event of alert.events)
		for (const item of event.meta)
			if (["target_host", "target_fqdn", "target_uri"].includes(item.key)) return item.value;
	return "";
};
const alertSource = (alert: CrowdsecAlert) => alert.source.ip || alert.source.value || alert.source.rdns || "—";

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
	const [scan, setScan] = useState<{ key: string; cursors: string[]; page: number; session: number } | null>(null);
	const filterKey = JSON.stringify([windowHours, deferredSearch, scenario, country, target]);
	const activePage = scan ? (scan.key === filterKey ? scan.page : 1) : page;
	const cursor = scan ? (scan.key === filterKey ? scan.cursors[activePage - 1] : "") : undefined;
	const params = useMemo(
		() => ({
			page: activePage,
			pageSize: 25,
			windowHours,
			search: deferredSearch,
			scenario,
			country,
			target,
			cursor,
		}),
		[activePage, windowHours, deferredSearch, scenario, country, target, cursor],
	);
	const history = useCrowdsecAlertHistory(params, {
		queryKey: ["crowdsec-alert-history", params, scan?.session],
		placeholderData: scan ? undefined : (previous: unknown) => previous,
		refetchInterval: scan ? false : 60_000,
		refetchOnWindowFocus: !scan,
		staleTime: scan ? Number.POSITIVE_INFINITY : 30_000,
	});
	const clear = () => {
		setScenario("");
		setCountry("");
		setTarget("");
		setSearch("");
		setPage(1);
	};
	return (
		<div id="crowdsec-alert-history">
			<div className="d-flex flex-wrap gap-2 mb-3">
				<button
					type="button"
					className="btn btn-sm btn-outline-secondary"
					onClick={() => {
						setScan(scan ? null : { key: filterKey, cursors: [""], page: 1, session: Date.now() });
						setPage(1);
					}}
				>
					<T id={scan ? "crowdsec.history.recent" : "crowdsec.history.explore"} />
				</button>
				{scan && (
					<button
						type="button"
						className="btn btn-sm btn-outline-secondary"
						onClick={() => {
							setScan({ key: filterKey, cursors: [""], page: 1, session: Date.now() });
						}}
					>
						<T id="crowdsec.history.restart" />
					</button>
				)}
			</div>
			{scan && (
				<Alert variant="info">
					<T id="crowdsec.history.scan-help" />
				</Alert>
			)}
			{scan && history.data?.start && history.data.end && (
				<p className="small text-secondary">
					{formatDateTime(history.data.start, locale)} — {formatDateTime(history.data.end, locale)}
				</p>
			)}
			{history.isError && history.data && (
				<Alert variant="warning">
					<T id="crowdsec.stale" />
				</Alert>
			)}
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
						aria-label={intl.formatMessage({ id: "crowdsec.history.search" })}
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
					<span key={value} className="badge bg-azure-lt text-break">
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
				<TableSkeleton />
			) : (
				<>
					{history.data.truncated && (
						<Alert variant="info">
							<T id={scan ? "crowdsec.history.scan-limit" : "crowdsec.history.sampled"} />
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
											<T
												id={
													scan
														? "crowdsec.history.batch-empty"
														: scenario || country || target || search
															? "crowdsec.history.no-matches"
															: "crowdsec.history.empty"
												}
											/>
										</td>
									</tr>
								)}
								{history.data.items.map((item) => {
									const open = expanded === item.id;
									return (
										<Fragment key={item.id}>
											<tr>
												<td>
													{item.startAt || item.createdAt
														? formatDateTime(item.startAt || item.createdAt, locale)
														: "—"}
												</td>
												<td className="text-break" style={{ minWidth: "10rem" }}>
													{alertSource(item)}
												</td>
												<td className="text-break">{item.scenario}</td>
												<td className="text-break">{alertTarget(item) || "—"}</td>
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
													<td colSpan={6} className="bg-secondary-lt">
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
							<T id="crowdsec.history.page" data={{ page: activePage }} />
							{" · "}
							<T
								id={
									scan
										? "crowdsec.history.batch-matches"
										: history.data.truncated
											? "crowdsec.matches-at-least"
											: "crowdsec.matches"
								}
								data={{ count: history.data.matched }}
							/>
						</span>
						<div className="btn-list">
							<button
								type="button"
								className="btn btn-outline-secondary"
								disabled={activePage === 1 || history.isFetching}
								onClick={() =>
									scan
										? setScan({ ...scan, page: Math.max(1, activePage - 1) })
										: setPage((value) => Math.max(1, value - 1))
								}
							>
								<IconChevronLeft size={16} />
								<T id="crowdsec.previous" />
							</button>
							<button
								type="button"
								className="btn btn-outline-secondary"
								disabled={!history.data.hasNext || history.isFetching}
								onClick={() => {
									if (scan && history.data.nextCursor)
										setScan({
											...scan,
											key: filterKey,
											cursors: [
												...(scan.key === filterKey ? scan.cursors.slice(0, activePage) : [""]),
												history.data.nextCursor,
											],
											page: activePage + 1,
										});
									else if (!scan) setPage((value) => value + 1);
								}}
							>
								<T id="crowdsec.next" />
								<IconChevronRight size={16} />
							</button>
						</div>
					</div>
				</>
			)}
		</div>
	);
};

export default AttackHistory;
