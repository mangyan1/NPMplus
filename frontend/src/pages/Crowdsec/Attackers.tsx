import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Offcanvas from "react-bootstrap/Offcanvas";
import { type CrowdsecAlert, getCrowdsecDecisions } from "src/api/backend";
import {
	type AttackerPage,
	getAttackerEvents,
	getAttackerTimeline,
	getCrowdsecAttackers,
} from "src/api/backend/getCrowdsecAttackers";
import { formatDateTime, intl, T } from "src/locale";
import AttackDetails, { RuleDetails } from "./AttackDetails";
import styles from "./Attackers.module.css";
import { TableSkeleton } from "./LoadingSkeleton";
import { scenarioLabel } from "./scenarios";

const comparableIp = (value: string) => {
	try {
		return value.includes(":") ? new URL(`http://[${value}]`).hostname : value;
	} catch {
		return value;
	}
};

const Events = ({ alert }: { alert: CrowdsecAlert }) => {
	const [page, setPage] = useState(1);
	const events = useQuery({
		queryKey: ["crowdsec-attacker-events", alert.id, page],
		queryFn: ({ signal }) => getAttackerEvents(alert.id, page, signal),
		retry: false,
	});
	return (
		<>
			{events.isError ? (
				<Alert variant="warning">
					<T id="crowdsec.attackers.events-unavailable" />
				</Alert>
			) : !events.data ? (
				<TableSkeleton />
			) : (
				<>
					<p className="text-secondary">
						<T id="crowdsec.attackers.retained" data={{ count: events.data.retained }} />
					</p>
					{events.data.truncated && (
						<Alert variant="info">
							<T id="crowdsec.attackers.events-partial" />
						</Alert>
					)}
					<AttackDetails alert={events.data.alert} />
					<div className="d-flex flex-wrap gap-2">
						<button
							type="button"
							className="btn btn-sm"
							disabled={page === 1}
							onClick={() => setPage(page - 1)}
						>
							<T id="crowdsec.previous" />
						</button>
						<span className="align-self-center">
							<T id="crowdsec.history.page" data={{ page }} />
						</span>
						<button
							type="button"
							className="btn btn-sm"
							disabled={!events.data.hasNext || page >= 1000}
							onClick={() => setPage(page + 1)}
						>
							<T id="crowdsec.next" />
						</button>
					</div>
				</>
			)}
		</>
	);
};

const Timeline = ({ ip, windowHours, onClose }: { ip: string; windowHours: number; onClose: () => void }) => {
	const [expanded, setExpanded] = useState<number | null>(null);
	const history = useInfiniteQuery({
		queryKey: ["crowdsec-attacker-timeline", ip, windowHours],
		initialPageParam: "",
		queryFn: ({ pageParam, signal }) => getAttackerTimeline(ip, windowHours, pageParam, signal),
		getNextPageParam: (last) => last.nextCursor || undefined,
		retry: false,
		staleTime: Number.POSITIVE_INFINITY,
		refetchOnMount: "always",
	});
	const pages = history.data?.pages ?? [];
	const latest = pages.at(-1);
	const alerts = [...new Map(pages.flatMap((page) => page.items).map((alert) => [alert.id, alert])).values()].sort(
		(a, b) => Date.parse(a.startAt || a.createdAt) - Date.parse(b.startAt || b.createdAt) || a.id - b.id,
	);
	return (
		<Offcanvas show onHide={onClose} placement="end" className={styles.drawer} aria-labelledby="attacker-title">
			<Offcanvas.Header closeButton>
				<Offcanvas.Title id="attacker-title">
					<T id="crowdsec.attackers.timeline" />
					<div className="text-break mt-1">
						<code>{ip}</code>
					</div>
				</Offcanvas.Title>
			</Offcanvas.Header>
			<Offcanvas.Body>
				<p className="text-secondary">
					<T id="crowdsec.attackers.evidence-help" />
				</p>
				{history.isError && (
					<Alert variant="warning">
						<T id="crowdsec.attackers.timeline-error" />
						<button
							type="button"
							className="btn btn-sm ms-2"
							onClick={() => (history.hasNextPage ? history.fetchNextPage() : history.refetch())}
						>
							<T id="crowdsec.attackers.retry" />
						</button>
					</Alert>
				)}
				{!history.data && history.isPending && <TableSkeleton />}
				{latest && (
					<>
						<div className="border rounded p-3 mb-4">
							<h3>
								<T id="crowdsec.attackers.decisions" />
							</h3>
							{latest.decisionsCheckedAt && (
								<p className="small text-secondary">
									<T id="crowdsec.attackers.checked" />: {formatDateTime(latest.decisionsCheckedAt)}
								</p>
							)}
							{!latest.decisionsAvailable ? (
								<T id="crowdsec.attackers.decisions-unavailable" />
							) : latest.decisions.length ? (
								latest.decisions.map((decision) => (
									<div key={decision.id} className="text-break mb-2">
										<strong>{decision.type}</strong> · {decision.scenario}
										<div className="text-secondary">
											<T id="crowdsec.expires" />:{" "}
											{decision.until ? formatDateTime(decision.until) : decision.duration}
										</div>
									</div>
								))
							) : (
								<T id="crowdsec.attackers.no-decision" />
							)}
							{latest.decisionsTruncated && (
								<p>
									<T id="crowdsec.attackers.partial" />
								</p>
							)}
							<p className="small text-secondary mb-0 mt-2">
								<T id="crowdsec.attackers.decision-help" />
							</p>
						</div>
						<p className="small text-secondary">
							<T id="crowdsec.attackers.window" />: {formatDateTime(latest.start || "")} —{" "}
							{formatDateTime(latest.end || "")}
						</p>
						{(history.hasNextPage || latest.truncated) && (
							<Alert variant="info">
								<T id="crowdsec.attackers.timeline-partial" />
							</Alert>
						)}
						{!alerts.length && (
							<p>
								<T id="crowdsec.attackers.timeline-empty" />
							</p>
						)}
						<ol className={styles.timeline}>
							{alerts.map((alert) => (
								<li key={alert.id}>
									<time className="small text-secondary">
										{formatDateTime(alert.startAt || alert.createdAt)}
									</time>
									<RuleDetails name={alert.scenario} />
									<p className="small mt-2">
										<T id="crowdsec.attackers.alert-events" data={{ count: alert.eventsCount }} />
									</p>
									<button
										type="button"
										className="btn btn-sm btn-outline-secondary"
										aria-expanded={expanded === alert.id}
										onClick={() => setExpanded(expanded === alert.id ? null : alert.id)}
									>
										<T
											id={
												expanded === alert.id
													? "crowdsec.collapse-details"
													: "crowdsec.expand-details"
											}
										/>
									</button>
									{expanded === alert.id && <Events key={alert.id} alert={alert} />}
								</li>
							))}
						</ol>
						{history.hasNextPage && (
							<button
								type="button"
								className="btn btn-outline-primary"
								disabled={history.isFetchingNextPage}
								onClick={() => history.fetchNextPage()}
							>
								<T id="crowdsec.attackers.older" />
							</button>
						)}
					</>
				)}
			</Offcanvas.Body>
		</Offcanvas>
	);
};

const initial = { session: "", advance: "", page: 1, search: "", sort: "last" };
const Attackers = ({ windowHours }: { windowHours: number }) => {
	const [params, setParams] = useState(initial);
	const [refresh, setRefresh] = useState(0);
	const [search, setSearch] = useState("");
	const [selected, setSelected] = useState<string | null>(null);
	const catalog = useQuery({
		queryKey: ["crowdsec-attackers", windowHours, params, refresh],
		queryFn: ({ signal }) => getCrowdsecAttackers({ ...params, windowHours }, signal),
		retry: false,
		staleTime: Number.POSITIVE_INFINITY,
		refetchOnWindowFocus: false,
		placeholderData: (previous) => previous,
	});
	const [lastData, setLastData] = useState<AttackerPage>();
	useEffect(() => {
		if (catalog.data && !catalog.isPlaceholderData) setLastData(catalog.data);
	}, [catalog.data, catalog.isPlaceholderData]);
	const data = catalog.data || lastData;
	const decisions = useQuery({
		queryKey: ["crowdsec-decisions", "attacker-status"],
		queryFn: ({ signal }) => getCrowdsecDecisions({ page: 1, pageSize: 100, origin: "local" }, signal),
		refetchInterval: 30000,
		retry: false,
	});
	const banStatus = (ip: string) => {
		if (decisions.isError || !decisions.data) return "ban-unknown";
		if (
			decisions.data.items.some(
				(item) =>
					comparableIp(item.value) === comparableIp(ip) &&
					item.scope.toLowerCase() === "ip" &&
					item.type === "ban" &&
					!item.simulated,
			)
		)
			return "ban-active";
		return decisions.data.truncated || decisions.data.hasNext ? "ban-unknown" : "ban-none";
	};
	const update = (change: Partial<typeof initial>) =>
		setParams({ ...params, session: data?.session || params.session, advance: "-", ...change });
	return (
		<section aria-labelledby="attackers-heading">
			<div className="d-flex flex-wrap justify-content-between gap-2 mb-2">
				<h2 id="attackers-heading">
					<T id="crowdsec.attackers.title" />
				</h2>
				<button
					type="button"
					className="btn btn-sm"
					disabled={catalog.isFetching}
					onClick={() => {
						setParams({ ...initial, search });
						setRefresh(refresh + 1);
					}}
				>
					<T id="crowdsec.attackers.refresh" />
				</button>
			</div>
			<p className="text-secondary">
				<T id="crowdsec.attackers.help" />
			</p>
			<form
				className={styles.filters}
				onSubmit={(event) => {
					event.preventDefault();
					update({ search, page: 1 });
				}}
			>
				<label>
					<span className="form-label">
						<T id="crowdsec.attackers.search" />
					</span>
					<input
						className="form-control"
						value={search}
						onChange={(event) => setSearch(event.target.value)}
					/>
				</label>
				<label>
					<span className="form-label">
						<T id="crowdsec.attackers.sort" />
					</span>
					<select
						className="form-select"
						value={params.sort}
						onChange={(event) => update({ sort: event.target.value, page: 1 })}
					>
						<option value="last">{intl.formatMessage({ id: "crowdsec.attackers.recent" })}</option>
						<option value="alerts">{intl.formatMessage({ id: "crowdsec.attackers.alerts" })}</option>
					</select>
				</label>
				<button className="btn btn-outline-primary" type="submit" disabled={catalog.isFetching}>
					<T id="crowdsec.attackers.filter" />
				</button>
			</form>
			{catalog.isError && (
				<Alert variant="warning">
					<T id={catalog.error.message || "error.unknown"} /> <T id="crowdsec.attackers.refresh-help" />
				</Alert>
			)}
			{catalog.isFetching && data && (
				<p role="status" className="small text-secondary">
					<T id="crowdsec.attackers.loading" />
				</p>
			)}
			{!data ? (
				catalog.isPending && <TableSkeleton />
			) : (
				<>
					<div className="border-top border-bottom py-3 my-3" aria-live="polite">
						<strong>
							<T id="crowdsec.attackers.count" data={{ count: data.matched }} />
						</strong>{" "}
						· <T id="crowdsec.attackers.scanned" data={{ count: data.scanned }} />
						<div className="small text-secondary mt-1">
							<T id={data.complete ? "crowdsec.attackers.complete" : "crowdsec.attackers.partial"} />
						</div>
						<div className="small text-secondary">
							<T id="crowdsec.attackers.window" />: {formatDateTime(data.start)} —{" "}
							{formatDateTime(data.end)}
						</div>
					</div>
					<div className="table-responsive">
						<table className={`table table-vcenter ${styles.table}`}>
							<thead>
								<tr>
									<th>
										<T id="crowdsec.source" />
									</th>
									<th className="d-none d-md-table-cell">
										<T id="crowdsec.attackers.targets" />
									</th>
									<th>
										<T id="crowdsec.attackers.alerts" />
									</th>
									<th className="d-none d-md-table-cell">
										<T id="crowdsec.attackers.first" />
									</th>
									<th className="d-none d-md-table-cell">
										<T id="crowdsec.attackers.last" />
									</th>
								</tr>
							</thead>
							<tbody>
								{data.items.map((row) => (
									<tr key={row.ip}>
										<td>
											<button
												type="button"
												className={`btn btn-link p-0 ${styles.ip}`}
												onClick={() => setSelected(row.ip)}
											>
												{row.ip}
											</button>
											<div className="small text-secondary text-break">
												{row.country || "—"} ·{" "}
												{row.asName || (row.asNumber ? `AS${row.asNumber}` : "—")}
											</div>
											<div
												className="small"
												title={intl.formatMessage({ id: "crowdsec.attackers.ban-help" })}
											>
												<T id={`crowdsec.attackers.${banStatus(row.ip)}`} />
											</div>
											<div className="small text-secondary">
												{row.scenarios.slice(0, 2).map(scenarioLabel).join(", ")}
											</div>
											<div className="small text-secondary d-md-none mt-1">
												<T id="crowdsec.attackers.last" />: {formatDateTime(row.lastSeen)}
											</div>
										</td>
										<td className="d-none d-md-table-cell text-break">
											{row.targets.slice(0, 2).join(", ") || "—"}
											{row.targets.length > 2 && ` +${row.targets.length - 2}`}
										</td>
										<td>
											{row.alerts}
											<div className="small text-secondary">
												<T id="crowdsec.attackers.alert-events" data={{ count: row.events }} />
											</div>
										</td>
										<td className="d-none d-md-table-cell">{formatDateTime(row.firstSeen)}</td>
										<td className="d-none d-md-table-cell">{formatDateTime(row.lastSeen)}</td>
									</tr>
								))}
								{!data.items.length && (
									<tr>
										<td colSpan={5} className="py-5 text-center text-secondary">
											<T id="crowdsec.attackers.empty" />
										</td>
									</tr>
								)}
							</tbody>
						</table>
					</div>
					<div className="d-flex flex-wrap align-items-center justify-content-between gap-2 mt-3">
						<div className="d-flex gap-2 align-items-center">
							<button
								type="button"
								className="btn btn-sm"
								disabled={params.page === 1 || catalog.isFetching}
								onClick={() => update({ page: params.page - 1 })}
							>
								<T id="crowdsec.previous" />
							</button>
							<T id="crowdsec.history.page" data={{ page: data.page }} />
							<button
								type="button"
								className="btn btn-sm"
								disabled={!data.hasNext || catalog.isFetching}
								onClick={() => update({ page: params.page + 1 })}
							>
								<T id="crowdsec.next" />
							</button>
						</div>
						{!data.complete && !data.truncated && (
							<button
								type="button"
								className="btn btn-outline-primary"
								disabled={catalog.isFetching}
								onClick={() => update({ advance: data.revision, page: 1 })}
							>
								<T id="crowdsec.attackers.older" />
							</button>
						)}
					</div>
					{data.truncated && (
						<Alert variant="info" className="mt-3">
							<T id="crowdsec.attackers.limit" />
						</Alert>
					)}
				</>
			)}
			{selected && (
				<Timeline key={selected} ip={selected} windowHours={windowHours} onClose={() => setSelected(null)} />
			)}
		</section>
	);
};
export default Attackers;
