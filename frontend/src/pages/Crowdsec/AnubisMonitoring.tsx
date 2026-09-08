import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { getAnubisReport } from "src/api/backend/getAnubisReport";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { MetricsSkeleton } from "./LoadingSkeleton";

const Pages = ({ page, total, change }: { page: number; total: number; change: (page: number) => void }) => (
	<div className="d-flex flex-wrap align-items-center gap-2 my-2">
		<button
			type="button"
			className="btn btn-sm btn-outline-secondary"
			disabled={page === 1}
			onClick={() => change(page - 1)}
		>
			<T id="crowdsec.anubis-report.previous" />
		</button>
		<span className="small">
			<T id="crowdsec.anubis-report.page" data={{ page, total }} />
		</span>
		<button
			type="button"
			className="btn btn-sm btn-outline-secondary"
			disabled={page * 25 >= total}
			onClick={() => change(page + 1)}
		>
			<T id="crowdsec.anubis-report.next" />
		</button>
	</div>
);
const AnubisMonitoring = () => {
	const { locale } = useLocaleState();
	const [hours, setHours] = useState(24);
	const [page, setPage] = useState(1);
	const [hostPage, setHostPage] = useState(1);
	const query = useQuery({
		queryKey: ["anubis-report", hours, page, hostPage],
		queryFn: ({ signal }) => getAnubisReport(hours, page, hostPage, signal),
		refetchInterval: 60_000,
		retry: false,
	});
	if (!query.data)
		return query.isError ? (
			<Alert variant="warning">
				<T id="crowdsec.anubis-report.unavailable" />
				<button
					type="button"
					className="btn btn-sm btn-outline-secondary ms-2"
					onClick={() => void query.refetch()}
				>
					<T id="crowdsec.anubis-report.retry" />
				</button>
			</Alert>
		) : (
			<MetricsSkeleton />
		);
	const { metrics, ledger, coverage } = query.data;
	return (
		<section className="border-top pt-3 mb-4" aria-labelledby="anubis-outcomes">
			<h3 id="anubis-outcomes">
				<T id="crowdsec.anubis-report.title" />
			</h3>
			<label className="form-label" htmlFor="anubis-window">
				<T id="crowdsec.anubis-report.window" />
			</label>
			<select
				className="form-select mb-3"
				id="anubis-window"
				value={hours}
				onChange={(event) => {
					setHours(Number(event.target.value));
					setPage(1);
				}}
			>
				{[1, 6, 24, 168].map((value) => (
					<option key={value} value={value}>
						{value === 168 ? "7d" : `${value}h`}
					</option>
				))}
			</select>
			{query.isError && (
				<Alert variant="warning">
					<T id="crowdsec.anubis-report.refresh-failed" />
				</Alert>
			)}
			<p className="small text-secondary">
				<T id="crowdsec.anubis-report.metrics-help" />
			</p>
			<p className="small">
				<T id={`crowdsec.anubis-report.${metrics.status}`} />
				{metrics.observedAt && ` · ${formatDateTime(metrics.observedAt, locale)}`}
			</p>
			{metrics.partial && (
				<p className="small text-secondary">
					<T id="crowdsec.anubis-report.partial" />
				</p>
			)}
			<div className="row g-2 mb-3">
				{(["issued", "validated", "failed"] as const).map((key) => (
					<div key={key} className="col-sm-4">
						<div className="border rounded p-2">
							<div className="small">
								<T id={`crowdsec.anubis-report.${key}`} />
							</div>
							<strong className="fs-3">
								{metrics.totals[key] === null ? "—" : intl.formatNumber(metrics.totals[key])}
							</strong>
						</div>
					</div>
				))}
			</div>
			<p className="small text-secondary">
				{formatDateTime(metrics.start, locale)} – {formatDateTime(metrics.end, locale)}
			</p>
			<details className="border-top py-3">
				<summary className="fw-semibold">
					<T id="crowdsec.anubis-report.coverage" data={{ total: coverage.total }} />
				</summary>
				<p className="small text-secondary mt-2">
					<T id="crowdsec.anubis-report.coverage-help" />
				</p>
				{coverage.items.map((host) => (
					<div className="border-top py-2" key={host.id}>
						<div className="text-break fw-semibold">{host.domains.join(", ")}</div>
						<div className="small">
							<T
								id={host.anubis ? "crowdsec.anubis-report.root-on" : "crowdsec.anubis-report.root-off"}
							/>
							{host.customUpstream && (
								<>
									{" "}
									· <T id="crowdsec.anubis-report.custom" />
								</>
							)}
						</div>
						{host.locations.map((location, index) => (
							<div className="small text-break" key={`${location.path}-${index}`}>
								{location.path}:{" "}
								<T id={location.anubis ? "crowdsec.anubis-report.on" : "crowdsec.anubis-report.off"} />
								{location.customUpstream && (
									<>
										{" "}
										· <T id="crowdsec.anubis-report.custom" />
									</>
								)}
							</div>
						))}
						{host.locationsTruncated && (
							<p className="small">
								<T id="crowdsec.anubis-report.locations-limited" />
							</p>
						)}
					</div>
				))}
				<Pages page={hostPage} total={coverage.total} change={setHostPage} />
			</details>
			<details className="border-top py-3">
				<summary className="fw-semibold">
					<T id="crowdsec.anubis-report.history" />
				</summary>
				<p className="small text-secondary mt-2">
					<T id="crowdsec.anubis-report.history-help" />
				</p>
				<p className="small">
					<T id="crowdsec.anubis-report.address-collector" />:{" "}
					<T id={`crowdsec.anubis-report.${ledger.status}`} />
					{ledger.observedAt && ` · ${formatDateTime(ledger.observedAt, locale)}`}
				</p>
				<p className="small">
					<T id="crowdsec.anubis-report.attempt-collector" />:{" "}
					<T id={`crowdsec.anubis-report.${ledger.attemptsStatus}`} />
				</p>
				{(ledger.gap || ledger.pending) && (
					<Alert variant="warning">
						<T id="crowdsec.anubis-report.gap" />
					</Alert>
				)}
				{ledger.items.length ? (
					<div className="table-responsive">
						<table className="table table-sm">
							<thead>
								<tr>
									<th>
										<T id="crowdsec.anubis-report.time" />
									</th>
									<th>
										<T id="crowdsec.source" />
									</th>
									<th>
										<T id="crowdsec.anubis-report.event" />
									</th>
									<th>
										<T id="crowdsec.anubis-report.active" />
									</th>
								</tr>
							</thead>
							<tbody>
								{ledger.items.map((item) => (
									<tr key={item.id}>
										<td>{formatDateTime(item.time, locale)}</td>
										<td className="text-break" style={{ minWidth: "9rem" }}>
											{item.ip}
										</td>
										<td>
											<T id={`crowdsec.anubis-report.event-${item.kind}`} />
										</td>
										<td>
											<T
												id={
													item.activeBan === null
														? "crowdsec.anubis-report.unknown"
														: item.activeBan
															? "crowdsec.anubis-report.active-yes"
															: "crowdsec.anubis-report.active-no"
												}
											/>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				) : (
					<p className="small">
						<T id="crowdsec.anubis-report.empty" />
					</p>
				)}
				<Pages page={page} total={ledger.total} change={setPage} />
			</details>
		</section>
	);
};
export default AnubisMonitoring;
