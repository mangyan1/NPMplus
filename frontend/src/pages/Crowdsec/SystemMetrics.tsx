import Alert from "react-bootstrap/Alert";
import type { useCrowdsecMetrics } from "src/hooks";
import { T } from "src/locale";
import { MetricsSkeleton } from "./LoadingSkeleton";
import Metric from "./Metric";

const SystemMetrics = ({ metrics }: { metrics: ReturnType<typeof useCrowdsecMetrics> }) =>
	!metrics.data ? (
		metrics.isError ? (
			<Alert variant="secondary">
				<T id="crowdsec.metrics-unavailable" />
			</Alert>
		) : (
			<MetricsSkeleton />
		)
	) : !metrics.data.available ? (
		<Alert variant="secondary">
			<T id={metrics.data.error || "crowdsec.metrics-unavailable"} />
		</Alert>
	) : (
		<>
			<h3>
				<T id="crowdsec.metrics.title" />
			</h3>
			<p className="text-secondary">
				<T id="crowdsec.metrics.since-restart" />
			</p>
			<div className="row g-3">
				<Metric
					label={<T id="crowdsec.metrics.bouncer-requests" />}
					value={metrics.data.bouncerRequests ?? "—"}
					tone="green"
				/>
				<Metric
					label={<T id="crowdsec.metrics.machine-requests" />}
					value={metrics.data.machineRequests ?? "—"}
					tone="orange"
				/>
				<Metric
					label={
						<T
							id={
								metrics.data.parserMetricScope === "nodes"
									? "crowdsec.metrics.parser-node-rate"
									: "crowdsec.metrics.parser-rate"
							}
						/>
					}
					value={
						metrics.data.parserSuccessRate === null || typeof metrics.data.parserSuccessRate === "undefined"
							? "—"
							: `${(metrics.data.parserSuccessRate * 100).toFixed(1)}%`
					}
					description={
						metrics.data.parserSuccessRate === null ||
						typeof metrics.data.parserSuccessRate === "undefined" ? (
							<T id="crowdsec.metrics.parser-unavailable" />
						) : undefined
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
				<Metric
					label={<T id="crowdsec.metrics.whitelist-hits" />}
					value={metrics.data.whitelistHits ?? "—"}
					description={<T id="crowdsec.metrics.whitelist-hits-help" />}
				/>
			</div>
		</>
	);

export default SystemMetrics;
