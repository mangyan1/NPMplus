import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { getSecurityTelemetry } from "src/api/backend/getSecurityTelemetry";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { MetricsSkeleton } from "./LoadingSkeleton";
import Metric from "./Metric";

const EnforcementTelemetry = ({ windowHours, mode }: { windowHours: number; mode: "waf" | "enforcement" }) => {
	const { locale } = useLocaleState();
	const [hostId, setHostId] = useState("");
	const query = useQuery({
		queryKey: ["security-telemetry", windowHours],
		queryFn: ({ signal }) => getSecurityTelemetry(windowHours, signal),
		refetchInterval: 60_000,
		retry: false,
	});
	if (!query.data)
		return query.isError ? (
			<Alert variant="secondary">
				<T id="crowdsec.telemetry.unavailable" />
			</Alert>
		) : (
			<MetricsSkeleton />
		);
	const { nginx, firewall } = query.data;
	const host = nginx.hosts.find((item) => String(item.id) === hostId);
	const counters = hostId ? host?.counters : nginx.totals;
	const observed = nginx.coveredMs > 0;
	const value = (number?: number) => (observed && number !== undefined ? intl.formatNumber(number) : "—");
	const status = (layer: typeof nginx | typeof firewall) => (query.isError ? "stale" : layer.status);
	return (
		<section className="mb-4" aria-labelledby={`telemetry-${mode}`}>
			<h3 id={`telemetry-${mode}`}>
				<T id={`crowdsec.telemetry.${mode}`} />
			</h3>
			<p className="text-secondary small">
				<T
					id="crowdsec.telemetry.window"
					data={{
						start: formatDateTime(query.data.start, locale),
						end: formatDateTime(query.data.end, locale),
					}}
				/>
			</p>
			{(nginx.incomplete || (mode === "enforcement" && firewall.incomplete)) && (
				<Alert variant="info">
					<T id="crowdsec.telemetry.partial" />
				</Alert>
			)}
			{query.isError && (
				<Alert variant="warning">
					<T id="crowdsec.stale" />
				</Alert>
			)}
			{mode === "waf" ? (
				<>
					<label className="form-label" htmlFor="telemetry-host">
						<T id="crowdsec.telemetry.host" />
					</label>
					<select
						id="telemetry-host"
						className="form-select mb-3"
						value={hostId}
						onChange={(event) => setHostId(event.target.value)}
					>
						<option value="">{intl.formatMessage({ id: "crowdsec.telemetry.all-hosts" })}</option>
						{hostId && !host && <option value={hostId}>#{hostId}</option>}
						{nginx.hosts.map((item) => (
							<option key={item.id} value={String(item.id)}>
								{item.domains.join(", ") || `#${item.id}`}
							</option>
						))}
					</select>
					<div className="row g-3">
						<Metric label={<T id="crowdsec.telemetry.inspected" />} value={value(counters?.inspected)} />
						<Metric
							label={<T id="crowdsec.telemetry.waf-bans" />}
							value={value(counters?.wafBans)}
							tone="red"
						/>
						<Metric
							label={<T id="crowdsec.telemetry.errors" />}
							value={value(counters?.errors)}
							tone="orange"
						/>
						<Metric label={<T id="crowdsec.telemetry.unreadable" />} value={value(counters?.unreadable)} />
					</div>
					<p className="text-secondary small mt-3">
						<T id="crowdsec.telemetry.waf-help" />
					</p>
					{nginx.hostsTruncated && (
						<Alert variant="info">
							<T id="crowdsec.telemetry.host-limit" />
						</Alert>
					)}
				</>
			) : (
				<>
					<div className="row g-3">
						<Metric
							label={<T id="crowdsec.telemetry.http-bans" />}
							value={value(nginx.totals.bans)}
							tone="red"
						/>
						<Metric
							label={<T id="crowdsec.telemetry.challenges" />}
							value={value(nginx.totals.challenges)}
						/>
						<Metric
							label={<T id="crowdsec.telemetry.input" />}
							value={firewall.coveredMs ? intl.formatNumber(firewall.totals.inputPackets) : "—"}
						/>
						<Metric
							label={<T id="crowdsec.telemetry.forward" />}
							value={firewall.coveredMs ? intl.formatNumber(firewall.totals.forwardPackets) : "—"}
						/>
					</div>
					<p className="text-secondary small mt-3">
						<T id="crowdsec.telemetry.layers-help" />
					</p>
					<p>
						<T id="crowdsec.telemetry.firewall-rules" />:{" "}
						<T
							id={
								status(firewall) !== "observed"
									? "crowdsec.telemetry.unknown"
									: firewall.serviceActive && firewall.inputRule && firewall.forwardRule
										? "crowdsec.telemetry.rules-present"
										: "crowdsec.telemetry.rules-missing"
							}
						/>
					</p>
				</>
			)}
			<div className="text-secondary small">
				<T id="crowdsec.telemetry.nginx" />: <T id={`crowdsec.telemetry.${status(nginx)}`} />
				{nginx.observedAt && ` (${formatDateTime(nginx.observedAt, locale)})`}
				{mode === "enforcement" && (
					<>
						<br />
						<T id="crowdsec.telemetry.firewall" />: <T id={`crowdsec.telemetry.${status(firewall)}`} />
						{firewall.observedAt && ` (${formatDateTime(firewall.observedAt, locale)})`}
					</>
				)}
			</div>
		</section>
	);
};
export default EnforcementTelemetry;
