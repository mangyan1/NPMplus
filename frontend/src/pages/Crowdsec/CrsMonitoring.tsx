import Alert from "react-bootstrap/Alert";
import type { CrowdsecMetrics } from "src/api/backend";
import { intl, T } from "src/locale";
import CrsControl from "./CrsControl";
import { crsStatus } from "./shared";

const CrsMonitoring = ({ data, stale }: { data: CrowdsecMetrics; stale: boolean }) => {
	const status = crsStatus(data, stale);
	const reported = data.available && !stale && data.appsecConfigured !== false;
	return (
		<section className="card" aria-labelledby="crs-monitor-title">
			<div className="card-body">
				<div className="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-2">
					<h3 id="crs-monitor-title" className="mb-0">
						<T id="crowdsec.crs.title" />
					</h3>
					<span className={`badge bg-${status.tone}-lt`}>
						<T id={status.label} />
					</span>
				</div>
				<p className="text-secondary">
					<T id="crowdsec.crs.description" />
				</p>
				<CrsControl configured={!stale && data.crsInstallerMode === "observe"} />
				{data.crsInstallerMode === "observe" && (
					<p className="text-secondary">
						<T id="crowdsec.crs.configured-help" />
					</p>
				)}
				{reported && (data.crsInbandHits ?? 0) > 0 && (
					<Alert variant="warning">
						<T id="crowdsec.crs.inband-warning" />
					</Alert>
				)}
				<div className="d-flex flex-wrap align-items-baseline gap-2 mb-2">
					<strong className="h2 mb-0">
						{reported && typeof data.crsObservationHits === "number"
							? intl.formatNumber(data.crsObservationHits)
							: "—"}
					</strong>
					<span>
						<T id="crowdsec.crs.matches" />
					</span>
					<span className="text-secondary small">
						<T id="crowdsec.appsec.since-restart" />
					</span>
				</div>
				<p className="text-secondary small">
					<T id="crowdsec.crs.matches-help" />
				</p>
				{reported && data.crsRules?.length ? (
					<div className="list-group list-group-flush">
						{data.crsRules.map((rule) => (
							<div
								key={rule.name}
								className="list-group-item px-0 d-flex justify-content-between align-items-start gap-2"
							>
								<div className="text-break">
									<strong>
										<T
											id={`crowdsec.crs.family-${["930", "931", "932", "933", "941", "942"].includes(rule.name.slice(0, 3)) ? rule.name.slice(0, 3) : "other"}`}
										/>
									</strong>
									<div className="text-secondary small">
										<T id="crowdsec.crs.rule" /> <code>{rule.name}</code>
									</div>
								</div>
								<span className="badge bg-orange-lt flex-shrink-0">
									{intl.formatNumber(rule.count)}
								</span>
							</div>
						))}
					</div>
				) : (
					<p className="text-secondary mb-0">
						<T id={reported ? "crowdsec.crs.empty" : "crowdsec.metrics-unavailable"} />
					</p>
				)}
			</div>
		</section>
	);
};

export default CrsMonitoring;
