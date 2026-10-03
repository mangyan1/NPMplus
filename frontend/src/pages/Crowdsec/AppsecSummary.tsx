import { IconChevronRight, IconShieldCheck } from "@tabler/icons-react";
import type { useCrowdsecMetrics } from "src/hooks";
import { intl, T } from "src/locale";
import styles from "./Dashboard.module.css";
import { appsecStatus, appsecTrafficAvailable } from "./shared";

// compact AppSec verdict on the overview: how many requests were inspected,
// how many were blocked, and a pass/blocked traffic bar. answers "is the WAF
// really blocking or just watching" without a tab switch
const AppsecSummary = ({ metrics, onOpen }: { metrics: ReturnType<typeof useCrowdsecMetrics>; onOpen: () => void }) => {
	const data = metrics.data;
	if (!data)
		return (
			<div className="text-secondary small py-5 text-center">
				<T id={metrics.isError ? "crowdsec.metrics-unavailable" : "crowdsec.appsec.status-checking"} />
			</div>
		);
	const status = appsecStatus(data, metrics.isRefetchError);
	const trafficAvailable = appsecTrafficAvailable(data);
	const requests = data.appsecRequests ?? 0;
	const blocked = data.appsecBlocked ?? 0;
	const passed = data.appsecPassed ?? Math.max(0, requests - blocked);
	const blockRate = data.appsecBlockRate ?? (requests > 0 ? blocked / requests : null);
	const blockedWidth = blockRate === null ? 0 : Math.min(100, Math.max(0, blockRate * 100));
	const passedWidth = requests > 0 ? 100 - blockedWidth : 0;
	const summary = trafficAvailable
		? intl.formatMessage({ id: "crowdsec.appsec.traffic-summary" }, { requests, blocked, passed })
		: intl.formatMessage({ id: "crowdsec.metrics-unavailable" });
	return (
		<button type="button" className={`${styles.wafSummary} ${styles.metricCard} w-100 text-start`} onClick={onOpen}>
			<div className={styles.wafIdentity}>
				<span className={`bg-${status.tone}-lt ${styles.metricIcon}`} aria-hidden="true">
					<IconShieldCheck size={22} />
				</span>
				<div>
					<div className={styles.serviceName}>
						<T id="crowdsec.overview.waf" />
					</div>
					<div className="text-secondary small mt-1">
						{data.appsecConfigured === false ? (
							<T id="crowdsec.appsec.status-disabled" />
						) : (
							<T id={status.label} />
						)}
					</div>
				</div>
			</div>
			<div>
				<div className={styles.metricValue}>{trafficAvailable ? intl.formatNumber(blocked) : "—"}</div>
				<div className="small">
					<T id="crowdsec.appsec.blocked" />
				</div>
				<div className="text-secondary small">
					<T id="crowdsec.appsec.since-restart" />
				</div>
			</div>
			<div className={styles.wafBreakdown}>
				<div className={`${styles.wafTraffic} mt-3`} role="img" aria-label={summary}>
					{trafficAvailable && requests > 0 ? (
						<>
							<span className={styles.wafPassed} style={{ width: `${passedWidth}%` }} />
							<span className={styles.wafBlocked} style={{ width: `${blockedWidth}%` }} />
						</>
					) : (
						<span className={styles.wafEmpty} />
					)}
				</div>
				<div className="d-flex flex-wrap gap-3 mt-2 small">
					<span className={styles.wafLegendItem}>
						<span className={`${styles.wafLegendDot} bg-green`} aria-hidden="true" />
						<T id="crowdsec.appsec.passed" />: {trafficAvailable ? intl.formatNumber(passed) : "—"}
					</span>
					<span className={styles.wafLegendItem}>
						<span className={`${styles.wafLegendDot} bg-red`} aria-hidden="true" />
						<T id="crowdsec.appsec.blocked" />: {trafficAvailable ? intl.formatNumber(blocked) : "—"}
					</span>
				</div>
				<p className="text-secondary small mb-0 mt-2">
					<T id="crowdsec.overview.waf-hint" />
				</p>
			</div>
			<span className={styles.sectionLink}>
				<T id="crowdsec.overview.waf-details" />
				<IconChevronRight size={16} aria-hidden="true" />
			</span>
		</button>
	);
};

export default AppsecSummary;
