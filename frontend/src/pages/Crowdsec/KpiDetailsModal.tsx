import type { ReactNode } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import type { AnubisStatus, CrowdsecInsights, CrowdsecInsightsItem, CrowdsecMetrics } from "src/api/backend";
import { Button } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import styles from "./Dashboard.module.css";
import { midTruncate, scenarioLabel } from "./scenarios";
import type { DashboardTab, KpiKind } from "./shared";
import { anubisServiceStatus, honeypotStatus } from "./shared";

const ItemList = ({
	title,
	items,
	renderName,
	onSelect,
}: {
	title: ReactNode;
	items: CrowdsecInsightsItem[];
	renderName?: (name: string) => ReactNode;
	onSelect?: (name: string) => void;
}) => (
	<div className="col-md-6">
		<h4>{title}</h4>
		{items.length ? (
			<div className="list-group list-group-flush">
				{items.map((item) => (
					<div key={item.name} className="list-group-item px-0 d-flex justify-content-between gap-2">
						{onSelect ? (
							<button type="button" className={styles.donutName} onClick={() => onSelect(item.name)}>
								{renderName ? renderName(item.name) : item.name}
							</button>
						) : (
							<span className="text-break">{renderName ? renderName(item.name) : item.name}</span>
						)}
						<span className="badge bg-secondary-lt flex-shrink-0">{item.count}</span>
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
	onFilterScenario,
}: {
	kind: KpiKind | null;
	insights?: CrowdsecInsights;
	metrics?: CrowdsecMetrics;
	anubis?: AnubisStatus;
	onClose: () => void;
	onNavigate: (tab: DashboardTab) => void;
	onFilterScenario: (scenario: string) => void;
}) => {
	const titles: Record<KpiKind, string> = {
		attacks: "crowdsec.kpi.attacks",
		local: "crowdsec.kpi.local",
		community: "crowdsec.kpi.community",
		anubis: "crowdsec.kpi.honeypot",
	};
	const serviceStatus = anubisServiceStatus(anubis);
	const trapStatus = honeypotStatus(anubis);
	const { locale } = useLocaleState();
	const navigate = (tab: DashboardTab) => {
		onClose();
		onNavigate(tab);
	};
	const filterScenario = (scenario: string) => {
		onClose();
		onFilterScenario(scenario);
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
							{typeof insights?.alertCount === "number"
								? `${intl.formatNumber(insights.alertCount)}${insights.sampled ? "+" : ""}`
								: "—"}{" "}
							<span className="text-secondary fs-5">
								<T id="crowdsec.insights.alert-count" />
							</span>
						</div>
						<div className="row g-4">
							<ItemList
								title={<T id="crowdsec.insights.scenarios" />}
								items={insights?.topScenarios ?? []}
								// readable label, exact ID on hover, click narrows the
								// activity tab to that scenario
								renderName={(name) => (
									<span title={name}>
										{scenarioLabel(name)}
										{name !== scenarioLabel(name) && (
											<span className="text-secondary small ms-1">({midTruncate(name, 28)})</span>
										)}
									</span>
								)}
								onSelect={filterScenario}
							/>
							<ItemList
								title={<T id="crowdsec.insights.countries" />}
								items={insights?.topCountries ?? []}
							/>
							<ItemList title={<T id="crowdsec.insights.asns" />} items={insights?.topAsns ?? []} />
							<ItemList title={<T id="crowdsec.insights.ips" />} items={insights?.topIps ?? []} />
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
							{typeof (insights?.localActiveDecisions ?? metrics?.localActiveDecisions) === "number"
								? intl.formatNumber(
										(insights?.localActiveDecisions ?? metrics?.localActiveDecisions) as number,
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
						<div className="d-flex flex-wrap gap-2 mb-3">
							<span className={`badge bg-${serviceStatus.tone}-lt`}>
								<T id={serviceStatus.label} />
							</span>
							<span className={`badge bg-${trapStatus.tone}-lt`}>
								<T id={trapStatus.label} />
							</span>
						</div>
						<p className="text-secondary">
							<T id="crowdsec.anubis.honeypot-help" />
						</p>
						{typeof anubis?.honeypot.activeCount === "number" ? (
							<div className="h2">
								<T id="crowdsec.anubis.active" data={{ count: anubis.honeypot.activeCount }} />
							</div>
						) : (
							<Alert variant="warning">
								<T id="crowdsec.anubis.decisions-unavailable" />
							</Alert>
						)}
						<h4>
							<T id="crowdsec.anubis.bans" />
						</h4>
						{anubis?.honeypot.items.length ? (
							<div className="table-responsive">
								<table className="table table-sm align-middle mb-0">
									<thead>
										<tr>
											<th>
												<T id="crowdsec.source" />
											</th>
											<th>
												<T id="crowdsec.reason" />
											</th>
											<th>
												<T id="crowdsec.expires" />
											</th>
										</tr>
									</thead>
									<tbody>
										{anubis.honeypot.items.map((item) => (
											<tr key={item.id}>
												<td className="text-break">{item.value}</td>
												<td title={item.scenario}>{scenarioLabel(item.scenario)}</td>
												<td className="text-nowrap">
													{item.until ? formatDateTime(item.until, locale) : item.duration}
												</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						) : (
							<div className="text-secondary">
								<T id="crowdsec.anubis.empty" />
							</div>
						)}
						<h4 className="mt-4">
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

export default KpiDetailsModal;
