import { IconGavel, IconRefresh } from "@tabler/icons-react";
import Alert from "react-bootstrap/Alert";
import type { CrowdsecDecision } from "src/api/backend";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useCrowdsecDecisions } from "src/hooks";
import { T } from "src/locale";
import { ADMIN, VIEW } from "src/modules/Permissions";

// newest decision first, so the top of the table is always the latest ban
const byNewest = (a: CrowdsecDecision, b: CrowdsecDecision) => (b?.id ?? 0) - (a?.id ?? 0);

const decisionTarget = (decision: CrowdsecDecision) =>
	decision.scope === "Ip" || !decision.scope ? decision.value : `${decision.scope}: ${decision.value ?? ""}`;

const Content = () => {
	const { isFetching, isError, error, data, refetch } = useCrowdsecDecisions();
	const decisions = [...(data ?? [])].sort(byNewest);

	if (isError) {
		return (
			<Alert variant="danger">
				<T id={error?.message || "error.unknown"} />
			</Alert>
		);
	}

	if (!data) {
		return <LoadingPage />;
	}

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-red" />
			<div className="card-header">
				<div className="row w-full">
					<div className="col">
						<h2 className="mt-1 mb-0 d-flex align-items-center gap-2">
							<IconGavel size={24} />
							<T id="crowdsec.title" />
							{decisions.length > 0 && (
								<span className="badge bg-red">
									<T id="crowdsec.active-count" data={{ count: decisions.length }} />
								</span>
							)}
						</h2>
					</div>
					<div className="col-md-auto col-sm-12">
						<div className="ms-auto d-flex flex-wrap btn-list">
							<span className="text-secondary small me-2 my-auto">
								<T id="crowdsec.live" />
							</span>
							<Button
								actionType="secondary"
								variant="outline"
								isLoading={isFetching}
								onClick={() => refetch()}
							>
								<IconRefresh size={16} className="me-1" />
								<T id="crowdsec.refresh" />
							</Button>
						</div>
					</div>
				</div>
			</div>
			<div className="card-body py-0">
				{decisions.length === 0 ? (
					<div className="py-5 text-center text-secondary">
						<T id="crowdsec.empty" />
					</div>
				) : (
					<div className="table-responsive">
						<table className="table card-table table-vh table-striped">
							<thead>
								<tr>
									<th>
										<T id="crowdsec.target" />
									</th>
									<th>
										<T id="crowdsec.reason" />
									</th>
									<th>
										<T id="crowdsec.origin" />
									</th>
									<th>
										<T id="crowdsec.action" />
									</th>
									<th>
										<T id="crowdsec.expires" />
									</th>
								</tr>
							</thead>
							<tbody>
								{decisions.map((decision) => (
									<tr key={decision.uuid || decision.id}>
										<td>{decisionTarget(decision)}</td>
										<td>
											{decision.scenario === "anubis-honeypot" ? (
												<span className="badge bg-orange">
													<T id="crowdsec.honeypot" />
												</span>
											) : (
												decision.scenario
											)}
										</td>
										<td>{decision.origin}</td>
										<td>
											{decision.type}
											{decision.simulated ? (
												<>
													{" "}
													<span className="badge bg-yellow">
														<T id="crowdsec.simulated" />
													</span>
												</>
											) : null}
										</td>
										<td>{decision.until ?? decision.duration}</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</div>
		</div>
	);
};

const Crowdsec = () => (
	<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
		<Content />
	</HasPermission>
);

export default Crowdsec;
