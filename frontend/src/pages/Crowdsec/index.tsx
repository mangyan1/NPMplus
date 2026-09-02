import { IconChevronDown, IconChevronRight, IconRefresh, IconSearch, IconTrash } from "@tabler/icons-react";
import { Fragment, useState } from "react";
import Alert from "react-bootstrap/Alert";
import type { CrowdsecAlert, CrowdsecDecision } from "src/api/backend";
import { Button, HasPermission } from "src/components";
import { useLocaleState } from "src/context";
import { useCrowdsecAlerts, useCrowdsecDecisions, useUnbanCrowdsecDecision } from "src/hooks";
import { formatDateTime, T } from "src/locale";
import { showDeleteConfirmModal } from "src/modals";
import { ADMIN, VIEW } from "src/modules/Permissions";
import AnimatedLogo from "./AnimatedLogo";

// newest decision first, so the top of the table is always the latest ban
const byNewest = (a: CrowdsecDecision, b: CrowdsecDecision) => (b?.id ?? 0) - (a?.id ?? 0);

const decisionTarget = (decision: CrowdsecDecision) =>
	decision.scope === "Ip" || !decision.scope ? decision.value : `${decision.scope}: ${decision.value ?? ""}`;

// the scope+value pair is what unban and the alert context address
const decisionKey = (decision: CrowdsecDecision) => `${decision.scope || "Ip"}:${decision.value ?? ""}`;

// "3d 4h" / "2h 05m" / "45s" time left on the ban, null when not computable
const expiresIn = (until?: string) => {
	const ms = new Date(until ?? 0).getTime() - Date.now();
	if (!Number.isFinite(ms) || ms <= 0) {
		return null;
	}
	const s = Math.floor(ms / 1000);
	const days = Math.floor(s / 86400);
	const hours = Math.floor((s % 86400) / 3600);
	const minutes = Math.floor((s % 3600) / 60);
	if (days > 0) return `${days}d ${hours}h`;
	if (hours > 0) return `${hours}h ${minutes}m`;
	if (minutes > 0) return `${minutes}m`;
	return `${s}s`;
};

// the alert(s) that produced a ban, shown when a row is expanded
const AlertContext = ({ decision }: { decision: CrowdsecDecision }) => {
	const { locale } = useLocaleState();
	const { isFetching, isError, error, data } = useCrowdsecAlerts(decision.scope || "Ip", decision.value, true);

	if (isFetching) {
		return <div className="text-secondary small py-2">…</div>;
	}
	if (isError) {
		return (
			<div className="text-secondary small py-2">
				<T id={error?.message || "error.unknown"} />
			</div>
		);
	}
	if (!data || data.length === 0) {
		return (
			<div className="text-secondary small py-2">
				<T id="crowdsec.no-alerts" />
			</div>
		);
	}
	return (
		<div className="py-2">
			{data.map((alert: CrowdsecAlert) => (
				<div key={alert.id} className="mb-2">
					<div>
						<span className="badge bg-cyan me-2">{alert.scenario}</span>
						{alert.message}
					</div>
					<div className="text-secondary small">
						{alert.startedAt ? formatDateTime(alert.startedAt, locale) : null}
						{alert.eventsCount ? (
							<>
								&nbsp;· <T id="crowdsec.events-count" data={{ count: alert.eventsCount }} />
							</>
						) : null}
					</div>
				</div>
			))}
		</div>
	);
};

const Content = () => {
	const { isFetching, isError, error, data, refetch } = useCrowdsecDecisions();
	const unban = useUnbanCrowdsecDecision();
	const [search, setSearch] = useState("");
	const [expanded, setExpanded] = useState<string | null>(null);

	const decisions = [...(data ?? [])].sort(byNewest);
	const needle = search.trim().toLowerCase();
	const filtered = needle
		? decisions.filter((decision) =>
				[decision.value, decision.scenario, decision.origin, decision.type]
					.filter(Boolean)
					.some((field) => (field as string).toLowerCase().includes(needle)),
			)
		: decisions;

	if (isError) {
		return (
			<Alert variant="danger">
				<T id={error?.message || "error.unknown"} />
			</Alert>
		);
	}

	if (!data) {
		return (
			<div className="py-5 d-flex justify-content-center">
				<AnimatedLogo />
			</div>
		);
	}

	const confirmUnban = (decision: CrowdsecDecision) => {
		const scope = decision.scope || "Ip";
		const value = decision.value ?? "";
		showDeleteConfirmModal({
			title: <T id="crowdsec.unban-title" data={{ target: decisionTarget(decision) }} />,
			children: <T id="crowdsec.unban-content" />,
			subject: decisionTarget(decision),
			onConfirm: async () => {
				await unban.mutateAsync({ scope, value });
			},
		});
	};

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-red" />
			<div className="card-header">
				<div className="row w-full">
					<div className="col">
						<h2 className="mt-1 mb-0 d-flex align-items-center gap-2">
							<AnimatedLogo />
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
							{decisions.length > 0 && (
								<div className="input-group input-group-flat w-auto">
									<span className="input-group-text input-group-text-sm">
										<IconSearch size={16} />
									</span>
									<input
										type="text"
										className="form-control form-control-sm"
										autoComplete="off"
										onChange={(e) => setSearch(e.target.value)}
									/>
								</div>
							)}
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
						{/* the backend caps one poll at 200 decisions; the list length is the cap signal */}
						{decisions.length >= 200 && (
							<div className="text-secondary small py-2">
								<T id="crowdsec.capped" data={{ count: decisions.length }} />
							</div>
						)}
						<table className="table card-table table-vh table-striped">
							<thead>
								<tr>
									<th>&nbsp;</th>
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
									<th>&nbsp;</th>
								</tr>
							</thead>
							<tbody>
								{filtered.map((decision) => {
									const key = decisionKey(decision);
									const remaining = expiresIn(decision.until);
									const isOpen = expanded === key;
									return (
										<Fragment key={key}>
											<tr>
												<td className="w-1">
													<button
														type="button"
														className="btn btn-sm btn-ghost-secondary"
														onClick={() => setExpanded(isOpen ? null : key)}
													>
														{isOpen ? (
															<IconChevronDown size={16} />
														) : (
															<IconChevronRight size={16} />
														)}
													</button>
												</td>
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
												<td title={decision.until ?? decision.duration}>
													{decision.until && remaining === null ? (
														<T id="crowdsec.expired" />
													) : remaining !== null ? (
														<T id="crowdsec.expires-in" data={{ duration: remaining }} />
													) : (
														(decision.until ?? decision.duration)
													)}
												</td>
												<td className="text-end">
													<Button
														size="sm"
														actionType="danger"
														onClick={() => confirmUnban(decision)}
													>
														<IconTrash size={16} />
														<T id="crowdsec.unban" />
													</Button>
												</td>
											</tr>
											{isOpen && (
												<tr>
													<td colSpan={7} className="bg-light">
														<AlertContext decision={decision} />
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
