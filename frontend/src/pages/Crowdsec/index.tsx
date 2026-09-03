import {
	IconChevronDown,
	IconChevronRight,
	IconChevronUp,
	IconRefresh,
	IconSearch,
	IconTrash,
} from "@tabler/icons-react";
import { Fragment, type ReactNode, useState } from "react";
import Alert from "react-bootstrap/Alert";
import type { CrowdsecAlert, CrowdsecDecision } from "src/api/backend";
import { Button, HasPermission } from "src/components";
import { useLocaleState } from "src/context";
import { useCrowdsecAlerts, useCrowdsecDecisions, useUnbanCrowdsecDecision } from "src/hooks";
import { formatDateTime, intl, T } from "src/locale";
import { showDeleteConfirmModal } from "src/modals";
import { ADMIN, VIEW } from "src/modules/Permissions";
import { showError } from "src/notifications";
import AnimatedLogo from "./AnimatedLogo";
import {
	type CrowdsecSortDirection,
	type CrowdsecSortKey,
	decisionTarget,
	filterCrowdsecDecisions,
	sortCrowdsecDecisions,
} from "./utils";

const AlertContext = ({ decision }: { decision: CrowdsecDecision }) => {
	const { locale } = useLocaleState();
	const { isFetching, isError, error, data } = useCrowdsecAlerts(decision.id, decision.scope, decision.value, true);

	if (isFetching && !data) return <div className="text-secondary small py-2">...</div>;
	if (isError && !data) {
		return (
			<div className="text-secondary small py-2">
				<T id={error?.message || "error.unknown"} />
			</div>
		);
	}
	if (!data?.length) {
		return (
			<div className="text-secondary small py-2">
				<T id="crowdsec.no-alerts" />
			</div>
		);
	}

	return (
		<div className="py-2">
			{isError && (
				<div className="text-warning small mb-2">
					<T id="crowdsec.stale" />
				</div>
			)}
			{data.map((alert: CrowdsecAlert) => (
				<div key={alert.id} className="mb-2">
					<div>
						<span className="badge bg-cyan me-2">{alert.scenario}</span>
						{alert.message}
					</div>
					<div className="text-secondary small">
						{alert.startAt ? formatDateTime(alert.startAt, locale) : null}
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

interface SortHeaderProps {
	label: ReactNode;
	column: CrowdsecSortKey;
	sortKey: CrowdsecSortKey;
	direction: CrowdsecSortDirection;
	onSort: (column: CrowdsecSortKey) => void;
}

const SortHeader = ({ label, column, sortKey, direction, onSort }: SortHeaderProps) => {
	const active = sortKey === column;
	const columnMessageId = {
		id: "crowdsec.title",
		origin: "crowdsec.origin",
		scenario: "crowdsec.reason",
		target: "crowdsec.target",
		type: "crowdsec.action",
	}[column];
	return (
		<th aria-sort={active ? (direction === "asc" ? "ascending" : "descending") : "none"}>
			<button
				type="button"
				className="btn btn-link p-0 text-reset text-decoration-none"
				onClick={() => onSort(column)}
				aria-label={intl.formatMessage(
					{ id: "crowdsec.sort-by" },
					{ column: intl.formatMessage({ id: columnMessageId }) },
				)}
			>
				{label}
				{active &&
					(direction === "asc" ? (
						<IconChevronUp size={14} className="ms-1" />
					) : (
						<IconChevronDown size={14} className="ms-1" />
					))}
			</button>
		</th>
	);
};

const Content = () => {
	const { locale } = useLocaleState();
	const { isFetching, isError, error, data, dataUpdatedAt, refetch } = useCrowdsecDecisions();
	const unban = useUnbanCrowdsecDecision();
	const [search, setSearch] = useState("");
	const [expanded, setExpanded] = useState<number | null>(null);
	const [sortKey, setSortKey] = useState<CrowdsecSortKey>("id");
	const [sortDirection, setSortDirection] = useState<CrowdsecSortDirection>("desc");

	const decisions = data?.items ?? [];
	const filtered = sortCrowdsecDecisions(filterCrowdsecDecisions(decisions, search), sortKey, sortDirection);

	if (isError && !data) {
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

	const onSort = (column: CrowdsecSortKey) => {
		if (column === sortKey) {
			setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
		} else {
			setSortKey(column);
			setSortDirection("asc");
		}
	};

	const confirmUnban = (decision: CrowdsecDecision) => {
		showDeleteConfirmModal({
			title: <T id="crowdsec.unban-title" data={{ target: decisionTarget(decision) }} />,
			children: <T id="crowdsec.unban-content" data={{ id: decision.id }} />,
			subject: decisionTarget(decision),
			details: (
				<T
					id="crowdsec.unban-details"
					data={{ origin: decision.origin, scenario: decision.scenario, type: decision.type }}
				/>
			),
			confirmLabel: <T id="crowdsec.unban" />,
			onConfirm: async () => {
				const result = await unban.mutateAsync(decision.id);
				if (!result.auditLogged) showError(intl.formatMessage({ id: "crowdsec.audit-warning" }));
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
									<label className="visually-hidden" htmlFor="crowdsec-search">
										<T id="crowdsec.search" />
									</label>
									<span className="input-group-text input-group-text-sm" aria-hidden="true">
										<IconSearch size={16} />
									</span>
									<input
										id="crowdsec-search"
										type="search"
										className="form-control form-control-sm"
										autoComplete="off"
										placeholder={intl.formatMessage({ id: "crowdsec.search" })}
										value={search}
										onChange={(event) => setSearch(event.target.value)}
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
				{isError && (
					<Alert variant="warning" className="mt-3 mb-0">
						<T id="crowdsec.stale" /> <T id={error?.message || "error.unknown"} />
					</Alert>
				)}
				<div className="text-secondary small py-2">
					<T
						id="crowdsec.last-updated"
						data={{ date: formatDateTime(new Date(dataUpdatedAt).toISOString(), locale) }}
					/>
				</div>
				{decisions.length === 0 ? (
					<div className="py-5 text-center text-secondary">
						<T id="crowdsec.empty" />
					</div>
				) : (
					<div className="table-responsive">
						{data.truncated && (
							<div className="text-secondary small pb-2">
								<T id="crowdsec.capped" data={{ count: data.limit }} />
							</div>
						)}
						<table className="table card-table table-vh table-striped">
							<thead>
								<tr>
									<th aria-label={intl.formatMessage({ id: "crowdsec.details" })}>&nbsp;</th>
									<SortHeader
										label={<T id="crowdsec.target" />}
										column="target"
										{...{ sortKey, direction: sortDirection, onSort }}
									/>
									<SortHeader
										label={<T id="crowdsec.reason" />}
										column="scenario"
										{...{ sortKey, direction: sortDirection, onSort }}
									/>
									<SortHeader
										label={<T id="crowdsec.origin" />}
										column="origin"
										{...{ sortKey, direction: sortDirection, onSort }}
									/>
									<SortHeader
										label={<T id="crowdsec.action" />}
										column="type"
										{...{ sortKey, direction: sortDirection, onSort }}
									/>
									<th>
										<T id="crowdsec.expires" />
									</th>
									<th>&nbsp;</th>
								</tr>
							</thead>
							<tbody>
								{filtered.length === 0 && (
									<tr>
										<td colSpan={7} className="py-4 text-center text-secondary">
											<T id="crowdsec.no-matches" />
										</td>
									</tr>
								)}
								{filtered.map((decision) => {
									const isOpen = expanded === decision.id;
									const detailsId = `crowdsec-decision-${decision.id}`;
									return (
										<Fragment key={decision.id}>
											<tr>
												<td className="w-1">
													<button
														type="button"
														className="btn btn-sm btn-ghost-secondary"
														onClick={() => setExpanded(isOpen ? null : decision.id)}
														aria-expanded={isOpen}
														aria-controls={detailsId}
														aria-label={intl.formatMessage(
															{ id: isOpen ? "crowdsec.collapse" : "crowdsec.expand" },
															{ target: decisionTarget(decision) },
														)}
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
												<td>{decision.type}</td>
												<td title={decision.duration}>
													{decision.duration ? (
														<T
															id="crowdsec.expires-in"
															data={{ duration: decision.duration }}
														/>
													) : (
														<T id="crowdsec.unknown-duration" />
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
												<tr id={detailsId}>
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
