import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Button from "react-bootstrap/Button";
import Modal from "react-bootstrap/Modal";
import { disableCrowdsecCrs, enableCrowdsecCrs, getCrowdsecCrsControl } from "src/api/backend";
import { T } from "src/locale";

type Intent = "enable" | "disable";

const CrsControl = ({ configured }: { configured: boolean }) => {
	const [confirm, setConfirm] = useState(false);
	const [intent, setIntent] = useState<Intent>("enable");
	const client = useQueryClient();
	const status = useQuery({
		queryKey: ["crowdsec-crs-control"],
		queryFn: ({ signal }) => getCrowdsecCrsControl(signal),
		refetchInterval: 5000,
		retry: false,
	});
	const invalidate = async () => {
		await client.invalidateQueries({ queryKey: ["crowdsec-crs-control"] });
		await client.invalidateQueries({ queryKey: ["crowdsec-metrics"] });
		await client.invalidateQueries({ queryKey: ["audit-logs"] });
	};
	const enable = useMutation({
		mutationFn: enableCrowdsecCrs,
		onSuccess: async () => {
			setConfirm(false);
			await invalidate();
		},
	});
	const disable = useMutation({
		mutationFn: disableCrowdsecCrs,
		onSuccess: async () => {
			setConfirm(false);
			await invalidate();
		},
	});
	const action = intent === "disable" ? disable : enable;
	const data = status.data;
	const fresh = !status.isError && !status.isRefetchError;
	const running = data?.state === "running";
	const enabled = fresh && (data?.available ? data.enabled : configured);
	// Refresh the counters exactly when a running change finishes, not on mount.
	const previous = useRef<string | undefined>(undefined);
	useEffect(() => {
		const state = data?.state;
		if (fresh && previous.current === "running" && ["enabled", "idle"].includes(state ?? ""))
			void client.invalidateQueries({ queryKey: ["crowdsec-metrics"] });
		previous.current = state;
	}, [client, data?.state, fresh]);
	const allowed = fresh && data?.available && data.eligible && !running && !data.retryAfter;
	let help = "crowdsec.crs.control-loading";
	if (running)
		help = status.isError
			? "crowdsec.crs.control-reconnecting"
			: intent === "disable"
				? "crowdsec.crs.control-disabling"
				: "crowdsec.crs.control-running";
	else if (status.isError) help = "crowdsec.crs.control-unavailable";
	else if (data?.available === false) help = "crowdsec.crs.control-install";
	else if (enabled) help = "crowdsec.crs.control-enabled";
	else if (data && !data.eligible) help = "crowdsec.crs.control-unsupported";
	else if (data?.retryAfter) help = "crowdsec.crs.control-cooldown";
	else if (data) help = "crowdsec.crs.control-ready";
	return (
		<div className="mb-3">
			<div className="d-flex flex-wrap align-items-center gap-2">
				<Button
					variant={enabled ? "outline-danger" : "primary"}
					disabled={!allowed || action.isPending}
					onClick={() => {
						enable.reset();
						disable.reset();
						setIntent(enabled ? "disable" : "enable");
						setConfirm(true);
					}}
				>
					<T
						id={
							running && intent === "disable"
								? "crowdsec.crs.control-disabling"
								: running
									? "crowdsec.crs.control-enabling"
									: enabled
										? "crowdsec.crs.control-disable"
										: "crowdsec.crs.control-enable"
						}
					/>
				</Button>
				<span className="text-secondary small" role="status" aria-live="polite">
					<T id={help} />
				</span>
			</div>
			{fresh && ["failed", "rollback-failed"].includes(data?.state ?? "") && (
				<Alert className="mt-2 mb-0" variant="warning">
					<T id={`crowdsec.crs.control-${data?.state}`} />
				</Alert>
			)}
			<Modal
				show={confirm}
				onHide={() => !action.isPending && setConfirm(false)}
				aria-labelledby="crs-control-title"
				centered
			>
				<Modal.Header closeButton={!action.isPending}>
					<Modal.Title id="crs-control-title">
						<T id={intent === "disable" ? "crowdsec.crs.control-disable" : "crowdsec.crs.control-enable"} />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<p>
						<T
							id={
								intent === "disable"
									? "crowdsec.crs.control-disable-confirm"
									: "crowdsec.crs.control-confirm"
							}
						/>
					</p>
					{action.isError && (
						<Alert variant="warning">
							<T
								id={
									action.error.message.startsWith("crowdsec.crs.control-")
										? action.error.message
										: "crowdsec.crs.control-error"
								}
							/>
						</Alert>
					)}
				</Modal.Body>
				<Modal.Footer>
					<Button variant="secondary" disabled={action.isPending} onClick={() => setConfirm(false)}>
						<T id="cancel" />
					</Button>
					<Button
						variant={intent === "disable" ? "danger" : "primary"}
						disabled={!allowed || action.isPending}
						onClick={() => action.mutate()}
					>
						<T
							id={
								action.isPending
									? intent === "disable"
										? "crowdsec.crs.control-disabling"
										: "crowdsec.crs.control-enabling"
									: intent === "disable"
										? "crowdsec.crs.control-disable"
										: "crowdsec.crs.control-enable"
							}
						/>
					</Button>
				</Modal.Footer>
			</Modal>
		</div>
	);
};

export default CrsControl;
