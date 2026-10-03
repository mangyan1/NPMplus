import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Button from "react-bootstrap/Button";
import Modal from "react-bootstrap/Modal";
import { enableCrowdsecCrs, getCrowdsecCrsControl } from "src/api/backend";
import { T } from "src/locale";

const CrsControl = ({ configured }: { configured: boolean }) => {
	const [confirm, setConfirm] = useState(false);
	const client = useQueryClient();
	const status = useQuery({
		queryKey: ["crowdsec-crs-control"],
		queryFn: ({ signal }) => getCrowdsecCrsControl(signal),
		refetchInterval: 5000,
		retry: false,
	});
	const enable = useMutation({
		mutationFn: enableCrowdsecCrs,
		onSuccess: async () => {
			setConfirm(false);
			await client.invalidateQueries({ queryKey: ["crowdsec-crs-control"] });
			await client.invalidateQueries({ queryKey: ["crowdsec-metrics"] });
			await client.invalidateQueries({ queryKey: ["audit-logs"] });
		},
	});
	const data = status.data;
	const fresh = !status.isError && !status.isRefetchError;
	const running = data?.state === "running";
	const enabled = fresh && (data?.available ? data.enabled : configured);
	useEffect(() => {
		if (fresh && data?.state === "enabled") void client.invalidateQueries({ queryKey: ["crowdsec-metrics"] });
	}, [client, data?.state, fresh]);
	const allowed = fresh && data?.available && data.eligible && !running && !enabled && !data.retryAfter;
	let help = "crowdsec.crs.control-loading";
	if (running) help = status.isError ? "crowdsec.crs.control-reconnecting" : "crowdsec.crs.control-running";
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
					variant={enabled ? "outline-success" : "primary"}
					disabled={!allowed || enable.isPending}
					onClick={() => {
						enable.reset();
						setConfirm(true);
					}}
				>
					<T
						id={
							running
								? "crowdsec.crs.control-enabling"
								: enabled
									? "crowdsec.crs.control-enabled-label"
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
				onHide={() => !enable.isPending && setConfirm(false)}
				aria-labelledby="crs-enable-title"
				centered
			>
				<Modal.Header closeButton={!enable.isPending}>
					<Modal.Title id="crs-enable-title">
						<T id="crowdsec.crs.control-enable" />
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					<p>
						<T id="crowdsec.crs.control-confirm" />
					</p>
					{enable.isError && (
						<Alert variant="warning">
							<T
								id={
									enable.error.message.startsWith("crowdsec.crs.control-")
										? enable.error.message
										: "crowdsec.crs.control-error"
								}
							/>
						</Alert>
					)}
				</Modal.Body>
				<Modal.Footer>
					<Button variant="secondary" disabled={enable.isPending} onClick={() => setConfirm(false)}>
						<T id="cancel" />
					</Button>
					<Button variant="primary" disabled={!allowed || enable.isPending} onClick={() => enable.mutate()}>
						<T id={enable.isPending ? "crowdsec.crs.control-enabling" : "crowdsec.crs.control-enable"} />
					</Button>
				</Modal.Footer>
			</Modal>
		</div>
	);
};

export default CrsControl;
