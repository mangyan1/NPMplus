import { useState } from "react";
import { Alert } from "react-bootstrap";
import Form from "react-bootstrap/Form";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { useCreateCrowdsecBan } from "src/hooks";
import { intl, T } from "src/locale";
import EasyModal, { type InnerModalProps } from "src/modules/easyModal";

interface ShowProps {
	onCreated?: () => void;
}

interface Props extends InnerModalProps, ShowProps {}

const DURATION_OPTIONS = ["1h", "4h", "24h", "7d", "30d"];

const showManualBanModal = (props: ShowProps) => {
	EasyModal.show(ManualBanModal, props);
};

const ManualBanModal = EasyModal.create(({ visible, remove, onCreated }: Props) => {
	const createBan = useCreateCrowdsecBan();
	const [value, setValue] = useState("");
	const [duration, setDuration] = useState("4h");
	const [type, setType] = useState("ban");
	const [reason, setReason] = useState("");
	const [error, setError] = useState<string | null>(null);

	const onSubmit = async () => {
		if (createBan.isPending) return;
		setError(null);
		try {
			await createBan.mutateAsync({ value: value.trim(), duration, type, reason: reason.trim() });
			onCreated?.();
			remove();
		} catch (err: any) {
			const fields = err?.payload?.error?.fields;
			if (Array.isArray(fields) && fields.length > 0) {
				setError(intl.formatMessage({ id: "crowdsec.ban-invalid" }, { fields: fields.join(", ") }));
			} else {
				setError(err?.message || "error.unknown");
			}
		}
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="crowdsec.ban-title" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<Alert variant="danger" show={Boolean(error)} onClose={() => setError(null)} dismissible>
					<T id={error || "error.unknown"} />
				</Alert>
				<Form>
					<Form.Group className="mb-3">
						<Form.Label>
							<T id="crowdsec.ban-target" />
						</Form.Label>
						<Form.Control
							type="text"
							value={value}
							autoComplete="off"
							placeholder={intl.formatMessage({ id: "crowdsec.ban-target.placeholder" })}
							onChange={(event) => setValue(event.target.value)}
						/>
						<Form.Text>
							<T id="crowdsec.ban-target.help" />
						</Form.Text>
					</Form.Group>
					<Form.Group className="mb-3">
						<Form.Label>
							<T id="crowdsec.ban-duration" />
						</Form.Label>
						<Form.Select value={duration} onChange={(event) => setDuration(event.target.value)}>
							{DURATION_OPTIONS.map((option) => (
								<option key={option} value={option}>
									{option}
								</option>
							))}
						</Form.Select>
					</Form.Group>
					<Form.Group className="mb-3">
						<Form.Label>
							<T id="crowdsec.ban-action" />
						</Form.Label>
						<Form.Select value={type} onChange={(event) => setType(event.target.value)}>
							<option value="ban">ban</option>
							<option value="captcha">captcha</option>
						</Form.Select>
					</Form.Group>
					<Form.Group className="mb-3">
						<Form.Label>
							<T id="crowdsec.ban-reason" />
						</Form.Label>
						<Form.Control
							type="text"
							value={reason}
							autoComplete="off"
							placeholder={intl.formatMessage({ id: "crowdsec.ban-reason.placeholder" })}
							onChange={(event) => setReason(event.target.value)}
						/>
					</Form.Group>
				</Form>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={createBan.isPending}>
					<T id="cancel" />
				</Button>
				<Button
					actionType="danger"
					className="ms-auto"
					isLoading={createBan.isPending}
					disabled={createBan.isPending || value.trim().length === 0}
					onClick={onSubmit}
				>
					<T id="crowdsec.ban-submit" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export { showManualBanModal };
