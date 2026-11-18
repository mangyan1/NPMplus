import cn from "clsx";
import OverlayTrigger from "react-bootstrap/OverlayTrigger";
import Popover from "react-bootstrap/Popover";
import { T } from "src/locale";
import { showNginxErrorModal } from "src/modals";

export function StatusFormatter({ enabled, nginxOnline, nginxErr, reachable, reachErr }) {
	let color = "red";
	let label = "offline";
	let tip = nginxErr;

	if (!enabled) {
		color = "yellow";
		label = "disabled";
		tip = null;
	} else if (!nginxOnline) {
		color = "red";
		label = "offline";
		tip = nginxErr;
	} else if (reachable === false) {
		color = "orange";
		label = "unreachable";
		tip = reachErr;
	} else {
		color = "lime";
		label = "online";
		tip = null;
	}

	const status = (
		<span className={cn("status", `status-${color}`)} title={tip ? tip : undefined}>
			<span className="status-dot status-dot-animated" />
			<T id={label} />
		</span>
	);

	if (enabled && !nginxOnline) {
		return (
			<OverlayTrigger
				placement="top"
				overlay={
					<Popover>
						<Popover.Body>
							<T id="action.view-details" />
						</Popover.Body>
					</Popover>
				}
			>
				<button
					type="button"
					className="p-0 border-0 bg-transparent"
					onClick={() => showNginxErrorModal(nginxErr)}
				>
					{status}
				</button>
			</OverlayTrigger>
		);
	}

	return status;
}
