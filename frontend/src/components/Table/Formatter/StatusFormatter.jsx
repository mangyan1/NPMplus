import cn from "clsx";
import { T } from "src/locale";

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

	return (
		<span className={cn("status", `status-${color}`)} title={tip ? tip : undefined}>
			<span className="status-dot status-dot-animated" />
			<T id={label} />
		</span>
	);
}
