import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getCrowdsecAlerts } from "src/api/backend";
import { T } from "src/locale";
import AttackDetails from "./AttackDetails";

const HoneypotEvidence = ({ ip }: { ip: string }) => {
	const [open, setOpen] = useState(false);
	const query = useQuery({
		queryKey: ["honeypot-alert-evidence", ip],
		queryFn: ({ signal }) => getCrowdsecAlerts("Ip", ip, signal),
		enabled: open,
		staleTime: 30_000,
	});
	return (
		<details
			className="small mt-2 text-break"
			style={{ maxWidth: "32rem", whiteSpace: "normal" }}
			onToggle={(event) => setOpen(event.currentTarget.open)}
		>
			<summary>
				<T id="crowdsec.evidence.details" />
			</summary>
			<p className="my-2">
				<T id="crowdsec.evidence.honeypot" />
			</p>
			<p>
				<T id="crowdsec.evidence.honeypot-limits" />
			</p>
			<strong>
				<T id="crowdsec.evidence.related" />
			</strong>
			<p>
				<T id="crowdsec.evidence.related-help" />
			</p>
			{query.isFetching && (
				<p role="status">
					<T id="crowdsec.evidence.loading" />
				</p>
			)}
			{query.isError ? (
				<p role="alert">
					<T id="crowdsec.evidence.related-error" />
				</p>
			) : query.data?.length === 0 ? (
				<p>
					<T id="crowdsec.no-alerts" />
				</p>
			) : (
				query.data?.map((alert) => <AttackDetails key={alert.id} alert={alert} />)
			)}
		</details>
	);
};

export default HoneypotEvidence;
