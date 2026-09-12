import type { CrowdsecAlert } from "src/api/backend";
import { useLocaleState } from "src/context";
import { formatDateTime, T } from "src/locale";
import { attackType, toolHints } from "./attackEvidence";
import { scenarioLabel } from "./scenarios";

export const RuleDetails = ({ name }: { name: string }) => (
	<div className="text-break">
		<strong>{scenarioLabel(name)}</strong>
		<div>
			<code>{name}</code>
		</div>
		<div className="text-secondary">
			<T id={`crowdsec.evidence.type-${attackType(name)}`} />
		</div>
	</div>
);

const AttackDetails = ({ alert }: { alert: CrowdsecAlert }) => {
	const { locale } = useLocaleState();
	return (
		<section
			className="small py-2 text-break"
			aria-label={`Alert ${alert.id}`}
			style={{ overflowWrap: "anywhere", maxWidth: "min(60rem, calc(100vw - 5rem))" }}
		>
			<RuleDetails name={alert.scenario} />
			<p className="my-2">{alert.message}</p>
			<p className="text-secondary">
				<T id={alert.simulated ? "crowdsec.evidence.simulated" : "crowdsec.evidence.detected"} />
			</p>
			<dl className="mb-2">
				<dt>
					<T id="crowdsec.source" />
				</dt>
				<dd>
					{alert.source.ip || alert.source.value || "—"} {alert.source.asName && ` · ${alert.source.asName}`}{" "}
					{alert.source.asNumber && `(AS${alert.source.asNumber})`}
				</dd>
				<dt>
					<T id="crowdsec.evidence.window" />
				</dt>
				<dd>
					{alert.startAt ? formatDateTime(alert.startAt, locale) : "—"} →{" "}
					{alert.stopAt ? formatDateTime(alert.stopAt, locale) : "—"}
				</dd>
			</dl>
			<p>
				<T id="crowdsec.evidence.sample" data={{ shown: alert.events.length, count: alert.eventsCount }} />
			</p>
			{alert.events.map((event, index) => {
				const agents = event.meta.filter((meta) => meta.key === "http_user_agent");
				const hints = [...new Set(agents.flatMap((meta) => toolHints(meta.value)))];
				return (
					<div key={`${alert.id}-${index}`} className="border-top pt-2 mt-2">
						{event.timestamp && (
							<div className="text-secondary mb-1">{formatDateTime(event.timestamp, locale)}</div>
						)}
						{event.meta
							.filter((meta) => meta.key === "rule_name")
							.map((meta, ruleIndex) => (
								<RuleDetails key={ruleIndex} name={meta.value} />
							))}
						<div className="my-2">
							<strong>
								<T id="crowdsec.evidence.client" />:{" "}
							</strong>
							{hints.length ? hints.join(", ") : <T id="crowdsec.evidence.unknown-tool" />}
						</div>
						{hints.length > 0 && (
							<p className="text-secondary">
								<T id="crowdsec.evidence.tool-help" />
							</p>
						)}
						{event.meta.map((meta, metaIndex) => (
							<div key={`${meta.key}-${metaIndex}`}>
								<span className="text-secondary">{meta.key}: </span>
								{meta.value}
							</div>
						))}
					</div>
				);
			})}
			{!alert.events.length && (
				<p>
					<T id="crowdsec.evidence.no-events" />
				</p>
			)}
		</section>
	);
};

export default AttackDetails;
