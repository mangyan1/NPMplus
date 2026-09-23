import type { CrowdsecAlert } from "src/api/backend";
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

// the rule, the source and the request line are rendered as their own lines
// above the raw dump, so repeating them there is pure noise. the User-Agent
// stays: it is the raw record behind the (spoofable) tool hint, not a
// duplicate of it.
const DUMPED_ELSEWHERE = new Set(["rule_name", "source_ip", "method", "target_uri", "uri"]);

// which URL was hit is the one thing an operator scans a page of events for,
// so it stays on the line rather than behind the disclosure below
const requestLine = (meta: CrowdsecAlert["events"][number]["meta"]) => {
	const target = meta.find((item) => item.key === "target_uri" || item.key === "uri");
	const verb = meta.find((item) => item.key === "method");
	return target || verb ? { verb: verb?.value, target: target?.value } : null;
};

// the ban list hoists this line above a run of alerts, so it lives here rather
// than being re-spelled at each call site
export const AlertSource = ({ source }: { source: CrowdsecAlert["source"] }) => (
	<>
		{source.ip || source.value || "—"} {source.asName && ` · ${source.asName}`}{" "}
		{source.asNumber && `(AS${source.asNumber})`}
	</>
);

const AttackDetails = ({ alert, compact = false }: { alert: CrowdsecAlert; compact?: boolean }) => {
	// an alert whose own scenario is not one of the rules its events name is a
	// rollup of separate matches (CrowdSec aggregates them), so the events are
	// the only place the matched rules appear and the caveat is needed. On a
	// per-rule alert the event names the same rule as the header: a duplicate.
	const matchedRules = [
		...new Set(
			alert.events.flatMap((event) =>
				event.meta
					.filter((meta) => meta.key === "rule_name" && meta.value !== alert.scenario)
					.map((meta) => meta.value),
			),
		),
	];
	return (
		<section
			className="small py-2 text-break"
			aria-label={`Alert ${alert.id}`}
			style={{ overflowWrap: "anywhere", maxWidth: "min(60rem, calc(100vw - 5rem))" }}
		>
			<RuleDetails name={alert.scenario} />
			<p className="my-2">{alert.message}</p>
			{matchedRules.length > 0 && (
				<p className="text-secondary">
					<T id="crowdsec.evidence.waf-rollup" />
				</p>
			)}
			{/* the ban header states the shared caveat once for every alert it
			    covers; only the simulated warning is specific to one alert */}
			{compact ? (
				alert.simulated && (
					<p className="text-secondary">
						<T id="crowdsec.evidence.simulated" />
					</p>
				)
			) : (
				<p className="text-secondary">
					<T id={alert.simulated ? "crowdsec.evidence.simulated" : "crowdsec.evidence.detected"} />
				</p>
			)}
			<dl className="mb-2">
				{!compact && (
					<>
						<dt>
							<T id="crowdsec.source" />
						</dt>
						<dd>
							<AlertSource source={alert.source} />
						</dd>
					</>
				)}
				<dt>
					<T id="crowdsec.evidence.window" />
				</dt>
				<dd>
					{alert.startAt ? formatDateTime(alert.startAt) : "—"} →{" "}
					{alert.stopAt ? formatDateTime(alert.stopAt) : "—"}
				</dd>
			</dl>
			<p>
				<T id="crowdsec.evidence.sample" data={{ shown: alert.events.length, count: alert.eventsCount }} />
			</p>
			{alert.events.map((event, index) => {
				const agents = event.meta.filter((meta) => meta.key === "http_user_agent");
				const hints = [...new Set(agents.flatMap((meta) => toolHints(meta.value)))];
				const rules = event.meta.filter((meta) => meta.key === "rule_name" && meta.value !== alert.scenario);
				const fields = event.meta.filter((meta) => !DUMPED_ELSEWHERE.has(meta.key));
				const request = requestLine(event.meta);
				return (
					<div key={`${alert.id}-${index}`} className="border-top pt-2 mt-2">
						{event.timestamp && (
							<div className="text-secondary mb-1">{formatDateTime(event.timestamp)}</div>
						)}
						{request && (
							<div className="text-break">
								{request.verb && <strong>{request.verb} </strong>}
								{request.target}
							</div>
						)}
						{rules.map((meta, ruleIndex) => (
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
						{/* the per-event key/value list is what made one ban run to ~130
						    lines; it is reference detail, so it is collapsed by default */}
						{fields.length > 0 && (
							<details>
								<summary className="text-secondary">
									<T id="crowdsec.evidence.raw-fields" />
								</summary>
								<p className="text-secondary my-2">
									<T id="crowdsec.evidence.raw-fields-help" />
								</p>
								{fields.map((meta, metaIndex) => (
									<div key={`${meta.key}-${metaIndex}`}>
										<span className="text-secondary">{meta.key}: </span>
										{meta.value}
									</div>
								))}
							</details>
						)}
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
