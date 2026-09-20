# Investigating observed attackers

The CrowdSec page opens on **Overview**; switch to the **Attackers** tab to investigate. Each row groups one source IP from locally retained detection alerts.
Search by IP, country, ASN, observed host or detector name; sort by most recent observation or alert count.
The same IP may represent several clients. Community blocklist downloads, manual decisions and simulated alerts do not
create attacker rows. An expired ban does not remove retained detections.

**Load older history** extends the snapshot without double-counting earlier batches. Rows are paginated on the server.
The page reports the selected observation window, scanned alert count and whether coverage is partial. First observation,
counts and ordering may change as older history loads. Refresh history starts a new snapshot. Snapshots expire after ten
minutes or a backend restart and may be evicted when several administrators browse simultaneously.

Each request scans at most four batches of 25 alerts. The underlying signed history cursor stops after 100 batches,
or sooner if an upstream response or timestamp tie prevents safe progress. The UI labels this limit explicitly. It does
not claim to show unlogged traffic, deleted history, or every attacker beyond that boundary. Host and scenario summaries
are bounded examples from retained alert metadata, not exhaustive request inventories.

Select an IP to open **Observed activity**. Detections appear chronologically, and loading older history extends the
sequence. Expand a detection to read retained event records, paginated 25 at a time. Query strings, fragments and
unapproved event fields remain excluded. The event count recorded by CrowdSec can exceed the number of retained records;
the UI marks incomplete evidence. Individual upstream responses are bounded to 12 MiB and event browsing to 25,000 records.

Local exact-IP decisions are displayed separately from detections. A decision is an instruction to remediation components,
not proof of a blocked request. Range and community decisions are not included in this status. Missing or incomplete
decision data produces an unavailable status. Aggregate enforcement observations remain in the WAF and System tabs;
this view does not attribute those totals to individual IPs or infer successful exploitation or privilege escalation.

All investigation endpoints require administrator access. No new database, external intelligence subscription, or
additional deployment container is required.
