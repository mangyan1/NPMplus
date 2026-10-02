# Patched CrowdSec build

This build retains CrowdSec v1.8.1 at its immutable release commit and the official
image's entrypoint, staged configuration, detection agent, LAPI, AppSec and every
notification plugin. It rebuilds with Go 1.26.8, gRPC 1.83.2 and x/crypto 0.56.0,
updates Alpine packages, and separately rebuilds yq 4.50.1 with x/net 0.58.0 and
x/text 0.41.0. Native RE2 and upstream's static SQLite implementation stay enabled.
The MIT license is included in the image.

The old pgx/v4 driver uses end-of-life pgproto3/v2, which has no patched release.
Two driver imports move to the maintained pgx/v5 5.11.0 standard-library driver.
The parser regression checks invalid server-controlled field lengths without
panics and preserves valid NULL, empty and populated fields. The same regression
fails with the old driver. Upstream database, LAPI, AppSec, expression, config and
hub tests run during the build. CI also exercises upstream's concurrent PostgreSQL
alert-ingestion/cleanup test against a real PostgreSQL database.

The runtime smoke starts the actual entrypoint with a read-only root filesystem,
dropped capabilities and private loopback ports. It verifies authenticated LAPI
access, read-only bouncer permissions, machine decision writes, AppSec allow/block,
metrics, decision deletion, and key/database persistence through restart. Synthetic
test decisions remain local; production CAPI enrollment and enforcement are unchanged.

Both architectures must pass the Security Images gate without exceptions at
MEDIUM/HIGH/CRITICAL before their exact contents are published as
`ghcr.io/mangyan1/npmplus:crowdsec`. The raw reports retain unclassified findings.
GO-2026-5932 applies to deprecated x/crypto/openpgp; the build explicitly verifies
that no CrowdSec command imports that package. It is not suppressed.

```sh
docker build -t npmplus-crowdsec:check security-images/crowdsec
python3 security-images/crowdsec/smoke.py npmplus-crowdsec:check
```

The fork owns these pins and the two-import driver patch. Reassess against each
upstream stable release. This image does not move CrowdSec's upstream tags.
