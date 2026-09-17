"""Post-build patches for the pinned lua-cs-bouncer, both fail-loud on drift.

One observation insertion after the pinned bouncer's HTTP response (telemetry
only). One upstream fix carried ahead of the pin: an AppSec failure under
APPSEC_FAILURE_ACTION=deny served the ban response with HTTP 200 because the
failure return kept the function's initial status_code placeholder. Upstream
PR https://github.com/crowdsecurity/lua-cs-bouncer/pull/159 fixes it; drop
this patch when the pin moves past a release carrying it.
"""
from pathlib import Path

filename = Path("/usr/local/share/lua/5.1/crowdsec.lua")
source = filename.read_text()
anchor = '  if err ~= nil then\n    -- the appsec stops reading at max_body_size'
if source.count(anchor) != 1:
    raise SystemExit("CrowdSec AppSec observation anchor changed; review telemetry before upgrading")
source = source.replace(anchor, '  require("npmplus_telemetry").response(res and res.status, err)\n\n' + anchor)

deny_anchor = """  local ok, remediation, status_code = true, "allow", 200
  if runtime.conf["APPSEC_FAILURE_ACTION"] == DENY then
    ok = false
    remediation = runtime.conf["FALLBACK_REMEDIATION"]
  end
"""
deny_replacement = """  local ok, remediation, status_code = true, "allow", 200
  if runtime.conf["APPSEC_FAILURE_ACTION"] == DENY then
    ok = false
    remediation = runtime.conf["FALLBACK_REMEDIATION"]
    -- the failure return carries this status code to ban.apply: deny must
    -- serve the ban response as 403, not as the 200 placeholder
    status_code = ngx.HTTP_FORBIDDEN
  end
"""
if source.count(deny_anchor) != 1:
    raise SystemExit("CrowdSec AppSec deny branch changed; re-evaluate the failure status patch before upgrading")
source = source.replace(deny_anchor, deny_replacement)
filename.write_text(source)