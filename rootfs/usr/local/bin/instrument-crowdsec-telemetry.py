"""Insert one observation after the pinned bouncer's HTTP response.

Fail the image build on source drift rather than silently misreporting WAF data.
This hook does not change request handling or upstream return values.
"""
from pathlib import Path

filename = Path("/usr/local/share/lua/5.1/crowdsec.lua")
source = filename.read_text()
anchor = '  if err ~= nil then\n    -- the appsec stops reading at max_body_size'
if source.count(anchor) != 1:
    raise SystemExit("CrowdSec AppSec observation anchor changed; review telemetry before upgrading")
source = source.replace(anchor, '  require("npmplus_telemetry").response(res and res.status, err)\n\n' + anchor)
filename.write_text(source)
