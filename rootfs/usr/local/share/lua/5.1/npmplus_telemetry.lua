-- Local, bounded observations. No IPs, URLs, headers, payloads or API keys.
local M = {}
local names = {"checks", "inspected", "errors", "unreadable", "bans", "waf_bans", "challenges"}
local installed = false
local function increment_inner(name)
    local id = tonumber(ngx.var.npmplus_proxy_host_id) or 0
    if id < 1 or id > 1000000000 or id % 1 ~= 0 or ngx.is_subrequest then return end
    local dict = ngx.shared.npmplus_telemetry
    -- Use a fixed number of slots; never allocate from attacker-supplied Host.
    local slot = dict:get("host:" .. id)
    if not slot then
        local count = dict:incr("hosts", 1, 0)
        if not count or count > 200 then dict:incr("overflow", 1, 0); return end
        local ok = dict:safe_add("host:" .. id, count)
        slot = dict:get("host:" .. id)
        if not slot then return end
        if ok then dict:safe_set("id:" .. count, id) end
    end
    local _, err = dict:incr(name .. ":" .. slot, 1, 0)
    if err then dict:incr("overflow", 1, 0) end
end
local function increment(name)
    -- Observation failure must never prevent the original remediation call.
    pcall(increment_inner, name)
end

function M.response(status, err)
    local ctx = ngx.ctx
    ctx.npmplus_appsec_response = true
    if not err and (status == 200 or status == 403) then
        increment("inspected")
    else
        increment("errors")
    end
end

function M.install(cs)
    if installed then return end
    installed = true
    local dict = ngx.shared.npmplus_telemetry
    dict:safe_add("epoch", tostring(ngx.now()))
    local check = cs.AppSecCheck
    cs.AppSecCheck = function(...)
        increment("checks")
        ngx.ctx.npmplus_appsec_response = false
        local ok, remediation, status, response, err = check(...)
        ngx.ctx.npmplus_appsec_denied = ok == false
        if not ngx.ctx.npmplus_appsec_response then increment("unreadable") end
        return ok, remediation, status, response, err
    end
    -- Observe the actual remediation calls; a decision lookup is not a block.
    for _, spec in ipairs({{"ban", "bans"}, {"captcha", "challenges"}, {"challenge", "challenges"}}) do
        local plugin = require("plugins.crowdsec." .. spec[1])
        local apply = plugin.apply
        plugin.apply = function(...)
            increment(spec[2])
            if spec[2] == "bans" and ngx.ctx.npmplus_appsec_denied then increment("waf_bans") end
            return apply(...)
        end
    end
end

function M.render()
    -- A reload can preserve shared memory after the bouncer is disabled.
    -- Do not present its old counters as a newly observed active source.
    if not installed then
        ngx.status = 503
        ngx.header.content_type = "application/json"
        ngx.say('{"error":"CrowdSec observation disabled"}')
        return
    end
    local dict = ngx.shared.npmplus_telemetry
    local hosts = {}
    for slot = 1, math.min(dict:get("hosts") or 0, 200) do
        local id = dict:get("id:" .. slot)
        if id then
            local values = {}
            for _, name in ipairs(names) do values[name] = dict:get(name .. ":" .. slot) or 0 end
            hosts[#hosts + 1] = {id=id, counters=values}
        end
    end
    ngx.header.content_type = "application/json"
    local encoded = require("cjson").encode({epoch=dict:get("epoch"), hosts=hosts, overflow=dict:get("overflow") or 0})
    if #hosts == 0 then encoded = encoded:gsub('"hosts":{}', '"hosts":[]') end
    ngx.say(encoded)
end
return M
