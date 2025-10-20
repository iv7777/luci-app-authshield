-- LuCI CBI model for AuthShield
local sys = require "luci.sys"
local jsonc = require "luci.jsonc"


local m, s, o

m = Map("authshield", translate("AuthShield"),
    translate("Lightweight intrusion prevention that delays or blocks repeated failed login attempts for both LuCI and Dropbear SSH."))

-- IMPORTANT: the UCI section type is 'settings' (not 'main')
s = m:section(TypedSection, "settings", translate("General Settings"))
s.anonymous = true
s.addremove = false

-- Enable / Disable
o = s:option(Flag, "enabled", translate("Enable AuthShield"))
o.default = 1
o.rmempty = false

-- Failure threshold
o = s:option(Value, "threshold", translate("Failure Threshold"),
    translate("Number of failed attempts within the time window before an IP is banned."))
o.datatype = "uinteger"
o.default = 5
o.datatype = "range(1,30)"
o.rmempty = false

-- Time window (seconds)
o = s:option(Value, "window", translate("Time Window (s)"),
    translate("Period in seconds during which failed attempts are counted."))
o.datatype = "uinteger"
o.default = 10
o.datatype = "range(10,60)"
o.rmempty = false

-- Penalty duration (seconds)
o = s:option(Value, "penalty", translate("Ban Duration (s)"),
    translate("How long (in seconds) a client is banned after exceeding the threshold."))
o.datatype = "uinteger"
o.default = 60
o.datatype = "range(60,600)"
o.rmempty = false

-- Ports protected
o = s:option(Value, "ports", translate("Protected Ports"),
    translate("TCP ports to protect (space-separated). Usually 80 443 for LuCI, add others as needed."))
o.default = "80 443"

-- Escalate frequent offenders
o = s:option(Flag, "escalate_enable", translate("Escalate frequent offenders"),
    translate("If an IP is banned more than 5 times within 1 hour, ban it for 24 hours."))
o.default = 1

-- Monitor Dropbear SSH
o = s:option(Flag, "watch_dropbear", translate("Monitor Dropbear SSH"),
    translate("Also monitor bad password attempts on Dropbear SSH service."))
o.default = 0

-- Ignore private/local IPs
o = s:option(Flag, "ignore_private_ip", translate("Ignore Private IPs"),
    translate("Skip banning LAN, loopback, and link-local addresses."))
o.default = 1



-- Current bans (from nft sets; shows IP and remaining time)
do
    local function format_secs(s)
        s = tonumber(s or 0) or 0
        local d = math.floor(s / 86400); s = s % 86400
        local h = math.floor(s / 3600);  s = s % 3600
        local m = math.floor(s / 60);    local sec = math.floor(s % 60)
        if d > 0 then return string.format("%dd %02dh%02dm", d, h, m) end
        if h > 0 then return string.format("%dh %02dm %02ds", h, m, sec) end
        if m > 0 then return string.format("%dm %02ds", m, sec) end
        return string.format("%ds", sec)
    end

    local function fetch_set(setname)
        local out = sys.exec("nft -j list set inet fw4 " .. setname .. " 2>/dev/null")
        local list = {}
        if not out or #out == 0 then return list end
        local ok, obj = pcall(jsonc.parse, out)
        if not ok or not obj or not obj.nftables then return list end
        for _, item in ipairs(obj.nftables) do
            if item.set and item.set.elem then
                for _, e in ipairs(item.set.elem) do
                    if type(e) == "table" then
                        local ip = (type(e.elem) == "table" and (e.elem.val or e.elem[1])) or e.elem or e.val or e[1]
                        local rem = e.expires or e.timeout or (type(e.elem) == "table" and e.elem.timeout)
                        if ip then table.insert(list, { ip = tostring(ip), rem = tonumber(rem) }) end
                    elseif type(e) == "string" then
                        table.insert(list, { ip = e, rem = nil })
                    end
                end
            end
        end
        return list
    end

    local function render_rows(list)
        table.sort(list, function(a,b) return (a.ip or "") < (b.ip or "") end)
        if #list == 0 then return "<em>" .. translate("None") .. "</em>" end
        local html = '<table class="table"><thead><tr><th>' .. translate("IP") .. '</th><th>' .. translate("Expires") .. '</th></tr></thead><tbody>'
        for _, r in ipairs(list) do
            local rem = (r.rem and r.rem > 0) and format_secs(r.rem) or "-"
            html = html .. "<tr><td>" .. r.ip .. "</td><td>" .. rem .. "</td></tr>"
        end
        html = html .. "</tbody></table>"
        return html
    end

    local v4 = fetch_set("authshield_penalty_v4")
    local v6 = fetch_set("authshield_penalty_v6")
    for _, x in ipairs(v6) do table.insert(v4, x) end  -- merge v6 into v4 list

    local dv = s:option(DummyValue, "_current_bans", translate("Currently Banned IPs"))
    dv.rawhtml = true
    function dv.cfgvalue()
        return render_rows(v4)
    end
end

return m
