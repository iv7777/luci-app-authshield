-- LuCI CBI model for AuthShield
local sys   = require "luci.sys"
local jsonc = require "luci.jsonc"

local m, s, o

m = Map("authshield", translate("AuthShield"),
    translate("Lightweight intrusion prevention that delays or blocks repeated failed login attempts for both LuCI and Dropbear SSH."))

-- IMPORTANT: the UCI section type is 'settings' (not 'main')
s = m:section(TypedSection, "settings", translate("General Settings"))
s.anonymous = true
s.addremove = false

-- small helpers
local function uint_range_validator(minv, maxv, label, def)
    return function(self, value)
        if not value or value == "" then
            return tostring(def)   -- auto-fill with default if empty
        end
        local n = tonumber(value)
        if not n or n < minv or n > maxv then
            return nil, translatef("%s must be %d–%d.", label, minv, maxv)
        end
        return tostring(math.floor(n))
    end
end

-- Enable / Disable
o = s:option(Flag, "enabled", translate("Enable AuthShield"))
o.default = 1
o.rmempty = false

-- Failure threshold
o = s:option(Value, "threshold", translate("Failure Threshold"),
    translate("Number of failed attempts within the time window before an IP is banned.") ..
    " " .. translate("Allowed range:") .. " " .. translate("1–30"))
o.placeholder = "5"
o.default = 5
o.rmempty = true
o.validate = uint_range_validator(1, 30, translate("Failure Threshold"), 5)
function o.write(self, section, value)
    if not value or value == "" then value = "5" end
    Value.write(self, section, value)
end

-- Time window (seconds)
o = s:option(Value, "window", translate("Time Window (s)"),
    translate("Period in seconds during which failed attempts are counted.") ..
    " " .. translate("Allowed range:") .. " " .. translate("10–60"))
o.placeholder = "10"
o.default = 10
o.rmempty = true
o.validate = uint_range_validator(10, 60, translate("Time Window (s)"), 10)
function o.write(self, section, value)
    if not value or value == "" then value = "10" end
    Value.write(self, section, value)
end

-- Penalty duration (seconds)
o = s:option(Value, "penalty", translate("Ban Duration (s)"),
    translate("How long (in seconds) a client is banned after exceeding the threshold.") ..
    " " .. translate("Allowed range:") .. " " .. translate("60–600"))
o.placeholder = "60"
o.default = 60
o.rmempty = true
o.validate = uint_range_validator(60, 600, translate("Ban Duration (s)"), 60)
function o.write(self, section, value)
    if not value or value == "" then value = "60" end
    Value.write(self, section, value)
end

-- Ports protected
local ports = s:option(Value, "ports", translate("Protected Ports"))
ports.placeholder = "80 443"
ports.description = translate("Space-separated ports (max 10). Each must be numeric, 1–65535.")
function ports.validate(self, value, section)
    if not value or value == "" then
        return value
    end
    local seen, out = {}, {}
    for p in value:gmatch("[%d]+") do
        local n = tonumber(p)
        if not n or n < 1 or n > 65535 then
            return nil, translatef("Invalid port number: %s (must be between 1 and 65535)", p)
        end
        if not seen[n] then
            seen[n] = true
            out[#out + 1] = tostring(n)
        end
        if #out > 10 then
            return nil, translate("You can specify at most 10 ports.")
        end
    end
    return table.concat(out, " ")
end

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

-- ---- Current bans (from nft sets; shows IP and remaining time with live countdown) ----
do
    local function fetch_set(setname)
        local out = sys.exec("nft -j list set inet fw4 " .. setname .. " 2>/dev/null")
        local list = {}
        if not out or #out == 0 then return list end

        local ok, obj = pcall(jsonc.parse, out)
        if not ok or type(obj) ~= "table" or type(obj.nftables) ~= "table" then
            return list
        end

        for _, item in ipairs(obj.nftables) do
            local set = item and item.set
            local elems = set and set.elem
            if type(elems) == "table" then
                for _, e in ipairs(elems) do
                    if type(e) == "table" then
                        local ip = (type(e.elem) == "table" and (e.elem.val or e.elem[1])) or e.elem or e.val or e[1]
                        local rem = e.expires or e.timeout or (type(e.elem) == "table" and e.elem.expires)
                        if ip then table.insert(list, { ip = tostring(ip), rem = tonumber(rem) or 0 }) end
                    elseif type(e) == "string" then
                        table.insert(list, { ip = e, rem = 0 })
                    end
                end
            end
        end
        return list
    end

    local function render_rows(list)
        table.sort(list, function(a,b) return (a.ip or "") < (b.ip or "") end)
        if #list == 0 then
            return "<em>" .. translate("None") .. "</em>"
        end

        local html = {}
        html[#html+1] = '<table class="table"><thead><tr><th>'
        html[#html+1] = translate("IP")
        html[#html+1] = '</th><th>'
        html[#html+1] = translate("Expires")
        html[#html+1] = '</th></tr></thead><tbody>'

        for _, r in ipairs(list) do
            local sec = r.rem and math.floor(r.rem) or 0
            local init = (sec > 0) and (tostring(sec) .. "s") or "-"
            html[#html+1] = '<tr' .. (sec <= 0 and ' class="opacity-50"' or '') .. '>'
            html[#html+1] = '<td>' .. r.ip .. '</td>'
            html[#html+1] = '<td class="as-ttl" data-seconds="' .. tostring(sec) .. '">' .. init .. '</td>'
            html[#html+1] = '</tr>'
        end
        html[#html+1] = '</tbody></table>'

        -- Live countdown (client-side)
        html[#html+1] = [[
<script>
(function(){
  function fmt(sec){
    sec = Math.max(0, Math.floor(sec));
    var d = Math.floor(sec/86400); sec %= 86400;
    var h = Math.floor(sec/3600); sec %= 3600;
    var m = Math.floor(sec/60); var s = sec % 60;
    if (d>0) return d + "d " + String(h).padStart(2,"0") + "h" + String(m).padStart(2,"0") + "m";
    if (h>0) return h + "h " + String(m).padStart(2,"0") + "m " + String(s).padStart(2,"0") + "s";
    if (m>0) return m + "m " + String(s).padStart(2,"0") + "s";
    return s + "s";
  }
  var cells = document.querySelectorAll(".as-ttl");
  if (!cells.length) return;
  setInterval(function(){
    cells.forEach(function(td){
      var sec = parseInt(td.dataset.seconds || "0", 10);
      if (isNaN(sec)) sec = 0;
      if (sec <= 0){
        td.textContent = "-";
        var tr = td.closest("tr");
        if (tr) tr.classList.add("opacity-50");
        return;
      }
      sec -= 1;
      td.dataset.seconds = String(sec);
      td.textContent = fmt(sec);
    });
  }, 1000);
})();
</script>]]
        return table.concat(html)
    end

    local v4 = fetch_set("authshield_penalty_v4")
    local v6 = fetch_set("authshield_penalty_v6")
    for _, x in ipairs(v6) do table.insert(v4, x) end  -- merge

    local dv = s:option(DummyValue, "_current_bans", translate("Currently Banned IPs"))
    dv.rawhtml = true
    function dv.cfgvalue()
        return render_rows(v4)
    end
end

return m
