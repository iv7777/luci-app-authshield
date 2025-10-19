-- LuCI CBI model for AuthShield

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

-- Time window (seconds)
o = s:option(Value, "window", translate("Time Window (s)"),
    translate("Period in seconds during which failed attempts are counted."))
o.datatype = "uinteger"
o.default = 10

-- Penalty duration (seconds)
o = s:option(Value, "penalty", translate("Ban Duration (s)"),
    translate("How long (in seconds) a client is banned after exceeding the threshold."))
o.datatype = "uinteger"
o.default = 60

-- Ports protected
o = s:option(Value, "ports", translate("Protected Ports"),
    translate("TCP ports to protect (space-separated). Usually 80 443 for LuCI, add others as needed."))
o.default = "80 443"

-- Monitor Dropbear SSH
o = s:option(Flag, "watch_dropbear", translate("Monitor Dropbear SSH"),
    translate("Also monitor bad password attempts on Dropbear SSH service."))
o.default = 0

-- Ignore private/local IPs
o = s:option(Flag, "ignore_private_ip", translate("Ignore Private IPs"),
    translate("Skip banning LAN, loopback, and link-local addresses."))
o.default = 1

return m
