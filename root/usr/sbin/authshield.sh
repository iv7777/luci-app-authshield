#!/bin/sh
#
# AuthShield — lightweight intrusion prevention for OpenWrt
#   Watches syslog for repeated failed logins (LuCI/rpcd, optionally Dropbear)
#   and temporarily bans offending IPs using nftables set timeouts.
#
# Notes
#   - No LuCI patching needed.
#   - IPv4 & IPv6 supported via separate nft sets.
#   - Private IPs (RFC1918/loopback/link-local/ULA) can be ignored.
#

# ---------- Defaults ----------

WINDOW="${WINDOW:-10}"               # Sliding window in seconds for counting failed logins
THRESHOLD="${THRESHOLD:-5}"          # Number of failures within WINDOW before a ban
PENALTY="${PENALTY:-60}"             # Ban duration in seconds
WATCH_DROPBEAR="${WATCH_DROPBEAR:-0}" # Monitor Dropbear SSH bad passwords (1 = enable)

# Global (long-window) rule defaults
GLOBAL_ENABLE="${GLOBAL_ENABLE:-1}"      # Enable long-term global ban tracking
GLOBAL_THRESHOLD="${GLOBAL_THRESHOLD:-60}" # Failures allowed in long-term window
GLOBAL_WINDOW="${GLOBAL_WINDOW:-43200}"    # Long-term window in seconds (12h)
GLOBAL_PENALTY="${GLOBAL_PENALTY:-86400}"  # 24-hour ban duration for global threshold

IGNORE_PRIVATE="${IGNORE_PRIVATE:-1}"      # Ignore local/private IP addresses

# nftables set references (table/chain are prepared by the init script)
SET_V4="${SET_V4:-authshield_penalty_v4}"  # IPv4 penalty set name
SET_V6="${SET_V6:-authshield_penalty_v6}"  # IPv6 penalty set name
SET_V4_PATH="inet fw4 $SET_V4"             # Full path for IPv4 set
SET_V6_PATH="inet fw4 $SET_V6"             # Full path for IPv6 set

# Escalation switch and params
ESCALATE_ENABLE="${ESCALATE_ENABLE:-1}"       # Enable escalation tracking (1 = on)
ESCALATE_THRESHOLD="${ESCALATE_THRESHOLD:-5}" # Bans within window to trigger escalation
ESCALATE_WINDOW="${ESCALATE_WINDOW:-3600}"    # Time window for escalation (1h)
ESCALATE_PENALTY="${ESCALATE_PENALTY:-86400}" # Escalation ban duration (24h)
BAN_TRACK_FILE="${BAN_TRACK_FILE:-/var/run/authshield.bans}" # File storing ban history

# ---------- Helpers ----------

# Ensure both nft sets exist (exit if firewall isn’t ready)
ensure_sets() {
  nft list set $SET_V4_PATH >/dev/null 2>&1 || exit 1
  nft list set $SET_V6_PATH >/dev/null 2>&1 || exit 1
}

# True if $1 is a private/loopback/link-local/ULA address
is_private_ip() {
  case "$1" in
    10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[0-1].* | 127.* | ::1 | fe80:* | fd* | fc*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# Add IP to the nft set with timeout = PENALTY
ban_ip() {
  local ip="$1"
  local override_dur="$2"
  local reason="$3"

  # Optionally skip private/local addresses
  if [ "$IGNORE_PRIVATE" = "1" ] && is_private_ip "$ip"; then
    return 0
  fi

  # Decide penalty
  local dur
  if [ -n "$override_dur" ]; then
    dur="$override_dur"
  elif [ "$ESCALATE_ENABLE" = "1" ]; then
    dur="$(record_and_get_penalty "$ip" 2>/dev/null)" || dur="$PENALTY"
  else
    dur="$PENALTY"
  fi

  case "$ip" in
    *:*) nft add element $SET_V6_PATH "{ $ip timeout ${dur}s }" 2>/dev/null ;; # IPv6
    *)   nft add element $SET_V4_PATH "{ $ip timeout ${dur}s }" 2>/dev/null ;; # IPv4
  esac

  if [ "$ESCALATE_ENABLE" = "1" ] && [ "$dur" -ge "$ESCALATE_PENALTY" ]; then
    logger -t authshield "Escalated ban: $ip for ${dur}s (> ${ESCALATE_THRESHOLD} bans within ${ESCALATE_WINDOW}s)"
  else
    logger -t authshield "Banned IP $ip for ${dur}s${reason:+ (reason: $reason)}"
  fi
}


# Stream failed login events from syslog and print only the offending IPs (one per line)
stream_failures() {
  # Keep logread -f on the left so awk sees a continuous stream.
  logread -f | awk -v watchdb="$WATCH_DROPBEAR" '
    # Emit the cleaned IP to stdout
    function emit_ip(ip) {
      gsub(/[,;]$/, "", ip)      # strip trailing punctuation
      sub(/:[0-9]+$/, "", ip)    # strip trailing :port
      if (ip != "") { print ip; fflush() }
    }

    # Scan fields and return the last token that looks like an IP(v4 or v6)
    function last_ip_like(   i, tok, ip) {
      ip = ""
      for (i = 1; i <= NF; i++) {
        tok = $i
        gsub(/^[\[\(]+|[\]\)]+$/, "", tok)   # strip [ ( and ) ]
        if (tok ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?[,;]?$/) {
          ip = tok
        } else if (tok ~ /^[0-9a-fA-F:]+(%[0-9A-Za-z._-]+)?(:[0-9]+)?[,;]?$/) {
          ip = tok
        }
      }
      return ip
    }

    {
      line = $0

      # LuCI / rpcd / uhttpd failed login lines (case-insensitive on "login")
      if (line ~ /(luci|rpcd|uhttpd)/ && line ~ /(fail|failed|bad)/ && line ~ /login/i) {
        ip = last_ip_like()
        if (ip != "") emit_ip(ip)
        next
      }

      # Dropbear (enabled when watchdb=1)
      # Match both "Bad password" and "Login attempt for nonexistent user"
      if (watchdb == "1" && line ~ /dropbear/ && (line ~ /(Bad|bad).*password/ || line ~ /[Ll]ogin attempt for nonexistent user/)) {
        ip = last_ip_like()
        if (ip != "") emit_ip(ip)
        next
      }

    }
  '
}

# Sliding-window counter:
#   - reads IPs (one per line) on stdin
#   - bans IP once it has THRESHOLD events within WINDOW seconds
monitor_and_ban() {
  awk -v WIN="$WINDOW" -v TH="$THRESHOLD" -v GWIN="$GLOBAL_WINDOW" -v GTH="$GLOBAL_THRESHOLD" -v GEN="$GLOBAL_ENABLE" '
    function now() { return systime() }

    # Append timestamp to IPs ring (T[ip_idx]) and maintain count N[ip]
    function push(ts, ip) { N[ip]++; T[ip "_" N[ip]] = ts }

    # Drop entries older than WIN seconds for this IP
    function prune(ts, ip,   n, m, i, t, MAXW) {
      MAXW = (GWIN > WIN ? GWIN : WIN)
      n = N[ip]; m = 0
      for (i = 1; i <= n; i++) {
        t = T[ip "_" i]
        if (ts - t <= MAXW) { m++; T[ip "_" m] = t }
      }
      N[ip] = m
    }

    # Main stream processing
    {
      ip = $0
      t  = now()
      prune(t, ip)
      push(t, ip)

      if (N[ip] >= TH) {
        print "BAN " ip
        N[ip] = 0
        fflush()
      } else if (GEN == 1) {
        # Count within the longer window without altering the compacted buffer
        longc = 0
        for (i = 1; i <= N[ip]; i++) {
          t2 = T[ip "_" i]
          if (now() - t2 <= GWIN) longc++
        }
        if (longc > GTH) {
          print "BAN24 " ip
          fflush()
        }
      }
    }
  '
}

# Record the ban for $ip, prune old records, and return the effective penalty (seconds)
record_and_get_penalty() {
  local ip="$1"
  local now cutoff tmp count
  now="$(date +%s)"
  cutoff=$(( now - ESCALATE_WINDOW ))
  tmp="/var/run/authshield.bans.$$"

  mkdir -p /var/run
  touch "$BAN_TRACK_FILE"

  count="$(awk -v cutoff="$cutoff" -v ip="$ip" -v out="$tmp" '
    $1 >= cutoff { print > out; if ($2 == ip) c++ }
    END { print (c ? c : 0) }
  ' "$BAN_TRACK_FILE")"

  mv -f "$tmp" "$BAN_TRACK_FILE" 2>/dev/null || true
  printf "%s %s\n" "$now" "$ip" >> "$BAN_TRACK_FILE"

  if [ $(( count + 1 )) -gt "$ESCALATE_THRESHOLD" ]; then
    printf "%s\n" "$ESCALATE_PENALTY"
  else
    printf "%s\n" "$PENALTY"
  fi
}

# ---------- Main ----------
main() {
  ensure_sets || { echo "authshield: nft sets missing" >&2; exit 1; }

  # Pipeline:
  #   [ logread -f → awk (IPs) ] | [ awk sliding window ] | [ shell loop → ban_ip ]
  stream_failures | monitor_and_ban | while read -r action ip; do
      case "$action" in
        BAN)
          ban_ip "$ip" "$PENALTY" "threshold/${THRESHOLD}@${WINDOW}s"
          ;;
        BAN24)
          ban_ip "$ip" "$GLOBAL_PENALTY" "global>${GLOBAL_THRESHOLD}@${GLOBAL_WINDOW}s"
          ;;
      esac
  done
}

main
