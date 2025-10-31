# luci-app-authshield

**Multi-service login intrusion prevention for OpenWrt (LuCI + Dropbear)**  
Author: **iv7777 <hongba@rocketmail.com>**  
Version: **1.16**  
Date: **2025-10-30**  
License: **MIT**

---

## 📦 Overview

**AuthShield** enhances OpenWrt’s security by automatically banning IPs that repeatedly fail login attempts within a short window — covering both **LuCI web interface** and **Dropbear SSH**.

- Works without modifying LuCI itself.
- Lightweight: pure shell + nftables.
- Auto-unbans IPs after timeout.
- Supports IPv4 and IPv6.
- Optional: ignore private IPs (LAN, loopback, link-local).

---

## ⚙️ Default Configuration

| Option | Default | Description |
|--------|----------|-------------|
| `enabled` | 1 | Enable or disable AuthShield |
| `threshold` | 5 | Number of failed attempts before ban |
| `window` | 10 | Time window (seconds) to count failures |
| `penalty` | 60 | Ban duration (seconds) |
| `ports` | 80 443 | Protected ports |
| `watch_dropbear` | 0 | Also monitor SSH login failures |
| `ignore_private_ip` | 1 | Skip bans for private/local IPs |

Configuration file: `/etc/config/authshield`

---

## 🧩 LuCI Web UI

Menu path: **System → AuthShield**  

Displays the following options:

- Enable / Disable
- Failures (threshold)
- Window (seconds)
- Penalty (seconds)
- Protected ports
- Also watch Dropbear bad passwords
- Ignore private IP ranges

---

## 🔧 Installation

### 1. Copy manually
```bash
# Copy contents to router
scp -r root/ root@router:/
scp -r luasrc/ root@router:/usr/lib/lua/
scp -r po/ root@router:/usr/lib/lua/luci/i18n/

# Apply setup
ssh root@router '/etc/uci-defaults/99-authshield-setup'
```

### 2. Build with OpenWrt SDK
Copy this folder into `package/feeds/luci/` and build with:
```bash
make package/luci-app-authshield/compile V=s
```

---

## 🧠 Verification

To see current banned IPs:
```bash
nft list element inet fw4 authshield_penalty_v4
nft list element inet fw4 authshield_penalty_v6
```

To check service status:
```bash
/etc/init.d/authshield status
```

To reload firewall rules:
```bash
/etc/init.d/firewall reload
```

---

## 🌐 Translation

Simplified Chinese (简体中文) translation is included:  
`po/zh_Hans/luci-app-authshield.po`

LuCI will automatically display the Chinese interface if your browser locale is Simplified Chinese.

---

## 🧱 Notes

- `logread -f` is used for efficient, non-blocking live log monitoring.
- Works with both `rpcd` and `uhttpd` authentication logs.
- Does **not** interfere with normal LuCI sessions.
- Ideal for snapshot or modern OpenWrt builds with nftables.

---

## 📜 License

This project is licensed under the MIT License.  
© 2025 iv7777 <hongba@rocketmail.com>

