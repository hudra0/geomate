# Geomate - Geographic Game Server Filter for OpenWrt

Geomate is an OpenWrt application that enables you to control connections to game servers based on their geographic location. By drawing regions on a map, you can specify where you want to allow or block server connections. The application learns over time by collecting IP addresses of game servers you connect to, making the filtering more effective the more you play.

![Geomate 3](https://github.com/user-attachments/assets/041934b4-446f-4c88-b62e-cd2a378c231f)

## Features

- 🌍 **Geographic Filtering**: Draw regions on a map to allow or block game server connections
- 🎮 **Game-Specific Filters**: Create separate filters for different games
- 📝 **Dynamic Learning**: Automatically learns and tracks game server IPs while you play
- 🔍 **Server Detection**: Builds comprehensive IP lists through actual gameplay
- ⚡ **Strict Mode**: Advanced control over untracked connections
- ⭐ **Whitelisting**: Ensure essential servers are always accessible

## Table of Contents

- [Prerequisites](#prerequisites)
- [How Does It Work?](#how-does-it-work)
- [Installation](#installation)
- [Post-Installation Steps](#post-installation-steps)
- [Configuration Options](#configuration-options)
- [Quick Start Guide](#quick-start-guide)
- [Using the Map](#using-the-map)
- [Detailed Configuration](#detailed-configuration)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Hardware Requirements](#hardware-requirements)
- [Backup and Updates](#backup-and-updates)
- [Uninstallation](#uninstallation)
- [Support](#support)
- [Important Notes and Expectations](#important-notes-and-expectations)

## Development Status
Geomate is under active development. Feedback on functionality, usability, and any issues is highly appreciated.

## Prerequisites

1. OpenWrt 23.05 or newer (the map is written for LuCI 23.05 and newer; it has been tested on LuCI 26.036 only)
2. 5MB free disk space
   - Note: Geomate's operations (monitoring, geolocation queries, filtering) can be resource-intensive
   - Multiple active filters require more system resources
   - Monitor system resources to prevent router overload
   - Low-end hardware may experience performance limitations
3. Active internet connection for geolocation services

## How Does It Work?

- **Dynamic Learning**: Monitors your game connections and collects server IP addresses
- **Geolocation**: Queries online API to get geographical coordinates of collected IPs
  - Note: IP geolocation is not always 100% accurate
  - While IP addresses can change locations, gaming servers typically maintain stable IPs
  - This makes the approach particularly effective for gaming applications
- **Filtering Rules**: Applies rules based on your defined map regions
- **Whitelisting**: Allows essential servers regardless of location
- **Blacklisting**: Blocks single servers, also inside a region; the whitelist wins
- **Strict Mode**: Controls how untracked connections are handled

## Installation

Tip: You can copy all commands from each section at once and paste them into your terminal.

### 1. Installing Geomate Core

```bash
# Get latest release tag and install Geomate Core
LATEST_TAG=$(uclient-fetch -O - https://api.github.com/repos/hudra0/geomate/releases/latest 2>/dev/null | grep -o '"tag_name":"[^"]*' | sed 's/"tag_name":"//') && \
# Detect package manager and install required dependencies
if command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
    $PKG_MANAGER add curl jq
elif command -v opkg >/dev/null 2>&1; then
    PKG_MANAGER="opkg"
    $PKG_MANAGER update && $PKG_MANAGER install curl jq
else
    echo "Error: No supported package manager found (apk/opkg)"
    exit 1
fi && \
mkdir -p /etc/geomate.d && \
# Download server lists
for file in $(curl -s https://api.github.com/repos/hudra0/geomate/contents/files/etc/geomate.d?ref=$LATEST_TAG | jq -r '.[].name'); do
    uclient-fetch -O "/etc/geomate.d/$file" "https://raw.githubusercontent.com/hudra0/geomate/$LATEST_TAG/files/etc/geomate.d/$file"
done && \
# Download and install core files
uclient-fetch -O /etc/init.d/geomate https://raw.githubusercontent.com/hudra0/geomate/$LATEST_TAG/files/etc/init.d/geomate && \
uclient-fetch -O /etc/geomate.sh https://raw.githubusercontent.com/hudra0/geomate/$LATEST_TAG/files/etc/geomate.sh && \
uclient-fetch -O /etc/geomate_trigger.sh https://raw.githubusercontent.com/hudra0/geomate/$LATEST_TAG/files/etc/geomate_trigger.sh && \
uclient-fetch -O /etc/geolocate.sh https://raw.githubusercontent.com/hudra0/geomate/$LATEST_TAG/files/etc/geolocate.sh && \
chmod +x /etc/init.d/geomate /etc/geomate.sh /etc/geomate_trigger.sh /etc/geolocate.sh && \
[ ! -f /etc/config/geomate ] && uclient-fetch -O /etc/config/geomate https://raw.githubusercontent.com/hudra0/geomate/$LATEST_TAG/files/etc/config/geomate; \
# Enable and start service with a small delay
/etc/init.d/geomate enable && \
sleep 2 && \
/etc/init.d/geomate start && \
echo "Geomate service installation complete!"
```

### 2. Installing the LuCI Web Interface

```bash
# Get latest release tag and install LuCI Web Interface
LATEST_TAG=$(uclient-fetch -O - https://api.github.com/repos/hudra0/luci-app-geomate/releases/latest 2>/dev/null | grep -o '"tag_name":"[^"]*' | sed 's/"tag_name":"//') && \
# Detect package manager and install required dependencies
if command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
    $PKG_MANAGER add lua luci-lua-runtime
elif command -v opkg >/dev/null 2>&1; then
    PKG_MANAGER="opkg"
    $PKG_MANAGER update && $PKG_MANAGER install lua luci-lua-runtime
else
    echo "Error: No supported package manager found (apk/opkg)"
    exit 1
fi && \
mkdir -p /www/luci-static/resources/view/geomate /usr/share/luci/menu.d /usr/share/rpcd/acl.d /usr/libexec/rpcd && \
uclient-fetch -O /www/luci-static/resources/view/geomate/view.js https://raw.githubusercontent.com/hudra0/luci-app-geomate/$LATEST_TAG/htdocs/luci-static/resources/view/geomate/view.js && \
uclient-fetch -O /www/luci-static/resources/view/geomate/geofilters.js https://raw.githubusercontent.com/hudra0/luci-app-geomate/$LATEST_TAG/htdocs/luci-static/resources/view/geomate/geofilters.js && \
uclient-fetch -O /www/luci-static/resources/view/geomate/map.html https://raw.githubusercontent.com/hudra0/luci-app-geomate/$LATEST_TAG/htdocs/luci-static/resources/view/geomate/map.html && \
uclient-fetch -O /usr/share/luci/menu.d/luci-app-geomate.json https://raw.githubusercontent.com/hudra0/luci-app-geomate/$LATEST_TAG/root/usr/share/luci/menu.d/luci-app-geomate.json && \
uclient-fetch -O /usr/share/rpcd/acl.d/luci-app-geomate.json https://raw.githubusercontent.com/hudra0/luci-app-geomate/$LATEST_TAG/root/usr/share/rpcd/acl.d/luci-app-geomate.json && \
uclient-fetch -O /usr/libexec/rpcd/luci.geomate https://raw.githubusercontent.com/hudra0/luci-app-geomate/$LATEST_TAG/root/usr/libexec/rpcd/luci.geomate && \
chmod +x /usr/libexec/rpcd/luci.geomate && \
/etc/init.d/rpcd restart && \
/etc/init.d/uhttpd restart
```

### Post-Installation Steps

After installing Geomate and the LuCI interface:

1. **Initialize Geolocation Data**
   ```bash
   /etc/geolocate.sh
   ```
   This fetches coordinate data for any default IP lists (e.g., `/etc/geomate.d/cod_servers.txt`).
   Without this step, Geomate may not filter accurately until the next scheduled update.

2. **Verify Installation**
   - Check if Geomate service is running
   - Access LuCI interface
   - Review initial configuration

3. **Prepare for First Use**
   - Keep Strict Mode disabled initially
   - Have your gaming device IP ready
   - Know your game's ports (or prepare to use QoSmate)

## Configuration Options

| Option | Description | Values | Default |
|--------|-------------|---------|---------|
| enabled | Enable/disable Geomate service | 0 (disabled), 1 (enabled) | 1 |
| debug_level | Control logging verbosity | 0 (minimal), 1 (normal), 2 (verbose) | 0 |
| strict_mode | Control how untracked connections are handled | 0 (allow untracked), 1 (block untracked) | 0 |
| operational_mode | How IP lists are managed | 'dynamic' (automatic learning), 'static' (predefined lists) | 'dynamic' |
| geolocation_mode | Frequency of IP geolocation updates | 'frequent' (check interval to twice that interval), 'daily' (once per day) | 'frequent' |
| check_interval | Seconds between collection cycles in Dynamic and Monitor Mode; also the minimum interval for frequent geolocation. The scheduler backs off to twice this value when there are no new IPs. Static Mode keeps its hourly loop and 30-60 minute scheduler | 300-3600 seconds | 1800 |

### Per-Filter Options

| Option | Description | Values | Default |
|--------|-------------|---------|---------|
| protocol | Protocol of the game traffic. The web interface offers TCP and UDP and always saves one. Written with uci or by hand, it can also be `udplite`, `sctp`, `dccp`, `icmp`, `igmp`, `esp`, `ah`, `comp`, `gre` or a protocol number, or several of them separated by spaces (`tcp udp`). Without ports the filter matches all traffic of the protocol from its Source IP, which then has to name devices. Ports without a protocol match TCP and UDP; without protocol and ports the filter matches all traffic from its Source IP. Any other value, such as nft's own `meta l4proto udp`, goes to nft unchanged, as in older versions | `tcp`, `udp` | none |
| src_ip | Source IP: the devices the filter applies to. One IPv4 address, a subnet (`192.168.1.0/24`) or a range (`192.168.1.10-192.168.1.20`), or several of them separated by spaces (a `list src_ip` works too). `!` or `!=` before an entry leaves it out: `192.168.1.0/24 !192.168.1.5`. Several entries and `!` need a backend whose `/etc/geomate.sh capabilities` prints `src_ip_multi`. A value in any other form, such as nft's own `!= 192.168.1.5` or `{ 192.168.1.5, 192.168.1.6 }`, goes to nft unchanged, as in older versions, if it passes the character check below. If nft rejects the value, the filter gets no rules at all and shows "nftables error" | IPv4 entries | empty (all devices) |
| src_port | Source Port: the port of the game on the device. One port, a range (`27015-27020`) or several separated by spaces. Empty or `any`: every port. Without `dest_port` too, the filter matches all traffic of its protocol (see `protocol`) | Ports | empty (all ports) |
| dest_port | Destination Port: the port of the game on the server, in the same forms as `src_port` | Ports | empty (all ports) |
| ip_list | Path of the IP list file (e.g. `/etc/geomate.d/cod_servers.txt`). Required for geographic filtering: its entries are geolocated in every mode; dynamic and monitor mode also collect new server IPs into it, static mode only uses what it contains. Without it the filter geolocates no IPs and relies on `allowed_ip` entries. Write an absolute path without a space at the start or end: the service uses the path exactly as written and creates a missing file under that name, so a trailing space gives the filter a new, empty list | File path | none |
| ip_expiry_days | Automatically remove IPs not seen for this many days | 0 (disabled), or number of days | 0 |
| allowed_ip | Allowed IPs, the whitelist (`list allowed_ip`): servers the filter always allows, wherever they are (see [Allowed IPs Explained](#allowed-ips-explained)). The Allowed IPs field of the web interface accepts IPv4 addresses and subnets (`185.34.107.0/24`), several per entry separated by spaces. Written with uci or by hand in `/etc/config/geomate`, an entry can also be a range (`185.34.107.128-185.34.107.129`) or a host name, and several in one entry can be separated by commas too. A host name is resolved by nft at every start and live reload; a name without a dot only as an entry of its own. A subnet or range may contain geolocated servers: they stay allowed through the entry. If a host name does not resolve, nft rejects all allowed IP entries of the filter, which shows "nftables error"; geolocated servers inside its subnets and ranges then stay allowed only if they are inside a circle, as with an older backend. An entry that lies inside another one is skipped, and partly overlapping ranges are merged into one. Anything else, such as `!1.2.3.4` or a mask like `1.2.3.0/255.255.255.0`, is skipped and logged, and the filter shows "nftables error"; its other entries still apply. That includes an address with a leading zero, such as `010.0.0.1`: nft reads such an octet as octal, so an older backend allowed 8.0.0.1 instead | IPv4 entries | none |
| blocked_ip | Blocked IPs, the blacklist (`list blocked_ip`): servers the filter always blocks, also inside its circles (see [Blocked IPs Explained](#blocked-ips-explained)). Allowed IPs win: a server that both lists cover is allowed. The entries take the same forms as `allowed_ip` and get the same checks: addresses, subnets and ranges, several per entry separated by spaces or commas, and host names. A host name does not block a geolocated server inside a circle. A skipped entry, or a host name that does not resolve, shows "nftables error" as for `allowed_ip`; if nft rejects the list, it blocks no server: servers in it are then blocked only when they are geolocated outside every circle, or by Strict Mode. The older comma-separated `option blocked_ips` still works and adds its entries to the list (see below). Needs a backend whose `/etc/geomate.sh capabilities` prints `blocked_ip`. An older backend ignores the list | IPv4 entries | none |

Source IP: several entries separated by spaces and `!` directly before an entry are new. An older backend could not build rules from a value in this form: the filter did nothing and showed "nftables error". After the update the same value filters, and with Strict Mode on it also drops. A value with exceptions only, such as `!192.168.1.5`, applies to every other address, like an empty field: it also matches packets that come in from the internet. Geomate logs "Source IP of <filter> has exceptions only" at every start for such a filter. Going back to an older backend turns these filters off again, with an nftables error.

Blocked IPs: `list blocked_ip` is new. An older backend read only the undocumented `option blocked_ips` and added its entries to the blocked set. A server inside a circle stayed allowed, because the allowed set is checked first. Now `option blocked_ips` works like `list blocked_ip`: its servers are blocked inside the circles too, unless the Allowed IPs cover them. Check a filter with this option after the update. A change of `list blocked_ip` is applied without a restart, a change of `option blocked_ips` restarts Geomate (see [How Changes Take Effect](#how-changes-take-effect)). The web interface writes only the list. Going back to an older backend ignores the list again.

Protocol and ports: an older backend built no rules for a filter with a protocol but no port (such as UDP from the web interface with both port fields empty), with ports but no protocol, or with several protocols: the filter did nothing and showed "nftables error". Now such a filter matches as described under `protocol`. Without ports it matches every server the device reaches over that protocol, not only game servers: dynamic and monitor mode collect all of them into the IP list, the geolocation then blocks those outside the regions (DNS resolvers, CDNs) for the device too, and with Strict Mode on the device's other traffic of that protocol to servers outside the allowed ones is dropped. Geomate logs "Filter <filter> has no ports" at every start for such a filter. Set the game's ports where they are known. A filter without ports whose Source IP is empty or has exceptions only still gets no rules and shows "nftables error", with "no ports and no device in Source IP" in the system log: it would match the protocol for every device and also the replies of the servers, so with Strict Mode on it would drop all traffic of that protocol in the network. Going back to an older backend turns these filters off again, with an nftables error.

Characters: Geomate checks the filter name, `protocol`, `src_ip`, `src_port` and `dest_port` before they reach nft. An older backend passed them on unchecked, and a `;` in any of them could run an nft command of its own, such as one that deletes the rules of the firewall.
- The name may contain letters, digits, spaces, `_`, `.` and `-`, as the map dialog and the Geo Filters page require. Geomate skips a filter with an empty name or any other character in its name: no sets, no rules, an error in the system log and in `/tmp/geomate_nft_errors.log`. An older backend failed on most such names with nftables errors too; it built the filter only for an empty name or a name with `/`.
- Protocol, Source IP and the ports may contain letters, digits, spaces and `. , : / _ - ! = < > & | ^ { } @`, the characters of the forms nft accepts there. A value with any other character, such as `;`, `#`, a quote or a line break, gives the filter no rules, logs an error and shows "nftables error".

## Quick Start Guide

1. **Access the Web Interface**
   - Navigate to Services > Geomate in LuCI

2. **Draw Your Region**
   - Go to the "View" tab
   - Click "Draw circle" in the map toolbar and choose "New filter…" in the menu
   - Click on the map and drag to draw where you want to allow game connections
   - A dialog opens: name your filter (e.g., "Call of Duty"). More circles, editing and deleting are described in [Using the Map](#using-the-map)

3. **Configure Your Filter**
   - The dialog after drawing has the same options as the "Geo Filters" page, except the region list. The most important ones:
   - Protocol: Usually UDP for games
   - Source IP: Your console/PC IP (e.g., 192.168.1.208). Pick it from the suggested devices or type it, and give the device a static lease so the address stays the same. Several devices are separated by spaces, and `!` leaves one out (see `src_ip` in [Per-Filter Options](#per-filter-options) and [Geo Filters Page](#geo-filters-page))
   - Source Port / Destination Port: Use known values (e.g., 3074 for CoD) or see [Finding Game Ports and Protocols](#finding-game-ports-and-protocols)
   - Allowed IPs: Essential IPs for matchmaking/authentication, the whitelist (see [Allowed IPs Explained](#allowed-ips-explained))
   - IP List File: Either use an existing list or create an empty one (see [Understanding IP Lists](#understanding-ip-lists-and-allowed-ips))
   - Enable and IP Expiry (Days) can stay at their defaults

4. **Save & Let Geomate Learn**
   - Click "Save" in the dialog. The filter is applied at once, without Save & Apply: Geomate restarts, and the map shows "Applied." with an Undo button (see [How Changes Take Effect](#how-changes-take-effect))
   - Start with Dynamic or Monitor Mode to begin collecting server IPs
   - Play several matches to allow Geomate to collect and geolocate server IPs
   - The map will populate as IPs are discovered and geolocated
   - Started in Monitor Mode? Check your circles against the markers and the connections table. When they fit, switch to Dynamic Mode with the mode pill in the status row above the map (see [Changing the Mode](#changing-the-mode))
   - Keep Strict Mode disabled until you've built a comprehensive IP list

![GeomateAdd](https://github.com/user-attachments/assets/ffdd5da0-d8d6-4b88-af53-5da055d57138)

*The animation shows an older version of the map; the steps above describe the current one.*

## Using the Map

The **View** tab (Services > Geomate) shows the service status, the map and, below it, the table of active connections. Regions are circles. The **Geo Filters** tab lists all filters (see [Geo Filters Page](#geo-filters-page)).

The status row above the map shows a **Running** / **Not running** pill ("Status unknown" when the router does not answer), a pill with the operational mode (Dynamic mode, Static mode or Monitor mode; with write access it is a menu, see [Changing the Mode](#changing-the-mode)), a summary of the health checks ("All checks passed", or the names of the checks with an error, else those with a warning), "Loading GeoFilter data ..." while the service loads its data, the installed backend and frontend versions and the update state ("Up to date", "Update available", "Backend update available", "Frontend update available" or "Update check failed"). On narrow screens the row wraps and leaves out the versions and the update state. The status refreshes every 10 seconds while the tab is visible and every 5 minutes in the background. It refreshes at once when you return.

**Details** opens a panel with the service state and its PID, what the mode does, each check with its message (Config, Files, Data, Autostart, nftables, nft errors; ✓ ok, ○ note, ⚠ warning, ✗ error), both versions with their update channel, the update state and a **Check again** button. The panel opens by itself when a problem shows on two regular status refreshes in a row. A problem is a stopped service while Geomate is enabled, or a check with a warning or an error. If you close the panel, it stays closed until a new problem appears. It never closes by itself.

The update check runs when the page opens and then every hour. GitHub allows 60 unauthenticated requests per hour and IP address, so the browser keeps the result for an hour (10 minutes after a failure) and the page reuses it until then. **Check again** asks GitHub right away and also skips the router's own 10-minute cache.

After an update of the backend or the web interface, the status row checks for updates once more, so the update state does not keep showing the old result. If the page still runs an older version of the web interface, the status row shows "The web interface was updated. Reload the page." Click **Reload the page** to load the new version past the browser cache.

A LuCI login with read-only access to Geomate still sees the status and the update state. It can no longer start or stop Geomate or run the init script. Those actions need write access.

### Changing the Mode

With write access, the mode pill in the status row is a button with a ▾. It opens a menu with **Dynamic mode**, **Static mode** and **Monitor mode**, each with a one-line description. A check mark shows the mode of the saved configuration, which Geomate runs in once it has restarted. Pick an entry with the mouse, or use the arrow keys, Home, End and Enter. **Esc**, **Tab** or a click outside closes the menu. Without write access the pill is plain text.

The usual path: set up the circles in Monitor mode, check them against the markers and the Status column of the connections table, then switch to Dynamic mode here.

- The switch is applied at once, without Save & Apply: the map writes `operational_mode` to `/etc/config/geomate` and shows "Switched to Dynamic mode. Geomate restarts." with an **Undo** button for 10 seconds. A mode change restarts Geomate like any option other than circles, allowed and blocked IPs (see [How Changes Take Effect](#how-changes-take-effect)). Until it has restarted, for 60 seconds at most, the status row shows "Loading GeoFilter data ...".
- Switching from Monitor mode to Dynamic or Static mode asks first, because Geomate then starts to block. The dialog says "Geomate will block servers outside your regions." With Strict Mode on it adds "Strict mode also blocks servers that are not geolocated yet." The buttons are **Cancel** and **Switch to Dynamic mode** (or **Switch to Static mode**). Every other switch asks nothing.
- Undo writes the previous mode back and restarts Geomate again. Like every map change, it undoes the last change only.
- If Geomate is disabled in the global settings, the mode is saved and the map says "Saved. Geomate is not running." The switch does not start it. If Geomate is enabled but not running, the map says only "Switched to Dynamic mode.": the reload may start it or not.
- With unsaved Geomate changes in your LuCI session, the switch is refused, as described in [How Changes Take Effect](#how-changes-take-effect).

### How Changes Take Effect

The map applies every change at once: a new, moved, resized or deleted circle, a new filter, the Enable button in the message after drawing, the Allow, Remove, Block and Unblock buttons of the connections table and the mode menu of the status row. The View tab has no Save & Apply and no buttons in its footer. Each change is written to `/etc/config/geomate`, and Geomate picks it up right away. Only the Geomate configuration is committed. Unsaved changes of other configurations stay as they are.

- After each change the map shows "Applied." with an **Undo** button for 10 seconds. Allow and Remove show "Added … to the allowed IPs of …" or "Removed … from the allowed IPs of …" instead, Block and Unblock "Blocked … in …" or "Unblocked … in …", and the mode menu "Switched to …". Undo writes back the values the change replaced and applies that. It works for the last change only, and not when the filter (for a mode switch: the mode) was changed since. Undoing the creation of a filter deletes the filter.
- A change of circles, allowed IPs or blocked IPs (`list blocked_ip`) only: Geomate refills the allowed and blocked sets of the changed filter in place, without a restart. The rules, the counters and the IPs collected since the last save stay. Changing the circles, allowed or blocked IPs of a disabled filter needs nothing at all.
- Any other change (a new filter, Enable, any other option) restarts Geomate. It rebuilds all nftables rules, and filtering is bypassed for a short time. The IPs collected so far are saved to the IP lists before every stop.
- A change of circles, allowed or blocked IPs restarts Geomate too when a start has not finished yet, when the last start had nftables errors (an invalid Source IP counts as one), or when the names of two enabled filters differ only in spaces and underscores. If the run loop has stopped, for example after repeated crashes, every change restarts Geomate and so starts it again.
- An allowed or blocked IP entry that is not an IPv4 address, subnet, range or host name is skipped, on a live reload and at start; the other entries apply. The filter shows "nftables error" until the entry is fixed, so the next change of circles, allowed or blocked IPs restarts Geomate. Allowed IP subnets and ranges may contain geolocated servers. An older backend failed on such an overlap: up to 1000 geolocated servers were missing from the filter's sets, without an nftables error, and every live reload restarted Geomate.
- Geomate also compares the configuration file without its region, allowed IP and blocked IP lists with the file it started from. The first change of circles, allowed or blocked IPs after a hand edit of `/etc/config/geomate` therefore usually restarts Geomate once, because uci rewrites the whole file in its own format. The same happens on the first circle change of a filter whose regions are written as `option allowed_region` instead of `list allowed_region`, and on the first allowed or blocked IP change of a filter with `option allowed_ip` or `option blocked_ip` instead of the list. Geomate reads regions, allowed and blocked IPs only as lists: at start, on a live reload and when it collects new IPs, it ignores a hand-written `option allowed_region`, `option allowed_ip` or `option blocked_ip`. The older `option blocked_ips` (with "s") is read as before. The first save of a filter's edit dialog on the Geo Filters page can also restart Geomate once, when it fills in a missing default such as IP Expiry (Days).
- An older backend restarts Geomate for allowed IP changes too, and an even older one for every change, circles included. A backend without `blocked_ip` (see Backend Capabilities under [Debug and Monitoring Tools](#debug-and-monitoring-tools)) restarts Geomate for a blocked IP change and then ignores the list. `/etc/init.d/geomate update` updates backend and web interface together.
- If your LuCI session holds unsaved Geomate changes, for example from the Geo Filters page, the map refuses every change: a new circle disappears, an edit goes back, and the map says "Apply or revert the unsaved geomate changes first." Applying would also apply those changes unseen. The page shows the notice "Apply or revert the unsaved geomate changes before you change the map." with a **Show changes** button, which opens LuCI's Unsaved Changes dialog, where you apply or revert them. The notice also shows when you open the View tab with unsaved Geomate changes. Allow, Remove, Block, Unblock and the mode menu are refused the same way and show the same notice (the mode menu's ends "before you change the mode.").
- If a change cannot be applied, for example because the filters were changed in another browser tab, the map says so and shows the stored configuration again.
- Without write access to the Geomate configuration, the map only shows the circles: **Draw circle** is hidden and circles cannot be selected. The mode pill is plain text, and the connections table has no Allow, Remove, Block and Unblock buttons. The server button of the legend still works.
- Exception: **Upload IP List** in the new-filter dialog writes the list file to the router at once, before you click Save (it asks before it replaces an existing file). Cancel and Undo do not remove an uploaded file. **Create Empty List** only fills in the path. Geomate creates a missing file when it starts, and a new filter restarts it.

### Drawing a Circle

1. Click **Draw circle** in the map toolbar. The menu **Draw a circle for** lists your filters, each with its color, and **New filter…**. Disabled filters are marked "Disabled".
2. Pick an entry, then drag on the map. The bar on top says "Drag on the map to draw a circle for …" and shows the radius, which also shows next to the cursor. **Esc** or **Cancel** stops drawing. A click without a drag draws nothing: the map says "Drag to draw a circle." and you can drag again.
3. Existing filter: the circle is applied at once, without a dialog. For a disabled filter the message says "Applied. Filter … is disabled." and has an **Enable** button next to Undo. Drawing never enables a filter, and a disabled filter filters nothing. Enable is applied at once and restarts Geomate.
4. New filter: a dialog asks for the filter name and the filter options (Enable, Protocol, Source IP, Source Port, Destination Port, Allowed IPs, IP Expiry (Days), IP List File). The name may contain letters, digits, spaces, `_`, `.` and `-`. **Save** creates the filter and applies it at once. **Cancel** removes the circle. The list **Filter** at the top of the dialog can switch to an existing filter, and a name that matches an existing filter adds the circle to it. Names match ignoring case and with a space counting as `_` (a space and `_` give the same nftables sets), so "call_of_duty" adds the circle to "Call of Duty" instead of creating a second filter. The **Geo Filters** link under "More options" opens that page; when an existing filter is chosen, it opens that filter's edit dialog, which has the same options plus the name and the region list.

Each filter has a color of its own; with more than eight filters the colors repeat. The label of a circle shows the filter name. The selected circle has no label, and a small circle shows it only while the pointer is over it. A disabled filter is drawn faded. A dashed circle waits for its change to be applied. The legend shows the three states: Enabled, Disabled and Selected.

### Editing and Deleting a Circle

- Click a circle to select it. Only one circle is selected at a time, and selecting another keeps the changes of the first, like Done. Where circles overlap, the click selects the smallest one; click again at the same spot to select the next larger one. A small circle is zoomed in first so that the handles fit.
- Drag the **centre handle** to move the circle and the **edge handle** to resize it. A thin dashed ghost shows the old size, and the radius shows live next to the edge handle.
- Or type the radius in km in the bar at the bottom of the map, which also shows the filter and the centre. The circle follows at once, and Enter works like Done. The radius can be 0.001 to 20000 km.
- **Done** (or a click on the empty map) applies the change. **Cancel** or **Esc** restores the circle as it was.
- **Delete** asks "Delete circle?". **Yes** applies the deletion, **No** keeps the circle, and the question goes away by itself after 5 seconds. Deleting one circle never deletes the filter.
- The last circle of a filter opens the dialog "Delete the last circle of …?". For an enabled filter, **Delete and disable** is preselected; the other choices are **Delete** (the filter stays enabled) and **Cancel**. A filter without a region puts no geolocated IP into its allowed or blocked set. With Strict Mode on (and not in Monitor Mode), an enabled filter without a region therefore blocks every server except its allowed IPs; the dialog says which case applies. For a disabled filter, the dialog only asks to confirm.
- While a changed circle is selected, **Draw circle** asks you to click Done or Cancel first.

### Known Servers

Each filter in the legend has a server button, next to the eye and the magnifier. Its tooltip reads "Show known servers of …" or "Hide known servers of …". It draws the servers from the filter's geo data file (`/etc/geomate.d/<filter name>_geo_data.json`) as dots in the filter's color, so you see where the servers of a game are while you draw a circle. The legend lists the dot as "Known servers (bigger: more)".

- A dot is one position. Its size follows the number of servers there: a radius of 3 px for one server, 2 px more for every factor of 10, 12 px at most.
- The dots take no clicks and lie below the circles. A click goes through them to the circle or the map below.
- The button works without a circle and without write access. The first click loads the positions from the router, and the map keeps them for 5 minutes. While the dots are shown, the legend adds the number of servers to the filter's line, for example "2 circles · 12,843 servers".
- A filter without geolocated servers gets the note "No known servers for … yet." and the dots go off. If the positions cannot be loaded, a notification above the map says so once per filter, with the error: "Could not load the known servers of …: …". Later clicks show "Could not load the known servers of …." in the map. The legend line says "servers unknown". The map never turns a failure into "0 servers".
- Positions come from the rpcd method `getKnownServers` of the web interface. It only reads the geo data file and keeps a cache in `/tmp`. After an update of the web interface, an open LuCI session may not be allowed to call it yet: the notification then ends "Log in again after an update of the web interface." Log in to LuCI again.
- When the web interface does not answer within 60 seconds, the map shows "Could not load the known servers. Reload the page."

While a circle is selected, the bar at the bottom of the map shows a counter, "1,284 in circle · 9,876 / 12,843 in this filter". The first number counts the known servers inside the selected circle. The second counts those inside any circle of the filter, which is what the filter allows by position, and the third is all known servers of the filter. Allowed IPs are not part of it. The counter follows while you drag, resize or type a radius, and it loads the positions itself when the dots are off. Before the numbers are there, it says "Counting known servers…", "No known servers yet" or "Known servers unknown". Distances use the Haversine formula with the Earth radius of 6371000 m, like the backend.

With more than 3000 different positions, the positions are merged and rounded: first to 2 decimals of a degree, then to 1 and 0 while there are still more than 3000. The counter then has a tooltip, "Positions rounded to about 1 km" (10 km or 100 km for the coarser steps), and a server near the edge of a circle can be counted on the wrong side.

### Map Controls

| Control | What it does |
|---------|--------------|
| Fit all | Zoom to all circles, except those hidden with the eye in the legend. Without circles the map says "No circles yet." |
| Home | Go to your home view. Without a saved home view, zoom to all circles |
| Set home | Save the current view (centre and zoom) as the home view. The map says "Home view saved." |
| Fullscreen | Show the map in the whole window; Esc or the same button leaves it |
| Legend | Lists the filters with their circle count, then the circle states (Enabled, Disabled, Selected) and the connection markers (Allowed, Blocked, Whitelisted, and the clusters Several allowed, Several blocked, Several whitelisted and Mixed). The eye hides or shows the circles of a filter, the magnifier zooms to them, the server button shows its known servers (see [Known Servers](#known-servers)). The switch **Dark map tiles** dims the map; it is off by default |

The map opens at your home view if you saved one, otherwise it shows all circles. The link **Show on map** on the Geo Filters page opens it at the circles of that filter instead. Without circles and without a home view the map shows a default view over Europe.

The legend is closed by default on phones and when the map is narrower than 900 px, until you open or close it yourself. It also closes while you draw or edit a circle. The legend state, the dark tiles switch and the home view are stored in your browser, not on the router. The map follows the light or dark theme of LuCI. On a map narrower than 640 px the toolbar shows icons only. On a phone the buttons are larger and the map takes 60% of the screen height.

### Active Connections

Below the map, the **Active connections (n)** bar shows or hides the table. Click anywhere on the bar; its right end reads **Show** or **Hide**. The table stays hidden until you open it, and on wide screens the map gets shorter while it is shown. It lists every server that an enabled filter has seen traffic to in the last 10 seconds, and for 30 minutes after that (see **Last seen** below), whether Geomate knows its position or not. The columns are IP, Filter, Status, Country, City, ISP, Last seen and Traffic, and with write access a last one without a title for the Allow, Block, Remove and Unblock buttons. Private addresses and the router's own addresses are left out. The n in the bar counts the servers of the last refresh. Click a column header to sort. Until you pick a sort, the table is sorted by Traffic, highest rate first. LuCI keeps a sort you pick until you log out or close the browser tab. The data refreshes every 5 seconds while the tab is visible and pauses in a background tab. If it fails several times in a row, the status row above the map says "Connections not updated since …" or "Connections unavailable".

The **Search** field above the table shows only the rows whose IP, filter, country name or code, city or ISP contain the typed text, upper or lower case alike. Past rows are searched too. The text stays over the refreshes, and the n in the bar still counts every server of the last refresh. When no row matches, the table says "No matching connections". An empty field shows all rows.

The Status column shows what the filter's nftables sets say about the server:

| Status | Meaning |
|--------|---------|
| Whitelisted | The server is in the Allowed IPs of the filter in the Filter column, as an address of its own or inside a subnet or range. Allowed IPs of another filter do not count |
| Allowed | The server was geolocated inside a circle of the filter |
| Blocked | The server was geolocated outside every circle of the filter. In Monitor mode nothing is blocked: the status shows what the filter would do |
| Blacklisted | The server is in the Blocked IPs of the filter in the Filter column (see [Blocked IPs Explained](#blocked-ips-explained)), as an address of its own or inside a subnet or range, and the filter's blocked set has it. It is blocked wherever it is, also inside a circle. Whitelisted wins. In Monitor mode nothing is blocked. The tooltip names the filter: "In the blocked IPs of Call of Duty." |
| Untracked | The server is in neither set: it is not geolocated yet, or the filter has no circle. Strict Mode (outside Monitor mode) blocks it, otherwise it passes. The tooltip says which case applies and when the next geolocation update can place it, for example "Not geolocated yet. Strict mode blocks it. Geolocated with one of the next automatic updates." See [Geolocation Updates](#geolocation-updates). Static mode adds no new servers to the IP list |
| Unknown | The row has no verdict: it was restored after you left the page and has no stored status, for example from an older version of the page ("Seen before the page was loaded."), or you removed the address from the Allowed IPs or the Blocked IPs after the server was last seen ("Removed from the allowed IPs since last seen.", "Removed from the blocked IPs since last seen.") |

A Whitelisted, Blacklisted, Allowed or Blocked server without a known position, for example one that only the Allowed IPs cover, has the tooltip "Not on the map until geolocated." In Static mode it reads "Not on the map: static mode does not geolocate new servers."

Country, city and ISP come from the geolocation data of the filter. They show "–" when no data is known for an IP yet, and after an update from an older version until the next service start or geolocation batch refreshes the lookup cache. A connection with a known position also gets a marker on the map: green for Allowed, red for Blocked and Blacklisted, blue for Whitelisted. Markers close together form a cluster with a count: green if all are allowed, red if all are blocked, blue if all are whitelisted, orange if mixed. Click a marker for the IP, status, filter, country, city and ISP (and the organization, when it differs from the ISP). An untracked server has no marker.

**Last seen** shows "Now" for a server of the last refresh. For any other server it shows the time since the last refresh that had it, as "3 min ago" and from 60 minutes on as "1 h ago". A server stays in the table for 30 minutes after its last refresh, 300 servers at most, so a server does not vanish 10 seconds after its last packet. These past rows are dimmed and keep the status of their last refresh. A row goes away when its filter is disabled or deleted. The markers on the map and the n in the bar only count the servers of the last refresh. While the status row says "Connections not updated since …", no row says "Now" and each shows the age of the last refresh.

The page notes a server only while it is open and visible: the refresh pauses in a background tab. When you leave the View tab and come back in the same browser tab, the table starts with the servers of the last 30 minutes again. The browser keeps them in its session storage, nothing on the router. It stores the IP, filter, time, country and country code, city, ISP and organization. From the last refresh that had the server it also stores the status and, when counted, the packet and byte totals. The page writes it at most every 30 seconds and when the tab is hidden or left. These restored rows show their real age and, like other past rows, the stored status and total. Their Traffic tooltip has no "Seen for" line. A restored row without a stored status, for example from an older version of the page, shows **Unknown**. It shows Whitelisted when the Allowed IPs of its filter list the address as an entry of its own. The next refresh that has the server replaces the row, and its Traffic starts over like that of a new row: the total, then the rate.

**Traffic** counts the packets to the server that match the row's filter (its devices, protocol and ports), all devices of the filter together. Geomate counts them in the filter's collected set (see [Dynamic Mode](#dynamic-mode)) before the forward rules, so a blocked server is counted too. A row of the last refresh shows the rate over the refreshes of the last 20 seconds, for example "62 pkt/s", "3.4 pkt/s" or "0.07 pkt/s". A new row shows the total until its refreshes span 4 seconds, and a past row shows the total, such as "12 packets", from 10000 on rounded, such as "108k packets" or "1.2M packets". The tooltip adds the bytes, the average packet size and how long the page has seen the server, for example "2311 packets sent to the server, 413.0 KiB", "183 bytes per packet" and "Seen for 0h 4m 10s while this page was open". The column shows whether the filter's devices sent a server a few packets once, a low rate for many minutes or many packets per second for the length of a match. It does not say what the server is used for.

- A count starts with the server's first packet. It starts again from 0 after an hour without a packet and after every restart of Geomate. The page sees a restart by the new process ID within 10 seconds, and from its next refresh the row shows the total until it has a new rate. Until then the rate can read too low.
- "–" means no count: the backend is older and does not count (no `set_counters`, see Backend Capabilities under [Debug and Monitoring Tools](#debug-and-monitoring-tools)), Geomate runs in Static Mode, which has no collected set, or the row was restored after you left the page and has no stored total, for example from an older version of the page.
- Sorting by Traffic orders the rows by the current rate, then by the total. Past rows and rows without a rate yet count as 0 pkt/s, so right after the page opens, before the rows have a rate, the total decides. A row keeps the rate it is sorted by until its rate moves more than 10% away from it, so servers with nearly the same rate do not swap places at every refresh. While the mouse pointer is over the table, while the keyboard focus is in it and for 5 seconds after a touch, the rows keep their places and a new server goes to the end, so an Allow or Block button does not move away under the pointer. Once that ends, the rows take the current order. A click on the Traffic title or a choice in **Sort by** sorts at once.

**Flow offloading** (software or hardware, Network > Firewall > General Settings): once a connection runs, the router passes its packets around Geomate's rules, so Geomate sees only the first packets of each connection. The table shows the server as current for about 10 seconds after the connection starts and then as a past row, until Geomate sees a packet of it again: at a new connection, or when the connection resumes after a pause of about 30 seconds. Traffic counts only those first packets, for UDP often "1 packet". Filtering still works for new connections: Geomate decides on the first packet, and a blocked server's first packet is dropped, so its connection is never offloaded. A connection that is offloaded already is not checked again: a server that is blocked later, for example after a geolocation update, keeps that connection until it pauses for about 30 seconds. While flow offloading is on, a dimmed note at the table says so. An older web interface shows no note.

**Allow** and **Block** are in the last column, with write access only. Allow adds the server to the Allowed IPs of the filter in the row's Filter column, Block to its Blocked IPs. A row whose server the filter's Allowed IPs list as an entry of its own has **Remove** instead, and one whose server the Blocked IPs list has **Unblock**. A Whitelisted row has no Block button, because the Allowed IPs win. A server that only a subnet, a range or a longer entry such as `1.2.3.4 5.6.7.8` covers has no button: the cell shows "–", and its tooltip says to edit the entry on the Geo Filters page. A server that only the older `option blocked_ips` covers shows "–" too, with a tooltip to edit `/etc/config/geomate`. The buttons also work on past rows. Block and Unblock need a backend that reports `blocked_ip` (see Backend Capabilities under [Debug and Monitoring Tools](#debug-and-monitoring-tools)); with an older one the column has Allow and Remove only.

- A click is applied at once, without Save & Apply: Geomate writes `list allowed_ip` (Block and Unblock: `list blocked_ip`) of that filter to `/etc/config/geomate`. The map shows "Added 1.2.3.4 to the allowed IPs of Call of Duty.", "Blocked 1.2.3.4 in Call of Duty.", "Removed …" or "Unblocked …" with an **Undo** button (see [How Changes Take Effect](#how-changes-take-effect)). Without a loaded map, a notification shows the text. The row then shows Whitelisted or Blacklisted, or the status the sets give it after a Remove or Unblock.
- Allow puts the server into the filter's allowed set, which wins over the blocked set. Block puts it into the blocked set and takes it out of the allowed set, also inside a circle. With a backend that reloads live, the filter's sets are refilled without a restart. An older backend restarts Geomate. The restart clears the list of servers the filters have seen: the n in the bar stays 0 until the game sends traffic to the servers again (seconds in a running match, longer in the menu), and the rows stay as past rows until then.
- In Monitor mode Allow and Block change the status only. Nothing is blocked.
- A click is refused with a notification when the filter name is not unique ("Not applied: several filters are named …"), when the filter has a hand-written `option allowed_ip` or `option blocked_ip` ("Edit it on the Geo Filters page."), or when the address is listed already. Block is also refused for a server in the filter's Allowed IPs ("1.2.3.4 is in the allowed IPs of Call of Duty."). Unsaved Geomate changes in your session refuse it too.

The table uses compact rows: cell padding of 5 px by 10 px and small buttons, so more servers fit on the screen. When the table has 960 px or less of room, each server is a card of two lines instead of a row, whatever the theme does. The first line has the IP in bold, the status and the buttons. Below, in smaller dimmed text, come "Filter · Country · ISP" (a long name ends in "…") and on the right "Last seen · Traffic", for example "Now · 62 pkt/s". A row without a count shows Last seen only. With less than 560 px of room the card shows the country code, such as "DE", with the country name as tooltip; without a code it shows the name. The city and the column titles are left out. Instead of the column titles, a **Sort by** select next to the search field sorts the cards: Last seen from the newest, Traffic from the highest rate, IP and Country in ascending order. Table and cards share the sort order. After a sort by a column the select does not offer, such as ISP, it is empty. Phones and narrow windows get cards. A wider table is a real table in every theme, also in those that stack table rows on narrow windows. Up to 1040 px of room it leaves out the City column, like the cards. A browser without container queries shows cards only in windows up to 600 px.

### Server details

Until you select a server, the map takes the full width. Click a server IP in the list, or **Details** in its map popup, to select it, and the server panel opens beside the map. When the page content is 900 px wide or less (a window of 1100 px or less in a browser without container queries), the panel goes below the map, and the map takes 60% of the window height while the panel shows. Selecting a server from the fullscreen map returns to this overview. Selecting it again keeps its history; selecting another server starts a new history.

**Hide** collapses the panel to its heading below the full-width map and stops sampling. **Show**, or selecting the same server again, restores the panel and its history. **Close** removes the panel and selection; select a server to open it again. Showing the panel preserves a manual pause and does not reset the ten-minute sampling limit.

**Ping**, **Jitter** and **Ping loss** appear above the three-minute ping graph. They use ICMP probes from the router, not the game's packets. A timeout or missing measurement clears the current Ping value while keeping the graph's history. If a server never replies, the panel shows **No ping reply** and leaves Ping loss as "–". This does not indicate 100% loss of game traffic. Ping stops after three unanswered attempts, or ten consecutive timeouts after a successful reply. **Retry** starts another attempt. A server that does not answer ICMP provides no measured ping.

**Route RTT** starts when ping stops (see above), or with **Measure** while ping still runs. Measure is hidden while the route measurements run, and **Retry** ends them until ping stops again. It shows the round-trip time to the last answering router along the route to the selected server, together with its address, hop and measurement age. This is a separate diagnostic value, not a prediction or guaranteed bound for the game's ping. If the destination itself answers, the panel identifies that response. While the server has not answered a single ping, the graph shows the route RTT of the last three minutes instead, titled **Route RTT · Hop n**. A measurement without a reply leaves the line as it is. The line breaks where another router answers or the hop changes, and after more than 20 seconds without a measurement. Route results never enter Ping, Jitter, Ping loss or filtering decisions. Failed measurements clear the value; a value older than 10 seconds is marked expired.

The first route measurement sends probes for eight hops at a time and counts a reply that arrives within 1.2 seconds of its probe. It goes on until the server itself answers, up to 24 hops. Because a batch goes out at once, a near server can get up to eight probes in one search. Subsequent measurements reuse that hop and still send the probe to the original server: one probe per refresh, a second one when the first has no reply after half a second. A single router-wide job runs at a time, with a two-second minimum gap and cached results shared across pages. A job has a seven-second deadline and a hard limit of 28 probes. Route hints expire after three minutes; a failed route is not searched again within one minute. State is kept in RAM, with no additional packages or packet capture required.

The smaller **Packets** graph shows packets per second: **Received** from the server and **Sent** to it, for all devices matching the filter. The rate tooltips show average packet size. These counts do not measure the game's tick rate. Flow offloading limits both counts as described above. A restarted counter or a long gap starts a new line instead of showing a false spike.

Packet counters and direct ping are sampled once per second, with one sample request at a time. When a reply takes longer than half a second, the next request goes out twice the reply time after the previous one, but at most 4 seconds after it, so the packet rates still show. The one-second wait of an unanswered ping does not count as reply time. Enabled route measurements refresh about every two seconds, separately from those samples. Only the selected server is measured, while the tab and panel are visible and LuCI auto refresh is on. **Pause** freezes the measurements; **Resume** continues them. After ten minutes sampling pauses automatically. Leaving the page stops new requests. An already running bounded route job finishes on the router. Nothing is sampled before a server is selected.

Each sample reads the filter's collected sets, which hold the servers of the last hour. The more servers they hold, the more CPU time a sample costs the router. On an Intel N100 a sample took about 30 ms with 200 servers (Call of Duty had 121 on the test router). A filter without ports collects every server its devices reach (see `protocol` in [Per-Filter Options](#per-filter-options)). There a sample took 0.5 seconds with 20,000 servers and 2.1 seconds with 65,535, the most a set holds, and an open panel then uses half to two thirds of one core for these samples. Route measurements read the sets too, every two seconds, when the server sent nothing in the last 10 seconds.

The receiving rate needs a backend with `rx_counters`, and the sending rate needs `set_counters`. An older backend shows only the measurements it supports. Static mode has no packet counters. After an update of the web interface, an open LuCI session may not be allowed to call the new methods yet. The panel then says "Server measurements unavailable. Log in again after an update of the web interface." (for the route: "Route RTT unavailable. Log in again …"). Log in to LuCI again. "Route RTT not supported" means that the router cannot send the route probes, or that rpcd has not loaded the method since the update (`/etc/init.d/rpcd restart`). Server details are also available to read-only Geomate logins.

### Geo Filters Page

The **Geo Filters** tab is a normal LuCI settings page. Changes stay unsaved until you click **Save & Apply** in the page footer. Geomate then reloads as described in [How Changes Take Effect](#how-changes-take-effect). While Geomate has unsaved changes, the map refuses changes. The page has three parts:

- **Geolocation Status** shows when the last update ran, when the next one is due and how many IPs wait for geolocation.
- **Global Settings** has Enable, Strict Mode, Debug Level, Manual Geolocation, Operational Mode, Check Interval and Geolocation Update Mode. Check Interval offers 5, 10, 15, 30 and 60 minutes and shows only with a backend that reports `check_interval` (see [Check interval](#check-interval)). A value written by hand shows as a choice of its own.
- **Geo Filters** is the table of all filters, with buttons to add, edit and delete a filter.

The table has these columns:

| Column | Shows |
|--------|-------|
| Enable | A switch for the filter |
| Name | The filter name |
| Status | The state of the filter in the configuration, see below |
| Match | The traffic the filter looks at, built from Protocol, Source IP, Source Port and Destination Port. Examples: "UDP from 192.168.2.208 port 3074", "UDP from 192.168.2.208 to port 9000-9100". Without any of them only the protocol shows ("UDP traffic"), and without a protocol either "Any traffic". Ports without a protocol show as "TCP/UDP" ("TCP/UDP to port 3074"; an older web interface shows "Any protocol"): the service then matches both. Entries show as configured, with two additions. A Source IP address for which the router knows a host name shows it in brackets ("UDP from 192.168.2.208 (PS5) port 3074"). Exceptions follow the other entries as "except 192.168.2.10", or as "any except 192.168.2.10" when there is nothing else ("UDP from any except 192.168.2.10 to port 9000-9100"). Without host names, for example when the session may not read them, the column shows addresses only |
| IPs/Located | The IPs in the list and how many are located: "120 ✓" for all, "120 (60%)" for part of them, "120 (stale)" when the geo data holds IPs that left the list, "No data" when there is no information for the filter yet |
| Regions | The number and radii of the circles, for example "2 circles · 436 km, 683 km", and a **Show on map** link that opens the View tab at that filter. Invalid entries are counted ("1 invalid"), and "Not a list" marks a hand-written `option allowed_region` |

The edit dialog (titled "Filter <name>", or "New filter" for a new one) has every option of the filter: Enable, Name, Allowed Regions (one `circle:<latitude>:<longitude>:<radius in meters>` per entry, easier to edit on the map), Protocol, Source IP, Source Port, Destination Port, Allowed IPs, Blocked IPs, IP List File, IP Expiry (Days) and the buttons **Create Empty List**, **Upload List** and **Download List**. Blocked IPs shows only with a backend that reports `blocked_ip`; it takes IPv4 addresses and subnets like Allowed IPs (see [Blocked IPs Explained](#blocked-ips-explained)).

- **Name** takes letters, digits, spaces, `_`, `.` and `-`, the rule of the service (see Characters under [Per-Filter Options](#per-filter-options)). A new or changed name must not start or end with a space. Each filter needs a name of its own, also when spaces count as `_` and case is ignored: "Call of Duty" and "Call_of_Duty" would get the same nftables sets, so the dialog refuses a name that matches another filter in this way. An enabled filter without a name, or with a saved name that breaks the rule, shows "Invalid name" in the Status column, because the service skips the filter. Geomate does not rename it for you; change the name in the dialog.
  - After a rename: the geo data file and the record of IPs already queued for lookup (`/etc/geomate.d/runtime/<name>_last_processed`) are named after the filter. Until the next geolocation the filter has no coordinates and puts no server in its allowed or blocked set. With Strict Mode on it then blocks every server except its Allowed IPs, without Strict Mode only its Blocked IPs; in monitor mode it blocks nothing in any case. In Frequent Mode the next automatic geolocation also looks up the whole list again for the new name, within the request budget that all runs share (about 7 minutes for 10,000 IPs), and applies the result without a restart.
  - To keep the coordinates and skip this second lookup, rename both files on the router before Save & Apply, for example `mv "/etc/geomate.d/Call of Duty_geo_data.json" "/etc/geomate.d/CoD_geo_data.json"` and `mv "/etc/geomate.d/runtime/Call of Duty_last_processed" "/etc/geomate.d/runtime/CoD_last_processed"` (the second file exists only once Frequent Mode has looked up IPs of the filter). IPs still waiting in the queue at the rename are then looked up by the next daily update. Otherwise run Manual Geolocation, which looks up the whole list at once (a list of 10,000 IPs takes about 7 minutes), and delete the old geo data file; rename the `_last_processed` file all the same, or Frequent Mode looks the list up a second time.
- **IP List File** must be an absolute path, starting with `/`, without a space at the start or end and without a line break. The service uses the path exactly as written: with a space at the end it creates and fills a new, empty file instead of your list. The check applies only when you change the field, so a saved path that breaks the rule does not stop you from saving the other options. An enabled filter with such a saved path shows "Invalid list path" in the Status column.
- **Create Empty List** fills in the path `/etc/geomate.d/<name>_servers.txt` (the name in lowercase, other characters replaced by `_`). Geomate creates a missing file when it starts.
- **Upload List** writes the chosen file to the path in IP List File, or to that suggested path when the field is empty, at once and before you save the dialog. The file must lie directly in `/etc/geomate.d` and must not end in `.json` or `.md5`. If the file exists, the dialog asks "… already exists. Replace it with …?" and waits for **Replace** or **Cancel**. A path that names a folder gives a message instead.
- **Download List** saves the IP list of the filter as a file on your computer, to share it or to upload it on another router. Like Upload List it uses the path in IP List File, or the suggested path when the field is empty, and only a file directly in `/etc/geomate.d`. The file has one IPv4 address per line, sorted and without duplicates, the format that Upload List and the lists shipped with Geomate use. It leaves out the timestamps that IP Expiry adds, which would show when you play, and the addresses listed below, which belong to no game server. It is not an exact backup: uploaded again, the list starts IP Expiry anew. Dynamic and monitor mode save new IPs to the list at each check interval (30 minutes by default) and when the service stops, so IPs collected since then are not in the file yet. A missing, empty or unreadable list, or a path that names a folder, gives a message instead of a download. The browser reads the list through LuCI's file download, which has no size limit, so large collected lists work too. After an update of the web interface, an open session may be refused the download, with the message "No permission to read …", until you log in to LuCI again. Left out are:
  - the private and reserved addresses that the collection of new IPs skips too: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, 0.0.0.0/8 and 224.0.0.0/3
  - 100.64.0.0/10, the shared range of carrier-grade NAT, from which many providers give the router its WAN address. The collection of new IPs keeps these addresses
  - the router's own addresses, when the LuCI session may read them; otherwise the download skips this step without an error
- **Source IP** is the device the filter applies to. The field suggests the devices of your LAN as "192.168.2.208 (PS5)", or as "IP (MAC)" when the router knows no name. The suggestions come from the host hints that LuCI's Static Leases page uses, in numeric order, without the router's own addresses. You can type any entry as well. The field stores the address, not the name, so give the device a static lease: otherwise DHCP can change its address and the filter hits another device or none. An empty field means all devices.
  - With a backend that reports `src_ip_multi` (see [Debug and Monitoring Tools](#debug-and-monitoring-tools)), the field is a list. Each entry is an IPv4 address, a subnet (`192.168.2.0/24`) or a range (`192.168.2.10-192.168.2.20`). `!` before an entry leaves it out. A pasted "a b" becomes two entries. The entries are saved in one `option src_ip`, separated by spaces, as in earlier versions. For the rules this builds, see `src_ip` in [Per-Filter Options](#per-filter-options).
  - With an older backend, or when the backend does not answer, the field takes one address, with the same suggestions. Several entries and `!` are rejected there ("This Geomate backend supports one address only.", "This Geomate backend supports no exceptions.").
  - A new entry must be one of the three forms: "Expecting: IPv4 address, address/prefix or address range". A saved value that you do not change stays valid, so a filter with an old value can still be saved.
  - The new-filter dialog of the map has the same field.

The Status column shows the state of each filter in the configuration:

| Status | Meaning |
|--------|---------|
| Active | Enabled, with regions and an IP list, nothing unsaved and no error |
| Disabled | The filter is off and has no unsaved changes |
| Unsaved | The filter has unsaved changes. An enabled filter also shows it while the global Enable switch has an unsaved change |
| No regions | An enabled filter has no valid circle |
| No IP list | An enabled filter has no IP List File |
| nftables error | The service reported an nftables error for the filter, or its Source IP is invalid. See `/tmp/geomate_nft_errors.log` on the router |
| Invalid list path | The IP List File of an enabled filter does not start with `/`, starts or ends with a space, or has a line break (see IP List File above) |
| Invalid name | An enabled filter has no name, or its saved name has a character that filter names may not contain (see Name above). The service skips the filter: no sets, no rules. An older web interface can show "Active" for such a filter, or "–" when it has no name |
| Service off | Geomate is disabled in the global settings |
| Region not a list | An enabled filter has `option allowed_region` instead of `list allowed_region`. The service start, the live reload and the collection of new IPs skip it, and the map cannot show it |

Several words can show together, for example "Unsaved, No IP list".

## Detailed Configuration

### Understanding Operational Modes

#### Dynamic Mode
- Automatically learns server IPs during gameplay
- Builds IP lists over time: new IPs are saved at each check interval (30 minutes by default) and when the service stops or restarts
- Counts the packets and bytes sent to each collected server (`nft list set inet geomate geomate_<filter>_dynamic`, spaces in the filter name as `_`). A count starts with the server's first packet and ends when the server has been idle for an hour or Geomate restarts. New geo data does not restart Geomate (see [Geolocation Process](#geolocation-process)); a backend without `geo_reload` restarts it after it has geolocated new servers, usually right after it saved new IPs to the list
- Also counts the packets and bytes each server sends back to the filter's devices (`nft list set inet geomate geomate_<filter>_rx`). Only packets to the filter's Source IP and ports count, and only while the device has sent to that server in the last 10 seconds. The count ends like the one above. Not for a filter without working rules (see the nft errors in the status) or whose protocol is written as an nft expression
- With software or hardware flow offloading on (Network > Firewall > General Settings), Geomate sees only the first packets of each connection: offloaded packets bypass Geomate's rules. New servers are still collected and new connections still filtered, but the count stops after those first packets and the connections table shows a server as current only for about 10 seconds. See **Flow offloading** under [Active Connections](#active-connections)
- Recommended for most users

#### Static Mode
- Uses predefined IP lists
- No automatic learning or IP tracking
- Requires less system resources
- Probably better for low-end routers or when you have complete server lists

#### Monitor Mode
- Tracks and logs connections without blocking any traffic
- Collects, counts and geolocates IPs just like Dynamic Mode, but never blocks any connections
- Perfect for initial setup, testing, and analyzing game connections
- **Key Benefits**:
  - No risk of blocking legitimate connections during testing
  - Visualize all server connections on the map as they're discovered
  - Build your IP database while monitoring connections
  - Ideal for understanding your game's server infrastructure
- **Important Notes**:
  - On new filters the map starts empty - play multiple matches to build your IP database
  - IPs will appear on the map after they've been geolocated
  - Use this mode when you want to analyze connections without any filtering
  - Switch to Dynamic or Strict Mode when ready to enable filtering

### Essential Server Whitelisting
- **Matchmaking Servers**: Required by most games to find and join matches
- **Relay Servers**: Handle initial connections and game coordination
- **Authentication Servers**: Manage login and account verification
- Without proper whitelisting, games may:
  - Fail to start
  - Be unable to find matches
  - Disconnect unexpectedly

### Strict Mode Explained
- **Disabled (Default)**: 
  - Allows both known and untracked connections - untracked connections are connections that are not yet geolocated by Geomate
  - Ideal during initial setup and learning phase
  - Helps build comprehensive IP lists

- **Enabled**:
  - Only allows known and whitelisted connections
  - Use after building complete IP lists
  - Provides strongest filtering

### Geolocation Updates
- **Frequent Mode**:
  - Checks at the configured interval and backs off to twice that interval without new IPs (30-60 minutes by default)
  - Higher API usage
  - Better in early stages of learning

**Important Note:** In Frequent Mode with Strict Mode disabled, new geolocation data can block a previously untracked server during a match. A shorter check interval can make that happen sooner. With flow offloading on, a running connection is checked again only after a pause of about 30 seconds (see **Flow offloading** under [Active Connections](#active-connections)). To avoid this, consider using Daily Mode or enabling Strict Mode after an initial learning phase.

- **Daily Mode**:
  - Updates once per day
  - Reduces API calls
  - Queues no IPs, because every daily update looks up every listed IP. A queue left from Frequent Mode is emptied at the next cycle. After a switch to Frequent Mode, its first update also looks up the IPs a list gained in Daily Mode, or the whole list of a filter that never used Frequent Mode. That costs about as many requests as one daily update

### Check interval

In Dynamic and Monitor Mode, `check_interval` sets how often Geomate saves collected addresses and checks for geolocation work. A missing or invalid value uses 1800 seconds, and numeric values are limited to 300-3600 seconds. Existing configurations need no change. Static Mode keeps its current timing. In the web interface it is **Check Interval** on the Geo Filters page.

A shorter interval finds new servers sooner and runs more collection and status cycles. Routine timestamp refreshes happen about once an hour per list, even at 300 seconds; filters sharing a list refresh their collected addresses together. New IPs are still saved at the next cycle. A stop of the service also refreshes active IPs whose time is older than one hour per day of IP Expiry (at most a day), with one write of the list at most, or one per filter when filters sharing the list differ in IP Expiry; with an IP Expiry of 1 day that write happens at many stops. Active IPs already expired or within an hour of expiry are refreshed immediately, including when the service stops, so they survive a restart. Daily expiry also keeps addresses still present in a collected set. Geolocation requests from all cycles and manual runs use the same provider budget.

The status file in `/etc/geomate.d/runtime` is written at every cycle, and the scheduler's small files there when its check runs or its queue changes. A cycle that finds new servers also rewrites the whole IP list, and in Frequent Mode the geolocation that follows rewrites the filter's geo data file and its `_last_processed` file. All of them are on flash. With the 14,570 Call of Duty servers of the test router that is 3.2 MB per such cycle, so while a game keeps finding new servers, 5 minutes can write up to six times as much as 30 minutes.

### Geolocation Process

The geolocation process can be triggered manually through the UI or runs automatically based on your selected update mode. To optimize resource usage and API quota:

- Only active filters are processed during geolocation
- The [ip-api batch endpoint](https://ip-api.com/docs/api:batch) accepts up to 100 IPs per request and 15 requests per minute. All filters, manual runs and scheduled runs share a rolling 15-request/60-second budget in `/tmp/geomate/ratelimit`, including partial batches and retries. The provider URL, batch size and request budget are grouped at the top of `geolocate.sh`. A run that cannot reserve a request within 60 seconds stops and leaves its remaining IPs for a later run. If a killed run leaves the budget's lock behind, the next run takes it over
- `X-Rl` and `X-Ttl` response headers can delay the next request but never increase that budget. A numeric `Retry-After` is also accepted. HTTP 429 is retried once after the reported delay (at most 65 seconds), through the same limiter; curl does not retry on its own. Requests time out after 30 seconds. Failed batches keep the existing coordinates
- Frequent updates process the queued IPs in batches; the request limiter controls the pace. The old scheduler counted IPs as requests, so it could leave new servers queued unnecessarily. When the frequent update of a filter fails (API requests failed and no geo data changed, or the run stopped because it could not reserve a request), the filter's IPs stay queued for the next update. IPs of a failed batch in a run that changed geo data wait for the next daily update
- The process runs in the background and may take several minutes to complete
- Only one full run of all IPs runs at a time: Manual Geolocation, `service geomate geolocate`, `/etc/geolocate.sh` or the daily update. While one runs, `/tmp/geomate/geolocation.lock` holds its PID on the first line and its start time (Unix time) on the second. Another full run then logs "Geolocation is already running (PID n)", does nothing and exits with 3. A daily update that finds a run in progress stays due and runs with the next automatic update. A lock whose process is gone, for example after the run was killed, is taken over by the next run. The geolocation of newly collected IPs between the daily updates does not wait for this lock
- `/etc/geolocate.sh start` starts a manual full run in the background and returns at once with one line: "Geolocation started (PID n)" and exit code 0, "Geolocation is already running (PID n)" and exit code 3, or an error and exit code 1 when the run cannot create its lock file. A run with nothing to look up can end before `start` returns and still counts as started. The run logs to the system log as usual (tag `geolocate`) and applies new geo data at the end, as described below. `/etc/geolocate.sh` without argument and `service geomate geolocate` run in the foreground and end with exit code 0, with 1 when API requests failed and no geo data changed or the run stopped early because it could not reserve an API request, with 3 when a run is in progress already, or with 4 when the lock file cannot be created
- A web interface that knows the backend capability `geolocate_status` (see [Debug and Monitoring Tools](#debug-and-monitoring-tools)) can show a running geolocation and start Manual Geolocation with `start`. An older web interface starts the run as before; a second click while it runs starts no second run
- New geo data takes effect without a restart: at the end of each run that changed geo data, `/etc/geomate.sh reload_geo` refills the allowed and blocked sets of every enabled filter whose geo data file changed since its sets were built, in one nftables transaction and from the configuration of the last start. Rules, counters, the collected servers and the collection timer stay. The log shows "Geo data reload of <filter>: n allowed, m blocked geolocated IPs" per filter (Debug Level 1). `reload_geo` alone checks every enabled filter; with filter names it checks only those. It exits with 0 when the sets hold the current geo data, and also when Geomate is not running or was stopped or restarted while `reload_geo` ran ("Geo data reload: Geomate was stopped or restarted meanwhile, a start reads the geo data"): a geolocation no longer starts a stopped Geomate, its next start reads the new data
- Geomate restarts instead, as an older backend always did, when the geo data cannot be applied in place. A run of the automatic geolocation leaves that restart to the service loop, which restarts through rpcd (`ubus call rc init`) once the run has finished. Started by hand, the run restarts Geomate itself. With Debug Level 1 or higher the system log names the reason:
  - a start that has not finished after 60 seconds
  - no `inet geomate` table while the service runs, or no copy of the configuration of the last start in `/tmp/geomate/config`, unless a check one second later finds Geomate stopping or starting
  - the lock `/tmp/geomate/sets.lock` still held by another process after 60 seconds
  - nftables errors at the last start
  - uncommitted uci changes that differ from those of the last start
  - two enabled filters whose names differ only in spaces and underscores
  - a failed nftables transaction, or a work folder in `/tmp/geomate` that cannot be created

### Understanding IP Lists and Allowed IPs

#### IP List Files
IP list files are essential for Geomate to identify game server IPs. These files contain collections of IP addresses that belong to game servers. Geomate needs these lists to determine which game servers should be filtered based on your geographic settings. The IP list, combined with your specified ports and source IP, helps Geomate identify and filter the actual game server connections.

There are two ways to obtain these lists:

1. **Dynamic Learning (Recommended for New Games)**
   - Create a new geofilter with an empty IP list
   - Click "Create Empty List" in the dialog: it fills in the list path, and the service creates the empty file when it starts (saving a new filter restarts it)
   - Set operational mode to Dynamic
   - Geomate will automatically collect server IPs while you play

2. **Using Existing Lists**
   - Download pre-collected IP lists (e.g., Call of Duty servers)
   - Place files in `/etc/geomate.d/`
   - Either:
     - Upload via "Upload List" in the Geo Filters dialog or "Upload IP List" in the map's new-filter dialog (both write the file at once and ask before they replace an existing file)
     - Manually move the file to `/etc/geomate.d/` and set the path in the config or UI
   - Run "Manual Geolocation" for immediate use

#### Allowed IPs Explained
Games often require specific servers to be always accessible, regardless of location:
- Matchmaking servers
- Authentication servers
- Relay servers

For example, Call of Duty requires these IPs to be allowed:
```
185.34.107.128
185.34.107.129
```

Without proper Allowed IPs:
- Games may fail to start
- Matchmaking might not work
- Connection errors may occur

**Note:** Required IPs may vary by region. If you experience connection issues, you may need to identify and add region-specific servers to your Allowed IPs list.

#### Blocked IPs Explained
Blocked IPs are the opposite: servers the filter always blocks, also inside a circle. Use them for a single bad or wrongly located server, so you do not have to shrink a circle and lose the good servers around it. Click **Block** in the connections table, or add the address under Blocked IPs on the Geo Filters page.

The order is: Allowed IPs first, then Blocked IPs, then the circles. A server that both lists cover is allowed. The connections table shows a blocked server as Blacklisted. Blocked IPs need a backend that reports `blocked_ip`; an older backend ignores them, and the web interface then offers neither the field nor the Block button. See `blocked_ip` in [Per-Filter Options](#per-filter-options) for the forms of an entry and for the older `option blocked_ips`.

### Finding Allowed IPs

Finding the correct allowed IPs for games can involve some trial and error. Here's a systematic approach:

#### Method 1: Using Monitor Mode (Recommended)
1. Set Geomate to **Monitor Mode** in the LuCI interface (the mode pill in the status row of the View tab, see [Changing the Mode](#changing-the-mode))
2. Play your game normally - all connections will be tracked but not blocked
3. Click the Active connections bar below the map (or click a marker on the map) to see which servers your game connects to. The table is sortable and shows IP, status, country, city, ISP and when each server was last seen. To stop it from updating while you read, click the "Refreshing" indicator in the LuCI header (it changes to "Paused"); click it again to resume.
4. The map will populate with server locations as they're discovered and geolocated
5. Play multiple matches to build a comprehensive IP database
6. Pay attention to patterns - which servers are used for matchmaking vs. actual gameplay
7. Make note of essential servers (like authentication and matchmaking) for whitelisting, or click **Allow** in the connections table to add a server to the Allowed IPs of its filter at once
8. Once you've identified all necessary servers, decide on your filtering approach:
   - Use Dynamic Mode for automatic filtering (switch with the same mode pill; it asks before Geomate starts to block)
   - Use Static Mode if you want to manually manage IP lists
   - Enable Strict Mode when you're confident in your IP database

#### Method 2: Initial Game Launch Analysis
1. Start with no allowed IPs configured
2. Launch the game
3. Monitor initial connections in QoSmate
4. Focus on IPs that generate traffic over the configured game ports
5. These early connections are often essential servers

#### Method 3: Error-Driven Discovery
1. Start the game without allowed IPs
2. If you encounter network/server connectivity errors:
   - Check QoSmate for recent connection attempts
   - Add the first few IPs that attempted connections
   - Restart the game and test
   - Repeat if necessary

#### Important Notes on Allowed IPs
- Don't add every IP blindly - this would defeat the purpose of geo-filtering
- Focus on IPs that appear during game startup or matchmaking
- Essential servers typically include:
  - Authentication servers
  - Matchmaking servers
  - Login servers
- Some games may work without explicit allowed IPs if their essential servers don't use the geo-filtered ports

#### Best Practices
- Start with minimal allowed IPs
- Document which IPs resolve which issues
- Remove allowed IPs that prove unnecessary
- Use QoSmate to monitor traffic patterns
- Test thoroughly after adding new allowed IPs

### IP List Maintenance

Over time, IP lists can grow large and may contain outdated or invalid entries. Geomate provides tools to keep your IP lists clean and efficient.

#### Automatic IP Expiry

You can configure automatic removal of inactive IPs on a per-filter basis:

1. Edit a geo filter in the LuCI interface
2. Set **IP Expiry (Days)** to your preferred value (e.g., 180)
3. IPs not seen for that many days will be automatically removed on service start and, while Geomate runs, once a day before the daily geolocation. That run looks up only the listed IPs, so removed IPs also leave the geo data and the filter's sets. A list file is rewritten only when an IP was removed or got its first timestamp

**Note:** Existing filters default to `0` (disabled) for backward compatibility. New filters can be configured with expiry enabled.

#### Manual Cleanup

To remove private/invalid IPs from all IP lists:

```bash
/etc/init.d/geomate cleanup_ips
```

This command:
- Removes private IPs (10.x, 172.16-31.x, 192.168.x)
- Removes loopback (127.x) and link-local (169.254.x) addresses
- Cleans corresponding entries from geo_data.json files
- Shows a summary of removed/kept IPs

After cleanup, restart Geomate to apply changes:
```bash
/etc/init.d/geomate restart
```

### Finding Game Ports and Protocols

There are several ways to identify the correct ports and protocols for your games:

1. **Using QoSmate (Recommended)**
   - Install QoSmate on your router
   - Start your game and play normally
   - In LuCI, go to QoSmate's "Connections" tab
   - Filter the list by your gaming device's IP
   - Sort by "AVG BPS" or "AVG PPS" in descending order
   - Look for UDP connections with consistent traffic
   - Gaming traffic typically shows constant activity
   - Note both source and destination ports

2. **Alternative Methods**
   - Use Wireshark for detailed packet analysis
   - Use tcpdump on the router
   - Check game documentation or community forums

3. **Understanding Port Types**
   - Some games use fixed ports, others use port ranges
   - Examples:
     - Call of Duty: Source Port 3074 (fixed)
     - Fortnite: Destination Ports 9000-9100 (range)

4. **Configuring Ports in Geomate**
   - Use the identified ports in your geo filter settings
   - Usually, the UDP port with highest consistent traffic is your main gaming port
   - Only configure the port that remains constant
     - If source port is always the same (like CoD's 3074), use that
     - If destination port range is consistent (like Fortnite's 9000-9100), use that
   - You don't need to configure both source and destination ports
   - Port ranges are supported (e.g., '9000-9100')

### Creating Multiple Regions for a Game

You can allow game connections from multiple geographic areas by creating several circles for the same geofilter. Here's how:

1. **Create Your First Circle**
   - Click "Draw circle" in the map toolbar, choose "New filter…" and drag on the map
   - Enter a name for your geofilter (e.g., "COD" or "Fortnite")
   - Configure your settings in the dialog box
   - Click Save

2. **Add More Circles to the Same Filter**
   - Click "Draw circle" and choose the filter (e.g., "COD") in the menu "Draw a circle for"
   - Drag on the map again
   - The circle is added to that filter at once, without a dialog
   - Adjust or delete circles later as described in [Using the Map](#using-the-map)

3. **Check the Result**
   - Each circle is applied as soon as you draw it, so there is nothing to save or apply afterwards. If a circle is wrong, click "Undo" in the message or edit it as described in [Using the Map](#using-the-map)
   - Your game can now connect to servers in all circled regions

Example: If you want to play COD with friends from both Europe and USA:
1. Click "Draw circle", choose "New filter…", draw a circle over Europe, name it "COD"
2. Click "Draw circle", choose "COD", draw another circle over USA
3. Done: both circles are applied

## Troubleshooting

### Common Issues and Solutions

1. **Unable to Connect to Game Servers**
   - Causes:
     - Essential servers not whitelisted
     - Strict Mode enabled too early
     - Incorrect port configurations
     - No game servers are within your allowed regions
     - A needed server is in the Blocked IPs (status Blacklisted)
   - Solutions:
     - Add necessary IPs to "Allowed IPs" list, for example with **Allow** in the connections table (blocked and untracked servers show there)
     - Remove a needed server from the Blocked IPs, for example with **Unblock** in the connections table
     - Verify whitelist for matchmaking/relay servers
     - Confirm port configurations are correct
     - Disable Strict Mode during initial setup
     - Change allowed regions (circles) if necessary

2. **High Latency or Lag**
   - Causes:
     - Connecting to distant servers
     - Router resource constraints
   - Solutions:
     - Adjust allowed regions to include closer servers
     - Block a single bad server inside a circle with **Block** in the connections table instead of shrinking the circle
     - Review and optimize router resources
     - Verify server locations

3. **Geo-Filter Not Working**
   - Causes:
     - Incorrect configuration
     - Service issues
     - Firewall rules not applied
   - Solutions:
     - Verify geo-filter is enabled
     - Check the Status column of the filter on the Geo Filters page
     - Check protocol and port settings
     - Ensure service is running
     - Wait for firewall rules to apply after restart
     - Review log files for errors

4. **Router Performance Issues**
   - Causes:
     - Insufficient resources
     - Too many active filters
     - System overload
   - Solutions:
     - Reduce number of active filters
     - Close other resource-intensive applications
     - Consider hardware upgrade if persistent
     - Monitor system resources

5. **Manual Geolocation Starts No Run**
   - Cause: a geolocation of all IPs is in progress already, a manual one or the daily update. It can take several minutes, and a second one would double the requests to ip-api.com
   - Solutions:
     - Wait for the end of the run. `logread -e geolocate` shows "Geolocation is already running (PID n)" for the refused start. With Debug Level 1 or higher it also shows the end of the run: "the new geo data needs no restart", "restarting geomate service" or "skipping service restart"
     - `cat /tmp/geomate/geolocation.lock` shows the PID and the start time (Unix time) of the run in progress. The file is gone when the run has ended
     - If the run hangs, end it with `kill <PID>`. The next run takes over the lock

6. **An Update Is Already Running**
   - Cause: only one update runs at a time. A second `/etc/init.d/geomate update` prints "Error: An update is already running (PID n)." and exits with 3. It changes nothing. A service start during an update repairs no missing files and logs "An update is running: not repairing … files now."
   - Solutions:
     - Wait for the end of the run. `cat /tmp/geomate/update.lock` shows its PID and its start time (Unix time). The file is gone when the run has ended
     - A lock whose process is gone, for example after the run was killed, needs no cleanup. The next update takes it over
     - If a run ended after it began to install files, run the update again. It logs "The last update did not complete. Installing again.", installs both components again, restarts Geomate and reloads rpcd

7. **An Update From the Web Interface Failed or Was Interrupted**
   - "Update failed: …" shows the first error of the run. `/tmp/geomate/update_result.json` holds the result of the last update run: the exit code (`rc`), start and end time, the versions before and after, the first error, the backup folder and the log. `/tmp/geomate/update.log` holds the whole output of the last run that the web interface started. A run from the command line prints to the terminal and writes no log. `logread -e geomate` shows the messages of every run. Both files are in RAM and are gone after a reboot
   - "Update interrupted" means that the run ended without a result, for example because it was killed, or because rpcd was restarted while it ran. The update of another package can do that. Start the update again, with **Update** on the page or with `/etc/init.d/geomate update`. It installs both components again, restarts Geomate and reloads rpcd

### Game-Specific Network Analysis
- Use QoSmate for monitoring game connections
- Consider Wireshark for detailed packet analysis
- Use tcpdump for network traffic capture
- Research your game's network behavior and server infrastructure
- Some games may need specific server whitelisting

### VPN-Related Issues
- VPN usage may conflict with Geomate
- Some games might not find matches with both active
- Consider using either VPN or Geomate based on your needs

### Matchmaking and Region Changes
- Longer matchmaking times are normal with restricted regions
- Game restart may be required after region changes
- A change of circles, allowed or blocked IPs only does not restart the service: Geomate updates the allowed and blocked IPs of the changed filter in place. Any other change restarts it (see [How Changes Take Effect](#how-changes-take-effect))
- Consider expanding allowed regions if matchmaking is too slow

### Additional Tips
- During initial setup, keep Strict Mode disabled to allow IP learning
- Regularly check log files for potential issues
- After service restarts, allow time for firewall rules to rebuild

### Debug and Monitoring Tools

1. **Debug Levels**
   - **Level 0**: Minimal logging
   - **Level 1**: Standard operations
   - **Level 2**: Verbose debugging

2. **System Resource Monitoring**
   - Check CPU usage and available RAM
   - Monitor router performance
   - Review active connections and filters

3. **IP List Management**
   - Verify IP lists are correctly configured
   - Check for errors in IP list files
   - Monitor IP list updates and changes

4. **Check nftables Rules**
   - Use 'nft list table inet geomate' to view current rules
   - Check for any unexpected rules or mislocated ips

5. **Backend Capabilities**
   - `/etc/geomate.sh capabilities` prints the features of the installed backend as one line of words and exits with 0. It reads no configuration and changes nothing
   - Today it prints `src_ip_multi set_counters blocked_ip geolocate_status geo_reload check_interval rx_counters ui_update`. `src_ip_multi`: Source IP accepts several entries and exceptions with `!`. `set_counters`: each server in a filter's collected set (`geomate_<filter>_dynamic`, dynamic and monitor mode) carries `counter packets N bytes M`. Every restart of Geomate empties the set, so a server can disappear or start again from 0 between two reads. `blocked_ip`: `list blocked_ip` (and the older `option blocked_ips`) blocks its servers inside the circles too, and a change of `list blocked_ip` is applied without a restart. `geolocate_status`: every full geolocation run holds `/tmp/geomate/geolocation.lock` with its PID and start time, a second one exits with 3, and `/etc/geolocate.sh start` starts a manual run in the background (see [Geolocation Process](#geolocation-process)). `geo_reload`: new geo data refills the filters' sets in place (`/etc/geomate.sh reload_geo`) instead of restarting Geomate, so the counts of the collected set keep running. `check_interval`: the global collection interval is configurable between 300 and 3600 seconds, with 1800 as the default. `rx_counters`: in dynamic and monitor mode each enabled filter with working rules has a second set `geomate_<filter>_rx` whose servers carry `counter packets N bytes M` for what they sent to the filter's devices, and it is emptied by a restart like the collected set. A filter without working rules (see the nft errors) or whose protocol is an nft expression has none: read a missing set as "unknown". `ui_update`: `/etc/init.d/geomate update -y` installs newer versions without the question, and `/etc/init.d/geomate update_start -y`, `update_start -v release` or `update_start -v snapshot` starts that update in the background and prints one line (exit 0 "Update started (PID n)", 3 an update runs already, 1 not started or any other argument). A run holds `/tmp/geomate/update.lock` with its PID and start time and writes `/tmp/geomate/update_result.json` before it releases the lock; a run that `update_start` started writes its output to `/tmp/geomate/update.log` (see [Update from the Web Interface](#update-from-the-web-interface))
   - Words are only added, never renamed or removed, so the web interface and scripts can rely on them. An older backend prints its usage and exits with 1, which means no capabilities

## FAQ

**Does Geomate work with IPv6?**

Geomate only filters IPv4. The servers of the games covered here use IPv4.

If a console or PC connects to a game server over IPv6, Geomate does not see that connection. The server is not collected, not filtered and does not show on the map.

**How to check:** while you play, look at the router's connections, either in LuCI under **Status → Realtime Graphs → Connections** (network column **IPv6**), or with QoSmate under **Network → QoSmate → Connections** (IPv6 addresses contain colons, for example `2a02:…`). Look for connections on your game's port, for example 3074 for Call of Duty.

**If you find some** and want Geomate to cover these connections, one option is to turn off IPv6 in the network settings of that console or PC. The rest of your network can keep IPv6.

**Note:** a filter without a Source IP builds its rules from the ports only. In Strict Mode they also drop IPv6 traffic on those ports. A filter with a Source IP does not touch that device's IPv6 traffic.

On the command line you can check the same with `grep '^ipv6' /proc/net/nf_conntrack | grep -E 'port=(3074|3075) '` (use the ports of your filter).

**Q: Why should I keep Strict Mode disabled initially?**
A: During initial setup or when adding a new game, disabling Strict Mode allows Geomate to learn new server IPs while you play. Once most server IPs are collected, you can enable it for stricter filtering.

**Q: How long does it take for Geomate to learn all server IPs?**
A: This varies by game and how you play. Most games' essential servers are discovered within a few gaming sessions, but it may take longer to build a complete list.

**Q: Will Geomate affect my game performance?**
A: When properly configured, Geomate should not noticeably impact game performance. The filtering happens at the network level and is optimized for minimal latency.

**Q: What happens if I restart Geomate during gameplay?**
A: There might be a brief period where filtering is temporarily bypassed while firewall rules are rebuilt. This typically takes a few seconds to minutes. Server IPs collected since the last save are written to the IP lists before the service stops.

**Q: Will Geomate make my games easier or improve my gameplay?**
A: No, Geomate is a connection management tool that helps you control which game servers you connect to. It doesn't affect gameplay mechanics or matchmaking algorithms.

**Q: Can I use Geomate with a VPN?**
A: While technically possible, using both Geomate and a VPN simultaneously may cause matchmaking issues. You might need to choose one or the other depending on your needs.

**Q: Why does matchmaking take longer with Geomate?**
A: When you restrict server regions, the game has fewer servers to choose from, which can increase matchmaking time. This is normal and expected behavior.

**Q: Do I need to restart my game after changing regions?**
A: Yes, if you modify region settings while a game is running, you may need to restart the game for the changes to take full effect.

**Q: Will Geomate work with all my games?**
A: Not necessarily. Games handle networking differently, and some may require specific configurations or might not work with geographic filtering at all. You may need to research your specific game's network behavior.

**Q: Why do I need to whitelist certain servers?**
A: Many games use central servers for matchmaking, authentication, and relay functions. These servers might be located outside your allowed regions but are essential for the game to function. Without whitelisting them, you might not be able to start the game or find matches, even if your game servers are properly configured.

**Q: How can I find the correct ports and protocols for my game?**
A: The easiest way is to use QoSmate, another OpenWrt application:
1. Install QoSmate on your router
2. Start your game and play normally
3. In LuCI, go to QoSmate's "Connections" tab
4. Filter the list by your gaming device's IP
5. Sort by "AVG BPS" or "AVG PPS" in descending order
6. Look for UDP connections with consistent traffic - these are typically your game ports

Important: Games may use either fixed ports (like CoD's source port 3074) or port ranges (like Fortnite's destination ports 9000-9100). Configure only the port that remains constant - you don't need to set both source and destination ports. Port ranges are supported using the format '9000-9100'.

## Important Notes and Expectations

### What Geomate Does and Doesn't Do
- Geomate creates firewall rules to allow or block game servers based on their geographic location
- It does NOT automatically make you a better player
- It does NOT guarantee easier lobbies

### Intended Use Case
Geomate is specifically designed for precise geographic filtering of game servers, allowing you to define custom regions using circles on a map. If you need:
- Country-wide geoblocking
- Blocking access to your router from specific countries
- General geoblocking for regular server connections

Consider using alternatives like `banip` or `geoip-shell` instead, as they are better suited for these use cases.

### Game Compatibility
- Not all games have been tested with Geomate
- Each game handles matchmaking differently
- Some games may require specific server whitelisting
- You might need to research your game's network behavior
- Useful tools for game analysis:
  - QoSmate
  - Wireshark
  - tcpdump

## Tested Games Status

| Game | Status | IP List Completeness | Notes |
|------|--------|---------------------|--------|
| Call of Duty (MW3, BO6, Warzone) | Working | High | Extensively tested, requires port 3074 UDP |
| Fortnite | In Progress | Initial | Early testing phase, uses port range 9000-9100 |

**Legend:**
- Working: Tested and functioning as intended
- In Progress: Currently being tested and improved
- IP List Completeness:
  - High: Most server IPs identified and verified
  - Initial: Basic testing started, IP collection ongoing

## Hardware Requirements

### Minimum System Requirements
- OpenWrt 23.05 or newer
- Minimum 5MB free disk space (more for large IP lists, e.g., CoD needs ~5MB alone)
- Sufficient free RAM for IP list processing
- CPU: 750MHz or faster recommended

### OpenWrt Requirements
- Required packages:
  - curl (needed for IP geolocation)
  - jq
  - lua
  - luci-lua-runtime
  - luci (for web interface)

### Tested Devices
- FRITZ!Box 4020
  - CPU: Qualcomm Atheros QCA9561 @ 750MHz
  - RAM: 128MB
  - Flash: 16MB
  - Performance: Basic functionality works

### Performance Notes
- More RAM and CPU power will provide better performance
- Multiple active filters require more system resources
- Monitor system resources to prevent router overload
- Low-end hardware may experience some limitations
- Unofficial OpenWrt builds might have compatibility issues

### Not Recommended For
- Routers with less than 64MB RAM (basic functionality might work but performance will be limited)
- Very old or underpowered devices
- Unofficial OpenWrt builds from third-party vendors (compatibility issues may occur)

## Backup and Updates

### Updating Geomate

Geomate includes a flexible update system to keep your installation current with the latest features and improvements.

#### Basic Update
To update Geomate to the latest release version:

```bash
/etc/init.d/geomate update
```

This command will:
- Check for updates to both backend and frontend components
- Download and install the latest release versions if available
- Restart the service automatically if required

Geomate will preserve your existing configuration settings during updates.

When a newer version is available, the update asks before it installs. With `-y` it installs without the question.

The updater reloads rpcd when it installed a new access list (`acl.d`) or a new `luci.geomate`. Open LuCI sessions stay logged in, keep their unsaved changes and get the new permissions without a new login. An update that changes only the pages or the menu does not touch rpcd. If the reload fails, the update prints "Failed to reload rpcd", goes on and exits with 1: run `/etc/init.d/rpcd restart` and log in to LuCI again.

The first update to this version is still done by the older updater, which restarts rpcd. Log in to LuCI again after it. Until then a notification on the View tab can say "Log in again after an update of the web interface." (see [Known Servers](#known-servers)), **Download List** can say "No permission to read …" and the server panel "Server measurements unavailable. Log in again after an update of the web interface." (see [Server details](#server-details)).

Geomate restarts only when the update installed or removed a backend file. If the restart fails, the update prints "Failed to restart Geomate." and exits with 1.

An update overwrites files that were changed by hand. It first saves each of them under its full path in `/tmp/geomate_old_modified_files`, for example `/tmp/geomate_old_modified_files/etc/geomate.sh`. The folder is in RAM and is gone after a reboot.

#### Update from the Web Interface

With write access, the **Updates** row in the details of the status row (see [Using the Map](#using-the-map)) has two buttons:

- **Update** shows when an update is available. It installs what is newer on the channel of each component, like `/etc/init.d/geomate update -y`.
- **Change channel** switches the backend and the web interface to the release or the snapshot channel, like `/etc/init.d/geomate update -v release` or `-v snapshot`. It installs the latest version of that channel, even if it is older than the installed one, and Geomate restarts.

The update runs on the router in the background, so it goes on when you close the tab. The row shows "Starting update...", then "Update running for n s" and at the end the result: the new versions, "Nothing to update." or "Update failed: …" with the first error. The result stays until you click **Dismiss**. A second tab, a new login and a read-only login show the same run and result; a read-only login has no buttons. If the update replaced files you had changed, the row names the backup folder. After an update of the web interface the page asks you to reload it.

The buttons need a backend that reports `ui_update` (see Backend Capabilities under [Debug and Monitoring Tools](#debug-and-monitoring-tools)) and a web interface that knows it. With an older backend the row says "To update, run service geomate update on the router." when an update is available. So the first update to this version runs from the command line. Updates of one component, forced updates and updates to a version, a branch or a commit stay on the command line too.

#### Advanced Update Options

For more control over the update process, Geomate supports several command-line options:

```bash
/etc/init.d/geomate update [options]
```

| Option | Description | Example |
|--------|-------------|---------|
| `-c COMPONENT` | Update only a specific component (BACKEND or FRONTEND) | `-c BACKEND` |
| `-v VERSION_OR_CHANNEL` | Specify version or channel in various formats:<br>- Version number: `-v 1.2.0`<br>- Channel selection: `-v release`, `-v snapshot`<br>- Branch selection: `-v branch=dev`<br>- Commit hash: `-v commit=a1b2c3d4` | `-v 1.2.0` |
| `-f` | Force update even if no newer version is available | `-f` |
| `-y` | Install newer versions without the question. Like the plain update it installs only components with a newer version, each on its own channel | `-y` |
| `-i` | Ignore cache results | `-i` |
| `-U CHANNEL` | Override update channel (takes precedence over `-v`) | `-U snapshot` |

#### Update Channels
- `release`: Stable versions (recommended for most users)
- `snapshot`: Latest code from the main branch
- `branch=NAME`: Code from a specific branch
- `commit=HASH`: Specific commit version

#### Usage Examples

Check for available updates without installing them:
```bash
/etc/init.d/geomate check_version
```

Update only the backend component:
```bash
/etc/init.d/geomate update -c BACKEND
```

Update to a specific version:
```bash
/etc/init.d/geomate update -v 1.2.0
```

Update to the latest release version:
```bash
/etc/init.d/geomate update -v release
```

Update to the latest snapshot (development) version:
```bash
/etc/init.d/geomate update -v snapshot
```

Update to a specific branch:
```bash
/etc/init.d/geomate update -v branch=dev
```

Update to a specific commit hash:
```bash
/etc/init.d/geomate update -v commit=a1b2c3d4e5f6...
```

> **Note:** The default update approach (using the release channel) is recommended for most users. Other update channels and options are primarily intended for testing and development purposes.

### Preserving IP Lists During Firmware Updates

Geomate stores all IP lists in the `/etc/geomate.d/` directory. By default, this directory is not preserved during OpenWrt firmware updates. To keep your IP lists across updates:

1. **Edit sysupgrade.conf**:
   ```bash
   echo "/etc/geomate.d/" >> /etc/sysupgrade.conf
   ```

2. **Verify the Entry**:
   ```bash
   cat /etc/sysupgrade.conf
   ```
   You should see `/etc/geomate.d/` in the list.

This ensures that all your collected IP lists and configurations in the geomate.d directory are preserved when you update your OpenWrt firmware.

**Note**: Always make a backup of your IP lists before major updates, just to be safe.

## Uninstallation

To uninstall Geomate while preserving your configuration and collected server data:

```bash
# Stop and disable the service
/etc/init.d/geomate stop && \
/etc/init.d/geomate disable && \
# Remove application files but keep config and data
rm -f /etc/init.d/geomate /etc/geomate.sh /etc/geomate_trigger.sh /etc/geolocate.sh && \
# Remove LuCI interface
rm -rf /www/luci-static/resources/view/geomate /usr/share/luci/menu.d/luci-app-geomate.json /usr/share/rpcd/acl.d/luci-app-geomate.json /usr/libexec/rpcd/luci.geomate && \
# Restart services
/etc/init.d/rpcd restart && \
/etc/init.d/uhttpd restart
```

Note: This will preserve your configuration (`/etc/config/geomate`) and collected server data (`/etc/geomate.d/`). If you want to completely remove everything, including configuration and data, add these commands:
```bash
rm -rf /etc/config/geomate /etc/geomate.d
```

## Support

For issues and questions:
- Submit issues on GitHub
- Post in the OpenWrt forum thread
