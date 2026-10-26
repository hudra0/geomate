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
| geolocation_mode | Frequency of IP geolocation updates | 'frequent' (30-60 min), 'daily' (once per day) | 'frequent' |

### Per-Filter Options

| Option | Description | Values | Default |
|--------|-------------|---------|---------|
| ip_list | Path of the IP list file (e.g. `/etc/geomate.d/cod_servers.txt`). Required for geographic filtering: its entries are geolocated in every mode; dynamic and monitor mode also collect new server IPs into it, static mode only uses what it contains. Without it the filter geolocates no IPs and relies on `allowed_ip` entries | File path | none |
| ip_expiry_days | Automatically remove IPs not seen for this many days | 0 (disabled), or number of days | 0 |

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
   - Source IP: Your console/PC IP (e.g., 192.168.1.208)
   - Source Port / Destination Port: Use known values (e.g., 3074 for CoD) or see [Finding Game Ports and Protocols](#finding-game-ports-and-protocols)
   - Allowed IPs: Essential IPs for matchmaking/authentication, the whitelist (see [Allowed IPs Explained](#allowed-ips-explained))
   - IP List File: Either use an existing list or create an empty one (see [Understanding IP Lists](#understanding-ip-lists-and-allowed-ips))
   - Enable and IP Expiry (Days) can stay at their defaults

4. **Save & Let Geomate Learn**
   - Click "Save" in the dialog. The filter is applied at once, without Save & Apply: Geomate restarts, and the map shows "Applied." with an Undo button (see [How Changes Take Effect](#how-changes-take-effect))
   - Start with Dynamic or Monitor Mode to begin collecting server IPs
   - Play several matches to allow Geomate to collect and geolocate server IPs
   - The map will populate as IPs are discovered and geolocated
   - Keep Strict Mode disabled until you've built a comprehensive IP list

![GeomateAdd](https://github.com/user-attachments/assets/ffdd5da0-d8d6-4b88-af53-5da055d57138)

*The animation shows an older version of the map; the steps above describe the current one.*

## Using the Map

The **View** tab (Services > Geomate) shows the service status, the map and, below it, the table of active connections. Regions are circles. The **Geo Filters** tab lists all filters (see [Geo Filters Page](#geo-filters-page)).

The status row above the map shows a **Running** / **Not running** pill ("Status unknown" when the router does not answer), a pill with the operational mode (Dynamic, Static or Monitor), a summary of the health checks ("All checks passed", or the names of the checks with an error, else those with a warning), "Loading GeoFilter data ..." while the service loads its data, the installed backend and frontend versions and the update state ("Up to date", "Update available", "Backend update available", "Frontend update available" or "Update check failed"). On narrow screens the row wraps and leaves out the versions and the update state. The status refreshes every 10 seconds.

**Details** opens a panel with the service state and its PID, what the mode does, each check with its message (Config, Files, Data, Autostart, nftables, nft errors; ✓ ok, ○ note, ⚠ warning, ✗ error), both versions with their update channel, the update state and a **Check again** button. The panel opens by itself when a problem shows on two status refreshes in a row. A problem is a stopped service while Geomate is enabled, or a check with a warning or an error. If you close the panel, it stays closed until a new problem appears. It never closes by itself.

The update check runs when the page opens and then every hour. GitHub allows 60 unauthenticated requests per hour and IP address, so the browser keeps the result for an hour (10 minutes after a failure) and the page reuses it until then. **Check again** asks GitHub right away and also skips the router's own 10-minute cache.

### How Changes Take Effect

The map applies every change at once: a new, moved, resized or deleted circle, a new filter, and the Enable button in the message after drawing. The View tab has no Save & Apply and no buttons in its footer. Each change is written to `/etc/config/geomate`, and Geomate picks it up right away. Only the Geomate configuration is committed. Unsaved changes of other configurations stay as they are.

- After each change the map shows "Applied." with an **Undo** button for 10 seconds. Undo writes back the values the change replaced and applies that. It works for the last change only, and not when the filter was changed since. Undoing the creation of a filter deletes the filter.
- A change of circles or allowed IPs only: Geomate refills the allowed and blocked sets of the changed filter in place, without a restart. The rules, the counters and the IPs collected since the last save stay. Changing the circles or allowed IPs of a disabled filter needs nothing at all.
- Any other change (a new filter, Enable, any other option) restarts Geomate. It rebuilds all nftables rules, and filtering is bypassed for a short time. The IPs collected so far are saved to the IP lists before every stop.
- Such a change restarts Geomate too when a start has not finished yet, when the last start had nftables errors, or when the names of two enabled filters differ only in spaces and underscores. If the run loop has stopped, for example after repeated crashes, every change restarts Geomate and so starts it again.
- Geomate also compares the configuration file without its region and allowed IP lists with the file it started from. The first such change after a hand edit of `/etc/config/geomate` therefore usually restarts Geomate once, because uci rewrites the whole file in its own format. The same happens on the first circle change of a filter whose regions are written as `option allowed_region` instead of `list allowed_region`, and on the first allowed IP change of a filter with `option allowed_ip` instead of `list allowed_ip`.
- An older backend restarts Geomate for every change, circles included. `/etc/init.d/geomate update` updates backend and web interface together.
- If your LuCI session holds unsaved Geomate changes, for example from the Geo Filters page, the map refuses every change: a new circle disappears, an edit goes back, and the map says "Apply or revert the unsaved geomate changes first." Applying would also apply those changes unseen. The page shows the notice "Apply or revert the unsaved geomate changes before you change the map." with a **Show changes** button, which opens LuCI's Unsaved Changes dialog, where you apply or revert them. The notice also shows when you open the View tab with unsaved Geomate changes.
- If a change cannot be applied, for example because the filters were changed in another browser tab, the map says so and shows the stored configuration again.
- Without write access to the Geomate configuration, the map only shows the circles: **Draw circle** is hidden and circles cannot be selected.
- Exception: **Upload IP List** in the new-filter dialog writes the list file to the router at once, before you click Save (it asks before it replaces an existing file). Cancel and Undo do not remove an uploaded file. **Create Empty List** only fills in the path. Geomate creates a missing file when it starts, and a new filter restarts it.

### Drawing a Circle

1. Click **Draw circle** in the map toolbar. The menu **Draw a circle for** lists your filters, each with its color, and **New filter…**. Disabled filters are marked "Disabled".
2. Pick an entry, then drag on the map. The bar on top says "Drag on the map to draw a circle for …" and shows the radius, which also shows next to the cursor. **Esc** or **Cancel** stops drawing. A click without a drag draws nothing: the map says "Drag to draw a circle." and you can drag again.
3. Existing filter: the circle is applied at once, without a dialog. For a disabled filter the message says "Applied. Filter … is disabled." and has an **Enable** button next to Undo. Drawing never enables a filter, and a disabled filter filters nothing. Enable is applied at once and restarts Geomate.
4. New filter: a dialog asks for the filter name and the filter options (Enable, Protocol, Source IP, Source Port, Destination Port, Allowed IPs, IP Expiry (Days), IP List File). The name may contain letters, digits, spaces, `_`, `.` and `-`. **Save** creates the filter and applies it at once. **Cancel** removes the circle. The list **Filter** at the top of the dialog can switch to an existing filter, and a name that matches an existing filter (ignoring case) adds the circle to it. The **Geo Filters** link under "More options" opens that page; when an existing filter is chosen, it opens that filter's edit dialog, which has the same options plus the name and the region list.

Each filter has a color of its own; with more than eight filters the colors repeat. The label of a circle shows the filter name. The selected circle has no label, and a small circle shows it only while the pointer is over it. A disabled filter is drawn faded. A dashed circle waits for its change to be applied. The legend shows the three states: Enabled, Disabled and Selected.

### Editing and Deleting a Circle

- Click a circle to select it. Only one circle is selected at a time, and selecting another keeps the changes of the first, like Done. Where circles overlap, the click selects the smallest one; click again at the same spot to select the next larger one. A small circle is zoomed in first so that the handles fit.
- Drag the **centre handle** to move the circle and the **edge handle** to resize it. A thin dashed ghost shows the old size, and the radius shows live next to the edge handle.
- Or type the radius in km in the bar at the bottom of the map, which also shows the filter and the centre. The circle follows at once, and Enter works like Done. The radius can be 0.001 to 20000 km.
- **Done** (or a click on the empty map) applies the change. **Cancel** or **Esc** restores the circle as it was.
- **Delete** asks "Delete circle?". **Yes** applies the deletion, **No** keeps the circle, and the question goes away by itself after 5 seconds. Deleting one circle never deletes the filter.
- The last circle of a filter opens the dialog "Delete the last circle of …?". For an enabled filter, **Delete and disable** is preselected; the other choices are **Delete** (the filter stays enabled) and **Cancel**. A filter without a region puts no geolocated IP into its allowed or blocked set. With Strict Mode on (and not in Monitor Mode), an enabled filter without a region therefore blocks every server except its allowed IPs; the dialog says which case applies. For a disabled filter, the dialog only asks to confirm.
- While a changed circle is selected, **Draw circle** asks you to click Done or Cancel first.

### Map Controls

| Control | What it does |
|---------|--------------|
| Fit all | Zoom to all circles, except those hidden with the eye in the legend. Without circles the map says "No circles yet." |
| Home | Go to your home view. Without a saved home view, zoom to all circles |
| Set home | Save the current view (centre and zoom) as the home view. The map says "Home view saved." |
| Fullscreen | Show the map in the whole window; Esc or the same button leaves it |
| Legend | Lists the filters with their circle count, then the circle states (Enabled, Disabled, Selected) and the connection markers (Allowed, Blocked, Whitelisted, and the clusters Several allowed, Several blocked, Several whitelisted and Mixed). The eye hides or shows the circles of a filter, the magnifier zooms to them. The switch **Dark map tiles** dims the map; it is off by default |

The map opens at your home view if you saved one, otherwise it shows all circles. The link **Show on map** on the Geo Filters page opens it at the circles of that filter instead. Without circles and without a home view the map shows a default view over Europe.

The legend is closed by default on phones and when the map is narrower than 900 px, until you open or close it yourself. It also closes while you draw or edit a circle. The legend state, the dark tiles switch and the home view are stored in your browser, not on the router. The map follows the light or dark theme of LuCI. On a map narrower than 640 px the toolbar shows icons only. On a phone the buttons are larger and the map takes 60% of the screen height.

### Active Connections

Below the map, the **Active connections (n)** bar shows or hides the table. Click anywhere on the bar; its right end reads **Show** or **Hide**. The table stays hidden until you open it, and on wide screens the map gets shorter while it is shown. It lists every tracked game server connection with IP, Filter, Status, Country, City and ISP. Click a column header to sort. The data refreshes every 5 seconds while the tab is visible and pauses in a background tab. If it fails several times in a row, the status row above the map says "Connections not updated since …" or "Connections unavailable". Status is Whitelisted, Allowed, Blocked, Untracked (not geolocated) or Unknown.

Country, city and ISP come from the geolocation data of the filter. They show "–" when no data is known for an IP yet, and after an update from an older version until the next service start or geolocation batch refreshes the lookup cache. A connection with a known position also gets a marker on the map: green for Allowed, red for Blocked, blue for Whitelisted. Markers close together form a cluster with a count: green if all are allowed, red if all are blocked, blue if all are whitelisted, orange if mixed. Click a marker for the IP, status, filter, country, city and ISP (and the organization, when it differs from the ISP).

### Geo Filters Page

The **Geo Filters** tab is a normal LuCI settings page. Changes stay unsaved until you click **Save & Apply** in the page footer. Geomate then reloads as described in [How Changes Take Effect](#how-changes-take-effect). While Geomate has unsaved changes, the map refuses changes. The page has three parts:

- **Geolocation Status** shows when the last update ran, when the next one is due and how many IPs wait for geolocation.
- **Global Settings** has Enable, Strict Mode, Debug Level, Manual Geolocation, Operational Mode and Geolocation Update Mode.
- **Geo Filters** is the table of all filters, with buttons to add, edit and delete a filter.

The table has these columns:

| Column | Shows |
|--------|-------|
| Enable | A switch for the filter |
| Name | The filter name |
| Status | The state of the filter in the configuration, see below |
| Match | The traffic the filter looks at, built from Protocol, Source IP, Source Port and Destination Port. Examples: "UDP from 192.168.2.208 port 3074", "UDP from 192.168.2.208 to port 9000-9100". Without any of them only the protocol shows ("UDP traffic"), and without a protocol either "Any traffic". Entries show as configured |
| IPs/Located | The IPs in the list and how many are located: "120 ✓" for all, "120 (60%)" for part of them, "120 (stale)" when the geo data holds IPs that left the list, "No data" when there is no information for the filter yet |
| Regions | The number and radii of the circles, for example "2 circles · 436 km, 683 km", and a **Show on map** link that opens the View tab at that filter. Invalid entries are counted ("1 invalid"), and "Not a list" marks a hand-written `option allowed_region` |

The edit dialog (titled "Filter <name>", or "New filter" for a new one) has every option of the filter: Enable, Name, Allowed Regions (one `circle:<latitude>:<longitude>:<radius in meters>` per entry, easier to edit on the map), Protocol, Source IP, Source Port, Destination Port, Allowed IPs, IP List File, IP Expiry (Days) and the buttons **Create Empty List** and **Upload List**.

- **Create Empty List** fills in the path `/etc/geomate.d/<name>_servers.txt` (the name in lowercase, other characters replaced by `_`). Geomate creates a missing file when it starts.
- **Upload List** writes the chosen file to the path in IP List File, or to that suggested path when the field is empty, at once and before you save the dialog. The file must lie directly in `/etc/geomate.d` and must not end in `.json` or `.md5`. If the file exists, the dialog asks "… already exists. Replace it with …?" and waits for **Replace** or **Cancel**.

The Status column shows the state of each filter in the configuration:

| Status | Meaning |
|--------|---------|
| Active | Enabled, with regions and an IP list, nothing unsaved and no error |
| Disabled | The filter is off and has no unsaved changes |
| Unsaved | The filter has unsaved changes. An enabled filter also shows it while the global Enable switch has an unsaved change |
| No regions | An enabled filter has no valid circle |
| No IP list | An enabled filter has no IP List File |
| nftables error | The service reported an nftables error for the filter. See `/tmp/geomate_nft_errors.log` on the router |
| Service off | Geomate is disabled in the global settings |
| Region not a list | An enabled filter has `option allowed_region` instead of `list allowed_region`. The service start skips it and the map cannot show it |

Several words can show together, for example "Unsaved, No IP list".

## Detailed Configuration

### Understanding Operational Modes

#### Dynamic Mode
- Automatically learns server IPs during gameplay
- Builds IP lists over time: new IPs are saved to the IP list every 30 minutes and when the service stops or restarts
- Recommended for most users

#### Static Mode
- Uses predefined IP lists
- No automatic learning or IP tracking
- Requires less system resources
- Probably better for low-end routers or when you have complete server lists

#### Monitor Mode
- Tracks and logs connections without blocking any traffic
- Collects and geolocates IPs just like Dynamic Mode, but never blocks any connections
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
  - Updates every 30-60 minutes - After this time geomate geolocates the newly collected IPs while gaming
  - Higher API usage
  - Better in early stages of learning

**Important Note:** If you play games with long match durations (over 30 minutes), you might experience issues when using Frequent Mode with Strict Mode disabled. In this case, a server that was initially allowed might be blocked mid-game, causing a game crash or disconnection. To avoid this, consider using Daily Mode or enabling Strict Mode after an initial learning phase.

- **Daily Mode**:
  - Updates once per day
  - Reduces API calls

### Geolocation Process

The geolocation process can be triggered manually through the UI or runs automatically based on your selected update mode. To optimize resource usage and API quota:

- Only active filters are processed during geolocation
- IP addresses are processed in batches to respect API rate limits
- The process runs in the background and may take several minutes to complete

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

### Finding Allowed IPs

Finding the correct allowed IPs for games can involve some trial and error. Here's a systematic approach:

#### Method 1: Using Monitor Mode (Recommended)
1. Set Geomate to **Monitor Mode** in the LuCI interface
2. Play your game normally - all connections will be tracked but not blocked
3. Click the Active connections bar below the map (or click a marker on the map) to see which servers your game connects to. The table is sortable and shows IP, status, country, city and ISP. To stop it from updating while you read, click the "Refreshing" indicator in the LuCI header (it changes to "Paused"); click it again to resume.
4. The map will populate with server locations as they're discovered and geolocated
5. Play multiple matches to build a comprehensive IP database
6. Pay attention to patterns - which servers are used for matchmaking vs. actual gameplay
7. Make note of essential servers (like authentication and matchmaking) for whitelisting
8. Once you've identified all necessary servers, decide on your filtering approach:
   - Use Dynamic Mode for automatic filtering
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
3. IPs not seen for that many days will be automatically removed on service start

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
   - Solutions:
     - Add necessary IPs to "Allowed IPs" list
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
- A change of circles or allowed IPs only does not restart the service: Geomate updates the allowed and blocked IPs of the changed filter in place. Any other change restarts it (see [How Changes Take Effect](#how-changes-take-effect))
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

## FAQ

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
