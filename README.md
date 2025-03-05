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

1. OpenWrt 23.05 or newer
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
for file in $(curl -s https://api.github.com/repos/hudra0/geomate/contents/files/etc/geomate.d | jq -r '.[].name'); do
    curl -L -o "/etc/geomate.d/$file" "https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geomate.d/$file"
done && \
# Download and install core files
wget -O /etc/init.d/geomate https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/init.d/geomate && \
wget -O /etc/geomate.sh https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geomate.sh && \
wget -O /etc/geomate_trigger.sh https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geomate_trigger.sh && \
wget -O /etc/geolocate.sh https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geolocate.sh && \
chmod +x /etc/init.d/geomate /etc/geomate.sh /etc/geomate_trigger.sh /etc/geolocate.sh && \
if [ ! -f /etc/config/geomate ]; then wget -O /etc/config/geomate https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/config/geomate; fi && \
# Enable and start service with a small delay
/etc/init.d/geomate enable && \
sleep 2 && \
/etc/init.d/geomate start && \
echo "Geomate service installation complete!"
```

### 2. Installing the LuCI Web Interface

```bash
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
wget -O /www/luci-static/resources/view/geomate/view.js https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/htdocs/luci-static/resources/view/geomate/view.js && \
wget -O /www/luci-static/resources/view/geomate/geofilters.js https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/htdocs/luci-static/resources/view/geomate/geofilters.js && \
wget -O /www/luci-static/resources/view/geomate/map.html https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/htdocs/luci-static/resources/view/geomate/map.html && \
wget -O /usr/share/luci/menu.d/luci-app-geomate.json https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/root/usr/share/luci/menu.d/luci-app-geomate.json && \
wget -O /usr/share/rpcd/acl.d/luci-app-geomate.json https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/root/usr/share/rpcd/acl.d/luci-app-geomate.json && \
wget -O /usr/libexec/rpcd/luci.geomate https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/root/usr/libexec/rpcd/luci.geomate && \
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

## Quick Start Guide

1. **Access the Web Interface**
   - Navigate to Services > Geomate in LuCI

2. **Draw Your Region**
   - Go to the "View" tab
   - Click the circle icon to draw a region on the map
   - Draw where you want to allow game connections
   - Name your filter (e.g., "Call of Duty")

3. **Configure Your Filter**
   - Protocol: Usually UDP for games
   - Gaming Device IP: Your console/PC IP (e.g., 192.168.1.208)
   - Ports: Use known values (e.g., 3074 for CoD) or see [Finding Game Ports and Protocols](#finding-game-ports-and-protocols)
   - Whitelist: Add essential IPs for matchmaking/authentication (see [Allowed IPs Explained](#allowed-ips-explained))
   - IP List: Either use an existing list or create an empty one (see [Understanding IP Lists](#understanding-ip-lists-and-allowed-ips))

4. **Save & Let Geomate Learn**
   - Click "Save" and then "Save and Apply"
   - Play your game - Geomate will learn server IPs
   - Keep Strict Mode disabled initially

![GeomateAdd](https://github.com/user-attachments/assets/ffdd5da0-d8d6-4b88-af53-5da055d57138)

## Detailed Configuration

### Understanding Operational Modes

#### Dynamic Mode
- Automatically learns server IPs during gameplay
- Builds IP lists over time
- Recommended for most users

#### Static Mode
- Uses predefined IP lists
- No automatic learning or IP tracking
- Requires less system resources
- Probably better for low-end routers or when you have complete server lists

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
   - Use the "Create empty list" button in the dialog
   - Set operational mode to Dynamic
   - Geomate will automatically collect server IPs while you play

2. **Using Existing Lists**
   - Download pre-collected IP lists (e.g., Call of Duty servers)
   - Place files in `/etc/geomate.d/`
   - Either:
     - Upload via the "Upload List" function in the geofilter dialog
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

#### Method 1: Initial Game Launch Analysis
1. Start with no allowed IPs configured
2. Launch the game
3. Monitor initial connections in QoSmate
4. Focus on IPs that generate traffic over the configured game ports
5. These early connections are often essential servers

#### Method 2: Error-Driven Discovery
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
   - Click on the map to start drawing your first circle
   - Enter a name for your geofilter (e.g., "COD" or "Fortnite")
   - Configure your settings in the dialog box
   - Click Save

2. **Add More Circles to the Same Filter**
   - Click on the map again to draw another circle
   - Important: Use the exact same filter name as before
   - The previous settings will appear automatically
   - Adjust settings if needed, or keep them the same
   - Click Save

3. **Activate Your Changes**
   - After adding all desired circles, click "Save & Apply"
   - Your game can now connect to servers in all circled regions

Example: If you want to play COD with friends from both Europe and USA:
1. Draw a circle over Europe, name it "COD"
2. Draw another circle over USA, use the same name "COD"
3. Click "Save & Apply" - Done!

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
A: There might be a brief period where filtering is temporarily bypassed while firewall rules are rebuilt. This typically takes a few seconds to minutes.

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
