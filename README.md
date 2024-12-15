# Geomate - Geographic Game Server Filter for OpenWrt

Geomate is an OpenWrt application that enables you to control connections to game servers based on their geographic location. By drawing regions on a map, you can specify where you want to allow or block server connections. The application learns over time by collecting IP addresses of game servers you connect to, making the filtering more effective the more you play.

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
- [Support and Contribution](#support-and-contribution)

## Alpha/Beta Use Terms

This application is provided for alpha/beta testing only. By using it, you agree **not** to distribute or share the software or any access credentials. Geomate is still under development, and feedback on functionality, usability, and issues is highly appreciated.

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

### Installing Geomate Core

```bash
TOKEN="YOUR-TOKEN-HERE"

opkg update && opkg install curl jq && \
mkdir -p /etc/geomate.d && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/init.d/geomate -o /etc/init.d/geomate && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geomate.sh -o /etc/geomate.sh && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geomate_trigger.sh -o /etc/geomate_trigger.sh && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geolocate.sh -o /etc/geolocate.sh && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/geomate.d/cod_servers.txt -o /etc/geomate.d/cod_servers.txt && \
chmod +x /etc/init.d/geomate /etc/geomate.sh /etc/geomate_trigger.sh /etc/geolocate.sh && \
[ ! -f /etc/config/geomate ] && curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/geomate/main/files/etc/config/geomate -o /etc/config/geomate && \
/etc/init.d/geomate enable && \
/etc/init.d/geomate start
```

### Installing the LuCI Web Interface

```bash
TOKEN="YOUR-TOKEN-HERE"

opkg update && opkg install lua luci-lua-runtime && \
mkdir -p /www/luci-static/resources/view/geomate /usr/share/luci/menu.d /usr/share/rpcd/acl.d /usr/libexec/rpcd && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/htdocs/luci-static/resources/view/geomate/view.js -o /www/luci-static/resources/view/geomate/view.js && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/htdocs/luci-static/resources/view/geomate/geofilters.js -o /www/luci-static/resources/view/geomate/geofilters.js && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/htdocs/luci-static/resources/view/geomate/map.html -o /www/luci-static/resources/view/geomate/map.html && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/root/usr/share/luci/menu.d/luci-app-geomate.json -o /usr/share/luci/menu.d/luci-app-geomate.json && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/root/usr/share/rpcd/acl.d/luci-app-geomate.json -o /usr/share/rpcd/acl.d/luci-app-geomate.json && \
curl -H "Authorization: Bearer $TOKEN" -L https://raw.githubusercontent.com/hudra0/luci-app-geomate/main/root/usr/libexec/rpcd/luci.geomate -o /usr/libexec/rpcd/luci.geomate && \
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
   - Whitelist: Add essential IPs for matchmaking/authentication

4. **Save & Let Geomate Learn**
   - Click "Save" and then "Save and Apply"
   - Play your game - Geomate will learn server IPs
   - Keep Strict Mode disabled initially

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
- Ideal for low-end routers or when you have complete server lists
- More efficient operation due to reduced background processes

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
  - Allows both known and untracked connections
  - Ideal during initial setup and learning phase
  - Helps build comprehensive IP lists

- **Enabled**:
  - Only allows known and whitelisted connections
  - Use after building complete IP lists
  - Provides strongest filtering

### Geolocation Updates
- **Frequent Mode**:
  - Updates every 30-60 minutes
  - Higher API usage
  - Better in early stages of learning

**Important Note:** If you play games with long match durations (over 30 minutes), you might experience issues when using Frequent Mode with Strict Mode disabled. In this case, a server that was initially allowed might be blocked mid-game, causing a game crash or disconnection. To avoid this, consider using Daily Mode or enabling Strict Mode after an initial learning phase.

- **Daily Mode**:
  - Updates once per day
  - Reduces API calls

### Finding Game Ports and Protocols

There are several ways to identify the correct ports and protocols for your games:

1. **Using QoSmate (Recommended)**
   - Install QoSmate on your router
   - Start your game and play normally
   - In LuCI, go to QoSmate's "Connections" tab
   - Filter by your gaming device's IP
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

## Troubleshooting

### Common Issues and Solutions

1. **Unable to Connect to Game Servers**
   - Causes:
     - Essential servers not whitelisted
     - Strict Mode enabled too early
     - Incorrect port configurations
   - Solutions:
     - Add necessary IPs to "Allowed IPs" list
     - Verify whitelist for matchmaking/relay servers
     - Confirm port configurations are correct
     - Disable Strict Mode during initial setup

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

### Additional Tips
- During initial setup, keep Strict Mode disabled to allow IP learning
- Regularly check log files for potential issues
- After service restarts, allow time for firewall rules to rebuild

## FAQ

**Q: Why should I keep Strict Mode disabled initially?**
A: During initial setup or when adding a new game, disabling Strict Mode allows Geomate to learn new server IPs while you play. Once most server IPs are collected, you can enable it for stricter filtering.

**Q: How long does it take for Geomate to learn all server IPs?**
A: This varies by game and how you play. Most games' essential servers are discovered within a few gaming sessions, but it may take longer to build a complete list.

**Q: Will Geomate affect my game performance?**
A: When properly configured, Geomate should not noticeably impact game performance. The filtering happens at the network level and is optimized for minimal latency.

**Q: What happens if I restart Geomate during gameplay?**
A: There might be a brief period where filtering is temporarily bypassed while firewall rules are rebuilt. This typically takes a few seconds to minutes.

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

## Hardware Requirements

### System Requirements
- OpenWrt 23.05 or newer
- Minimum 5MB free disk space (more for large IP lists, e.g., CoD needs ~5MB alone)
- CPU with at least 580MHz recommended
- Sufficient free RAM for IP list processing

### OpenWrt Requirements
- Required packages:
  - curl
  - jq
  - lua
  - luci-lua-runtime
  - luci (for web interface)

### Not Recommended For
- Routers with less than 64MB RAM
- Very old or underpowered devices
- Unofficial OpenWrt builds from third-party vendors

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

## Support and Contribution

For issues, questions, or contributions:
- Open an issue on GitHub
- Follow the contribution guidelines
- Join our community discussions
