#!/bin/sh

# shellcheck shell=ash
# shellcheck disable=SC3043  # ash supports local variables
# shellcheck disable=SC2317  # Functions are called by OpenWrt's system
# shellcheck disable=SC2155  # Combined declaration and assignment is fine for our use case
# shellcheck disable=SC1083  # nft syntax requires literal braces
# shellcheck disable=SC1091  # OpenWrt's /lib/functions.sh is not available during shellcheck
# shellcheck disable=SC2154  # Variables are assigned by OpenWrt's config_load

. /lib/functions.sh

GEOMATE_DATA_DIR="/etc/geomate.d"
GEOMATE_RUNTIME_DIR="${GEOMATE_DATA_DIR}/runtime"
GEOMATE_TMP_DIR="/tmp/geomate"
NFT_SET_PREFIX="geomate_"
debug_level=0

# Load configuration settings
load_config() {
    config_load 'geomate'
    config_get interface settings interface 'br-lan'
    config_get debug_level global debug_level '0'
    config_get strict_mode global strict_mode '0'
    config_get operational_mode global operational_mode 'dynamic'
}

# Log messages and optionally print them based on the debug level
log_and_print() {
    local message="$1"
    local level="${2:-1}"
    if [ "$level" -le "$debug_level" ]; then
        logger -t geomate "$message"
        echo "geomate: $message"
    fi
}

# Set up necessary directories for Geomate
setup_geomate_d() {
    if [ ! -d "$GEOMATE_DATA_DIR" ]; then
        log_and_print "Creating $GEOMATE_DATA_DIR directory" 1
        mkdir -p "$GEOMATE_DATA_DIR"
        if [ $? -ne 0 ]; then
            log_and_print "Failed to create $GEOMATE_DATA_DIR directory" 0
            return 1
        fi
    fi

    mkdir -p "$GEOMATE_RUNTIME_DIR"
    chmod 755 "$GEOMATE_RUNTIME_DIR"

    mkdir -p "$GEOMATE_TMP_DIR"
    chmod 755 "$GEOMATE_TMP_DIR"

    config_load 'geomate'
    config_foreach create_empty_ip_list 'geo_filter'
    chmod 755 "$GEOMATE_DATA_DIR"
    find "$GEOMATE_DATA_DIR" -type f -exec chmod 644 {} \;
}

# Create an empty IP list
create_empty_ip_list() {
    local name ip_list
    config_get name "$1" 'name'
    config_get ip_list "$1" 'ip_list'

    if [ ! -f "$ip_list" ]; then
        log_and_print "Creating empty IP list file for $name: $ip_list" 2
        touch "$ip_list"
    fi
}

# Set up nftables rules and filters
setup_nftables_and_filters() {
    log_and_print "Setting up nftables rules and filters..." 1
    
    # Delete existing table and recreate it
    nft delete table inet geomate 2>/dev/null
    nft add table inet geomate
    nft add chain inet geomate forward { type filter hook forward priority -150 \; policy accept \; }
    nft add chain inet geomate prerouting { type filter hook prerouting priority -150 \; policy accept \; }

    # Set up filters from configuration
    config_load 'geomate'
    config_foreach setup_geo_filter 'geo_filter'
    config_foreach create_dynamic_set 'geo_filter'

    # Add a catch-all rule based on strict_mode
    if [ "$strict_mode" = "1" ]; then
        log_and_print "Strict mode enabled: No default forward policy set" 1
    else
        nft add rule inet geomate forward counter accept
        log_and_print "Normal mode: Default forward policy set to accept" 1
    fi

    log_and_print "nftables rules and filters set up successfully" 1

    # Invalidate cache
    rm -f /tmp/geomate_ip_cache.json
    if [ $? -eq 0 ]; then
        log_and_print "Cache invalidated by deleting /tmp/geomate_ip_cache.json" 2
    else
        log_and_print "Failed to invalidate cache by deleting /tmp/geomate_ip_cache.json" 1
    fi

    verify_nftables_rules
}

# Helper function to collect allowed_region entries
append_allowed_region() {
    allowed_regions="$allowed_regions $1"
}

# Set up a geo filter based on configuration
setup_geo_filter() {
    local name protocol src_ip src_port dest_port enabled blocked_ips
    local allowed_ips=""
    local allowed_regions=""
    
    config_get name "$1" 'name'
    config_get protocol "$1" 'protocol'
    config_get src_ip "$1" 'src_ip'
    config_get src_port "$1" 'src_port'
    config_get dest_port "$1" 'dest_port'
    config_get enabled "$1" 'enabled' '0'
    config_get blocked_ips "$1" 'blocked_ips'

    # Collect allowed_region entries
    config_list_foreach "$1" 'allowed_region' append_allowed_region

    [ "$enabled" = "0" ] && return

    local set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"

    log_and_print "Setting up geo filter for $name" 1

    # Create sets for this filter
    nft add set inet geomate "${set_name}_allowed" { type ipv4_addr\; flags interval\; }
    nft add set inet geomate "${set_name}_blocked" { type ipv4_addr\; flags interval\; }

    # Add allowed IPs
    config_list_foreach "$1" 'allowed_ip' append_allowed_ip
    if [ -n "$allowed_ips" ]; then
        allowed_ips=${allowed_ips%,}
        log_and_print "Manually adding allowed IPs: $allowed_ips" 2
        nft add element inet geomate "${set_name}_allowed" { "$allowed_ips" }
    fi

    # Add blocked IPs
    if [ -n "$blocked_ips" ]; then
        log_and_print "Manually adding blocked IPs: $blocked_ips" 2
        nft add element inet geomate "${set_name}_blocked" { "$blocked_ips" }
    fi

    # Process all allowed regions together
    if [ -n "$allowed_regions" ]; then
        log_and_print "Processing geo data for $name with allowed regions: $allowed_regions" 2
        process_geo_data "$name" "${set_name}_allowed" "${set_name}_blocked" "$allowed_regions"
    fi

    # Add rules for allowed and blocked IPs
    local base_rule=""
    [ -n "$src_ip" ] && base_rule="ip saddr $src_ip"
    [ -n "$protocol" ] && base_rule="$base_rule $protocol"

    # Include src_port in the rule if set
    if [ -n "$src_port" ] && [ "$src_port" != "any" ]; then
        # Check if it's a port range
        if echo "$src_port" | grep -q '-'; then
            base_rule="$base_rule sport $src_port"
        else
            # Replace spaces with commas for nftables list format
            src_port=$(echo "$src_port" | tr ' ' ',')
            base_rule="$base_rule sport { $src_port }"
        fi
    fi

    # Include dest_port in the rule if set
    if [ -n "$dest_port" ] && [ "$dest_port" != "any" ]; then
        # Check if it's a port range
        if echo "$dest_port" | grep -q '-'; then
            base_rule="$base_rule dport $dest_port"
        else
            # Replace spaces with commas for nftables list format
            dest_port=$(echo "$dest_port" | tr ' ' ',')
            base_rule="$base_rule dport { $dest_port }"
        fi
    fi

    nft add rule inet geomate forward "$base_rule" ip daddr @"${set_name}"_allowed counter accept
    nft add rule inet geomate forward "$base_rule" ip daddr @"${set_name}"_blocked counter drop

    # Strict mode rule
    if [ "$strict_mode" = "1" ]; then
        nft add rule inet geomate forward "$base_rule" counter drop
        log_and_print "Strict mode: Added default drop rule for $name" 2
    fi

    log_and_print "Geo filter for $name set up successfully" 1
    log_and_print "Added allowed IPs from config: $allowed_ips" 2
    log_and_print "Added blocked IPs: $blocked_ips" 2
}

# Check if coordinates are within any allowed region
is_within_any_region() {
    local lat="$1"
    local lon="$2"
    shift 2
    local allowed_regions="$*"

    for allowed_region in $allowed_regions; do
        [ -n "$allowed_region" ] || continue
        if is_within_region "$lat" "$lon" "$allowed_region"; then
            return 0  # Within one of the allowed regions
        fi
    done
    return 1  # Outside all allowed regions
}

# Create dynamic sets based on configuration
create_dynamic_set() {
    local name protocol src_ip src_port dest_port enabled
    config_get name "$1" 'name'
    config_get protocol "$1" 'protocol'
    config_get src_ip "$1" 'src_ip'
    config_get src_port "$1" 'src_port'
    config_get dest_port "$1" 'dest_port'
    config_get enabled "$1" 'enabled' '0'

    [ "$enabled" = "0" ] && return

    local set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"

    log_and_print "Setting up sets for $name" 1

    # Create UI dynamic set in both modes (needed for map display)
    nft add set inet geomate "${set_name}_ui_dynamic" { type ipv4_addr\; flags dynamic,timeout\; timeout 30s\; }

    # Only create main dynamic set in dynamic mode
    if [ "$operational_mode" != "static" ]; then
        # Create existing dynamic set with 1-hour timeout
        nft add set inet geomate "${set_name}_dynamic" { type ipv4_addr\; flags dynamic,timeout\; timeout 1h\; }
    fi

    # Create the base rule
    local base_rule=""
    [ -n "$src_ip" ] && base_rule="ip saddr $src_ip"
    [ -n "$protocol" ] && base_rule="$base_rule $protocol"

    # Include src_port in the rule if set
    if [ -n "$src_port" ] && [ "$src_port" != "any" ]; then
        # Check if it's a port range
        if echo "$src_port" | grep -q '-'; then
            base_rule="$base_rule sport $src_port"
        else
            # Replace spaces with commas for nftables list format
            src_port=$(echo "$src_port" | tr ' ' ',')
            base_rule="$base_rule sport { $src_port }"
        fi
    fi

    # Include dest_port in the rule if set
    if [ -n "$dest_port" ] && [ "$dest_port" != "any" ]; then
        # Check if it's a port range
        if echo "$dest_port" | grep -q '-'; then
            base_rule="$base_rule dport $dest_port"
        else
            # Replace spaces with commas for nftables list format
            dest_port=$(echo "$dest_port" | tr ' ' ',')
            base_rule="$base_rule dport { $dest_port }"
        fi
    fi

    # Add rule for the ui dynamic set (always needed)
    nft add rule inet geomate prerouting "$base_rule" update @"${set_name}"_ui_dynamic { ip daddr }

    # Add rule for the main dynamic set only in dynamic mode
    if [ "$operational_mode" != "static" ]; then
        nft add rule inet geomate prerouting "$base_rule" update @"${set_name}"_dynamic { ip daddr }
    fi

    log_and_print "Sets for $name set up successfully" 1
}

# Process dynamic sets for a given configuration
process_dynamic_set() {
    local name ip_list
    config_get name "$1" 'name'
    config_get ip_list "$1" 'ip_list'
    local set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"

    log_and_print "Processing dynamic set for $name" 2

    # Use a fixed temporary file per set
    local temp_file="/tmp/geomate_${set_name}_temp.txt"

    # Retrieve IPs from the dynamic set
    nft list set inet geomate "${set_name}_dynamic" | sed -n '/elements = {/,/}/p' | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u > "$temp_file"

    if [ -s "$temp_file" ]; then
        log_and_print "New IPs found in dynamic set for $name:" 2
        
        # Add only new IPs to the IP list
        while IFS= read -r ip; do
            if ! grep -q "^$ip$" "$ip_list"; then
                if [ -s "$ip_list" ] && [ "$(tail -c 1 "$ip_list")" != "" ]; then
                    # Ensure there's a newline at the end of the file
                    echo "" >> "$ip_list"
                fi
                echo "$ip" >> "$ip_list"
                log_and_print "  Added new IP: $ip" 2
            fi
        done < "$temp_file"

        # Trigger geolocation update only if new IPs were added
        if [ $(wc -l < "$temp_file") -gt 0 ]; then
            # Get the allowed regions
            local allowed_region
            config_get allowed_region "$1" 'allowed_region'
            
            # Process the geo data with correct parameter order:
            # $1: name, $2: allowed_set, $3: blocked_set, $@: allowed_regions
            process_geo_data "$name" "${set_name}_allowed" "${set_name}_blocked" "$allowed_region"
        fi
    else
        log_and_print "No new IPs in dynamic set for $name" 2
    fi

    rm -f "$temp_file"  # Delete the temporary file after processing
}

# Update dynamic IPs based on configuration
update_dynamic_ips() {
    config_load 'geomate'
    config_foreach process_dynamic_set 'geo_filter'
}

# Helper function to collect allowed_ip entries
append_allowed_ip() {
    allowed_ips="${allowed_ips}${1},"
}

# Process geo data from the JSON file
process_geo_data() {
    local name="$1"
    local allowed_set="$2"
    local blocked_set="$3"
    shift 3
    local allowed_regions="$*"
    local geo_data_file="${GEOMATE_DATA_DIR}/${name}_geo_data.json"

    [ ! -f "$geo_data_file" ] && { log_and_print "Geo data file not found: $geo_data_file" 0; return; }
    [ -z "$allowed_regions" ] && { log_and_print "No allowed regions specified for $name" 0; return; }

    log_and_print "Processing geo data for $name with allowed regions: $allowed_regions" 2

    local allowed_ips=""
    local blocked_ips=""

    # Use jq to parse the JSON and feed it into the loop via Here-Document
    while IFS="	" read -r ip lat lon; do
        [ -z "$ip" ] || [ -z "$lat" ] || [ -z "$lon" ] && continue
        log_and_print "Checking IP: $ip, Lat: $lat, Lon: $lon" 2

        # Check if IP is within any of the allowed regions
        if is_within_any_region "$lat" "$lon" "$allowed_regions"; then
            allowed_ips="${allowed_ips}${ip},"
            log_and_print "IP $ip is within allowed regions, added to $allowed_set" 2
        else
            blocked_ips="${blocked_ips}${ip},"
            log_and_print "IP $ip is outside allowed regions, added to $blocked_set" 2
        fi
    done <<EOF
$(jq -r '. | [.query, .lat, .lon] | @tsv' "$geo_data_file")
EOF

    # Remove the last comma
    allowed_ips=${allowed_ips%,}
    blocked_ips=${blocked_ips%,}

    # Batch update the sets
    [ -n "$allowed_ips" ] && nft add element inet geomate "$allowed_set" { "$allowed_ips" }
    [ -n "$blocked_ips" ] && nft add element inet geomate "$blocked_set" { "$blocked_ips" }

    log_and_print "Finished processing geo data for $name" 2
}

# Determine if coordinates are within a specific region
is_within_region() {
    local lat="$1"
    local lon="$2"
    local region="$3"

    local region_type=$(echo "$region" | cut -d':' -f1)

    case $region_type in
        "circle")
            local center_lat=$(echo "$region" | cut -d':' -f2)
            local center_lon=$(echo "$region" | cut -d':' -f3)
            local radius=$(echo "$region" | cut -d':' -f4)

            if is_within_circle "$lat" "$lon" "$center_lat" "$center_lon" "$radius"; then
                return 0
            else
                return 1
            fi
            ;;
        # Additional region types like "rectangle" or "polygon" can be added here
        *)
            log_and_print "Unknown region type: $region_type" 1
            return 1
            ;;
    esac
}

# Check if coordinates are within a circle using the Haversine formula
is_within_circle() {
    local lat1="$1"
    local lon1="$2"
    local lat2="$3"
    local lon2="$4"
    local radius="$5"

    # Haversine formula in awk
    local distance=$(awk -v lat1="$lat1" -v lon1="$lon1" -v lat2="$lat2" -v lon2="$lon2" '
    BEGIN {
        # Convert degrees to radians
        lat1 = lat1 * 3.14159 / 180;
        lon1 = lon1 * 3.14159 / 180;
        lat2 = lat2 * 3.14159 / 180;
        lon2 = lon2 * 3.14159 / 180;

        # Difference in coordinates
        dlat = lat2 - lat1;
        dlon = lon2 - lon1;

        # Haversine formula
        a = sin(dlat/2) * sin(dlat/2) + cos(lat1) * cos(lat2) * sin(dlon/2) * sin(dlon/2);
        c = 2 * atan2(sqrt(a), sqrt(1-a));
        earth_radius = 6371000;  # Earth radius in meters
        print earth_radius * c;  # Result in meters
    }')

    log_and_print "Distance calculation for $lat1,$lon1 to $lat2,$lon2: distance=$distance, radius=$radius" 2

    if [ $(awk -v distance="$distance" -v radius="$radius" 'BEGIN {print (distance <= radius) ? 1 : 0}') -eq 1 ]; then
        log_and_print "IP is within the circle (distance: $distance, radius: $radius)" 2
        return 0  # Within the circle
    else
        log_and_print "IP is outside the circle (distance: $distance, radius: $radius)" 2
        return 1  # Outside the circle
    fi
}

# Verify the nftables rules to ensure they are set up correctly
verify_nftables_rules() {
    log_and_print "Verifying nftables rules..." 1
    
    local table_output=$(nft list table inet geomate)
    log_and_print "Full table output:" 2
    echo "$table_output"
    
    local prerouting_rules=$(echo "$table_output" | sed -n '/chain prerouting {/,/}/p')
    if [ -z "$prerouting_rules" ]; then
        log_and_print "No rules found in prerouting chain!" 0
    else
        log_and_print "Rules in prerouting chain:" 2
        echo "$prerouting_rules"
    fi
    
    # Check if dynamic sets have been created
    local dynamic_sets=$(echo "$table_output" | sed -n '/set.*dynamic/,/}/p')
    if [ -z "$dynamic_sets" ]; then
        log_and_print "No dynamic sets found!" 0
    else
        log_and_print "Dynamic sets:" 2
        echo "$dynamic_sets"
    fi

    # Display all chains
    log_and_print "All chains:" 2
    echo "$table_output" | sed -n '/chain/,/}/p'

    # Show the number of rules in each chain
    log_and_print "Rule count per chain:" 2
    echo "$table_output" | grep -c 'chain prerouting' | xargs echo "prerouting:"
    echo "$table_output" | grep -c 'chain forward' | xargs echo "forward:"
}

# Execute the Geomate trigger script
run_geomate_trigger() {
    /etc/geomate_trigger.sh
}

# Manually trigger a geolocation update
trigger_geolocation() {
    log_and_print "Manually triggering geolocation update" 1
    run_geomate_trigger
}

# Main function to run the service
run() {
    load_config
    setup_geomate_d

    # Create loading flag file
    log_and_print "Creating loading flag file at /tmp/geomate_loading" 1
    touch /tmp/geomate_loading

    setup_nftables_and_filters

    # Remove loading flag file
    log_and_print "Removing loading flag file at /tmp/geomate_loading" 1
    rm -f /tmp/geomate_loading

    log_and_print "Service is running" 0
    echo $$ > "/var/run/geomate.pid"
    
    # If in static mode, we don't need to run the monitoring loop
    if [ "$operational_mode" = "static" ]; then
        log_and_print "Running in static mode - checking for IP list changes" 1
        
        while true; do
            # Run geomate trigger to check for IP list changes and daily updates
            run_geomate_trigger
            sleep 3600  # Check every hour (3600 seconds)
        done
    fi
    
    SLEEP_DURATION=60  # Desired sleep duration
    CHECK_INTERVAL=1800  # Interval in seconds (1800 seconds = 30 minutes)

    last_check_time=$(date +%s)

    while true; do
        current_time=$(date +%s)
        
        # Calculate the remaining time until the next interval
        elapsed_time=$((current_time - last_check_time))
        remaining_time=$((CHECK_INTERVAL - elapsed_time))
        
        if [ $remaining_time -le 0 ]; then
            # Only perform dynamic updates in dynamic mode
            update_dynamic_ips
            run_geomate_trigger
            last_check_time=$current_time
            remaining_time=$CHECK_INTERVAL
        fi

        # Sleep for the minimum time between SLEEP_DURATION and remaining_time
        sleep_duration=$SLEEP_DURATION
        if [ $remaining_time -lt $SLEEP_DURATION ]; then
            sleep_duration=$remaining_time
        fi

        sleep $sleep_duration
    done
}

# Clean up nftables rules when the service is stopped
cleanup_nftables() {
    log_and_print "Cleaning up nftables rules..." 1
    nft delete table inet geomate 2>/dev/null
    log_and_print "nftables rules cleaned up" 1
}

# Handle script arguments
case "$1" in
    cleanup)
        cleanup_nftables
        ;;
    run)
        run
        ;;
    *)
        echo "Usage: $0 {run|cleanup}"
        exit 1
esac

exit 0
