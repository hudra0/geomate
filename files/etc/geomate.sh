#!/bin/sh

# shellcheck shell=ash
# shellcheck disable=SC3043  # ash supports local variables
# shellcheck disable=SC2317  # Functions are called by OpenWrt's system
# shellcheck disable=SC2329  # Functions are invoked indirectly via config_foreach
# shellcheck disable=SC2155  # Combined declaration and assignment is fine for our use case
# shellcheck disable=SC1083  # nft syntax requires literal braces
# shellcheck disable=SC1091  # OpenWrt's /lib/functions.sh is not available during shellcheck
# shellcheck disable=SC2154  # Variables are assigned by OpenWrt's config_load
# shellcheck disable=SC2181  # Using $? is intentional for clarity in error handling
# shellcheck disable=SC2002  # cat with pipe is used for readability in error log processing

. /lib/functions.sh

GEOMATE_DATA_DIR="/etc/geomate.d"
GEOMATE_RUNTIME_DIR="${GEOMATE_DATA_DIR}/runtime"
GEOMATE_TMP_DIR="/tmp/geomate"
NFT_ERROR_LOG="/tmp/geomate_nft_errors.log"
NFT_SET_PREFIX="geomate_"
CHECK_INTERVAL=1800  # Interval in seconds (30 minutes) - used for geolocation status
debug_level=0

# Wrapper for nft commands with error logging
# Logs failed commands to error log file for debugging
nft_exec() {
    local result rv
    result=$(nft "$@" 2>&1)
    rv=$?
    if [ $rv -ne 0 ]; then
        log_and_print "nft command failed: nft $*" 0
        log_and_print "Error: $result" 0
        printf '[%s] nft %s -> Error: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "$result" >> "$NFT_ERROR_LOG"
    fi
    return $rv
}

# Load configuration settings
load_config() {
    config_load 'geomate'
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

# Check if an IP is a valid public IP (not private/reserved)
# Returns 0 (true) for public IPs, 1 (false) for private/invalid IPs
is_valid_public_ip() {
    local ip="$1"
    case "$ip" in
        # Private networks (RFC 1918)
        10.*) return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 1 ;;
        192.168.*) return 1 ;;
        # Loopback
        127.*) return 1 ;;
        # Link-local
        169.254.*) return 1 ;;
        # Reserved/Invalid
        0.*) return 1 ;;
        # Multicast and reserved
        224.*|225.*|226.*|227.*|228.*|229.*|230.*|231.*) return 1 ;;
        232.*|233.*|234.*|235.*|236.*|237.*|238.*|239.*) return 1 ;;
        # Future use
        240.*|241.*|242.*|243.*|244.*|245.*|246.*|247.*) return 1 ;;
        248.*|249.*|250.*|251.*|252.*|253.*|254.*|255.*) return 1 ;;
        # Valid public IP
        *) return 0 ;;
    esac
}

# Clean up expired IPs from IP lists based on ip_expiry_days setting per filter
# Format: IP or IP,timestamp - IPs without timestamp are treated as "today"
cleanup_expired_ips_for_filter() {
    local name="$1"
    local ip_list="$2"
    local expiry_days="$3"
    
    # If expiry is 0 or not set, do nothing (disabled)
    [ -z "$expiry_days" ] || [ "$expiry_days" = "0" ] && return 0
    
    [ ! -f "$ip_list" ] && return 0
    
    local current_time=$(date +%s)
    local expiry_seconds=$((expiry_days * 86400))
    local cutoff_time=$((current_time - expiry_seconds))
    local temp_file="${ip_list}.cleanup_tmp"
    local removed_count=0
    local kept_count=0
    
    log_and_print "Cleaning up expired IPs for $name (expiry: $expiry_days days)" 2
    
    # Process each line
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        
        # Parse IP and timestamp (format: IP or IP,timestamp)
        local ip timestamp
        case "$line" in
            *,*)
                ip="${line%%,*}"
                timestamp="${line#*,}"
                ;;
            *)
                ip="$line"
                # No timestamp = treat as today (won't be expired)
                timestamp="$current_time"
                ;;
        esac
        
        # Check if expired
        if [ "$timestamp" -lt "$cutoff_time" ] 2>/dev/null; then
            removed_count=$((removed_count + 1))
            log_and_print "  Removed expired IP: $ip (last seen: $timestamp)" 3
        else
            # Keep the IP with its timestamp
            echo "${ip},${timestamp}" >> "$temp_file"
            kept_count=$((kept_count + 1))
        fi
    done < "$ip_list"
    
    # Replace original file atomically
    if [ -f "$temp_file" ]; then
        mv "$temp_file" "$ip_list"
    else
        # All IPs expired, create empty file
        : > "$ip_list"
    fi
    
    [ "$removed_count" -gt 0 ] && log_and_print "Removed $removed_count expired IPs for $name, kept $kept_count" 1
    
    return 0
}

# Process all filters and clean up expired IPs
cleanup_all_expired_ips() {
    log_and_print "Checking for expired IPs in all filters..." 2
    config_load 'geomate'
    config_foreach cleanup_filter_ips 'geo_filter'
}

# Helper function called by config_foreach
cleanup_filter_ips() {
    local name ip_list expiry_days enabled
    config_get name "$1" 'name'
    config_get ip_list "$1" 'ip_list'
    config_get expiry_days "$1" 'ip_expiry_days' '0'
    config_get enabled "$1" 'enabled' '0'
    
    # Only process enabled filters with expiry > 0
    [ "$enabled" = "1" ] && [ "$expiry_days" != "0" ] && \
        cleanup_expired_ips_for_filter "$name" "$ip_list" "$expiry_days"
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
    
    # Log operational mode
    if [ "$operational_mode" = "monitor" ]; then
        log_and_print "Running in MONITOR MODE - connections will be tracked but NOT blocked" 0
    fi
    
    # Delete existing table and recreate it
    nft delete table inet geomate 2>/dev/null
    nft_exec add table inet geomate
    nft_exec add chain inet geomate forward { type filter hook forward priority -150 \; policy accept \; }
    nft_exec add chain inet geomate prerouting { type filter hook prerouting priority -150 \; policy accept \; }

    # Set up filters from configuration
    config_load 'geomate'
    config_foreach setup_geo_filter 'geo_filter'
    config_foreach create_dynamic_set 'geo_filter'

    # Add a catch-all rule based on strict_mode - but not in monitor mode
    if [ "$operational_mode" = "monitor" ]; then
        log_and_print "Monitor mode: No blocking rules will be applied" 1
    elif [ "$strict_mode" = "1" ]; then
        log_and_print "Strict mode enabled: No default forward policy set" 1
    else
        nft_exec add rule inet geomate forward counter accept
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
    nft_exec add set inet geomate "${set_name}_allowed" { type ipv4_addr\; flags interval\; }
    nft_exec add set inet geomate "${set_name}_blocked" { type ipv4_addr\; flags interval\; }

    # Add allowed IPs
    config_list_foreach "$1" 'allowed_ip' append_allowed_ip
    if [ -n "$allowed_ips" ]; then
        allowed_ips=${allowed_ips%,}
        log_and_print "Manually adding allowed IPs: $allowed_ips" 2
        nft_exec add element inet geomate "${set_name}_allowed" { "$allowed_ips" }
    fi

    # Add blocked IPs
    if [ -n "$blocked_ips" ]; then
        log_and_print "Manually adding blocked IPs: $blocked_ips" 2
        nft_exec add element inet geomate "${set_name}_blocked" { "$blocked_ips" }
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
    local has_sport=0
    if [ -n "$src_port" ] && [ "$src_port" != "any" ]; then
        has_sport=1
        # Check if multiple values (separated by space) - need braces
        if echo "$src_port" | grep -q ' '; then
            src_port=$(echo "$src_port" | tr ' ' ',')
            base_rule="$base_rule sport { $src_port }"
        else
            # Single value (port or range) - no braces needed
            base_rule="$base_rule sport $src_port"
        fi
    fi

    # Include dest_port in the rule if set
    if [ -n "$dest_port" ] && [ "$dest_port" != "any" ]; then
        [ "$has_sport" = "1" ] && [ -n "$protocol" ] && base_rule="$base_rule $protocol"
        # Check if multiple values (separated by space) - need braces
        if echo "$dest_port" | grep -q ' '; then
            dest_port=$(echo "$dest_port" | tr ' ' ',')
            base_rule="$base_rule dport { $dest_port }"
        else
            # Single value (port or range) - no braces needed
            base_rule="$base_rule dport $dest_port"
        fi
    fi

    # Add forward rule for allowed IPs with error checking
    log_and_print "Adding forward rule: $base_rule ip daddr @${set_name}_allowed counter accept" 2
    if ! nft add rule inet geomate forward "$base_rule" ip daddr @"${set_name}"_allowed counter accept 2>&1 | tee $NFT_ERROR_LOG | grep -q .; then
        log_and_print "Successfully added forward rule for allowed IPs in $name" 2
    else
        log_and_print "ERROR: Failed to add forward rule for $name! Check $NFT_ERROR_LOG" 0
        log_and_print "Rule was: $base_rule ip daddr @${set_name}_allowed counter accept" 0
        cat $NFT_ERROR_LOG | while read -r line; do log_and_print "nft error: $line" 0; done
    fi
    
    # Only add drop rule if not in monitor mode
    if [ "$operational_mode" != "monitor" ]; then
        log_and_print "Adding drop rule: $base_rule ip daddr @${set_name}_blocked counter drop" 2
        if ! nft add rule inet geomate forward "$base_rule" ip daddr @"${set_name}"_blocked counter drop 2>&1 | tee $NFT_ERROR_LOG | grep -q .; then
            log_and_print "Successfully added drop rule for blocked IPs in $name" 2
        else
            log_and_print "ERROR: Failed to add drop rule for $name! Check $NFT_ERROR_LOG" 0
            log_and_print "Rule was: $base_rule ip daddr @${set_name}_blocked counter drop" 0
            cat $NFT_ERROR_LOG | while read -r line; do log_and_print "nft error: $line" 0; done
        fi
    else
        log_and_print "Monitor mode: Not adding drop rule for blocked IPs in $name" 2
    fi

    # Strict mode rule - only apply if not in monitor mode
    if [ "$strict_mode" = "1" ] && [ "$operational_mode" != "monitor" ]; then
        log_and_print "Strict mode: Adding default drop rule: $base_rule counter drop" 2
        if ! nft add rule inet geomate forward "$base_rule" counter drop 2>&1 | tee $NFT_ERROR_LOG | grep -q .; then
            log_and_print "Strict mode: Successfully added default drop rule for $name" 2
        else
            log_and_print "ERROR: Strict mode - Failed to add default drop rule for $name!" 0
            cat $NFT_ERROR_LOG | while read -r line; do log_and_print "nft error: $line" 0; done
        fi
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
    nft_exec add set inet geomate "${set_name}_ui_dynamic" { type ipv4_addr\; flags dynamic,timeout\; timeout 10s\; }

    # Only create main dynamic set in dynamic mode
    if [ "$operational_mode" != "static" ]; then
        # Create existing dynamic set with 1-hour timeout
        nft_exec add set inet geomate "${set_name}_dynamic" { type ipv4_addr\; flags dynamic,timeout\; timeout 1h\; }
    fi

    # Create the base rule
    local base_rule=""
    [ -n "$src_ip" ] && base_rule="ip saddr $src_ip"
    [ -n "$protocol" ] && base_rule="$base_rule $protocol"

    # Include src_port in the rule if set
    local has_sport=0
    if [ -n "$src_port" ] && [ "$src_port" != "any" ]; then
        has_sport=1
        # Check if multiple values (separated by space) - need braces
        if echo "$src_port" | grep -q ' '; then
            src_port=$(echo "$src_port" | tr ' ' ',')
            base_rule="$base_rule sport { $src_port }"
        else
            # Single value (port or range) - no braces needed
            base_rule="$base_rule sport $src_port"
        fi
    fi

    # Include dest_port in the rule if set
    if [ -n "$dest_port" ] && [ "$dest_port" != "any" ]; then
        [ "$has_sport" = "1" ] && [ -n "$protocol" ] && base_rule="$base_rule $protocol"
        # Check if multiple values (separated by space) - need braces
        if echo "$dest_port" | grep -q ' '; then
            dest_port=$(echo "$dest_port" | tr ' ' ',')
            base_rule="$base_rule dport { $dest_port }"
        else
            # Single value (port or range) - no braces needed
            base_rule="$base_rule dport $dest_port"
        fi
    fi

    # Add rule for the ui dynamic set (always needed) with error checking
    log_and_print "Adding prerouting rule for UI: $base_rule update @${set_name}_ui_dynamic { ip daddr }" 2
    if ! nft add rule inet geomate prerouting "$base_rule" update @"${set_name}"_ui_dynamic { ip daddr } 2>&1 | tee $NFT_ERROR_LOG | grep -q .; then
        log_and_print "Successfully added UI dynamic set rule for $name" 2
    else
        log_and_print "ERROR: Failed to add UI dynamic set rule for $name! Check $NFT_ERROR_LOG" 0
        log_and_print "Rule was: $base_rule update @${set_name}_ui_dynamic { ip daddr }" 0
        cat $NFT_ERROR_LOG | while read -r line; do log_and_print "nft error: $line" 0; done
    fi

    # Add rule for the main dynamic set only in dynamic mode
    if [ "$operational_mode" != "static" ]; then
        log_and_print "Adding prerouting rule for dynamic set: $base_rule update @${set_name}_dynamic { ip daddr }" 2
        if ! nft add rule inet geomate prerouting "$base_rule" update @"${set_name}"_dynamic { ip daddr } 2>&1 | tee $NFT_ERROR_LOG | grep -q .; then
            log_and_print "Successfully added main dynamic set rule for $name" 2
        else
            log_and_print "ERROR: Failed to add main dynamic set rule for $name! Check $NFT_ERROR_LOG" 0
            log_and_print "Rule was: $base_rule update @${set_name}_dynamic { ip daddr }" 0
            cat $NFT_ERROR_LOG | while read -r line; do log_and_print "nft error: $line" 0; done
        fi
    fi

    log_and_print "Sets for $name set up successfully" 1
}

# Process dynamic sets for a given configuration
process_dynamic_set() {
    local name ip_list expiry_days
    config_get name "$1" 'name'
    config_get ip_list "$1" 'ip_list'
    config_get expiry_days "$1" 'ip_expiry_days' '0'
    local set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"

    log_and_print "Processing dynamic set for $name" 2

    local temp_file="/tmp/geomate_${set_name}_temp.txt"
    local ip_list_tmp="${ip_list}.tmp"

    # Retrieve IPs from the dynamic set
    nft list set inet geomate "${set_name}_dynamic" | sed -n '/elements = {/,/}/p' | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u > "$temp_file"

    if [ -s "$temp_file" ]; then
        log_and_print "New IPs found in dynamic set for $name:" 2
        
        local added_count=0 skipped_private=0 updated_count=0
        local current_time=$(date +%s)
        
        # Build list of new IPs to add and IPs to update timestamps for
        local new_ips_file="/tmp/geomate_${set_name}_new.txt"
        local update_ips_file="/tmp/geomate_${set_name}_update.txt"
        : > "$new_ips_file"
        : > "$update_ips_file"
        
        while IFS= read -r ip; do
            # Skip private/invalid IPs
            if ! is_valid_public_ip "$ip"; then
                skipped_private=$((skipped_private + 1))
                log_and_print "  Skipped private/invalid IP: $ip" 3
                continue
            fi
            
            # Check if IP already exists (with or without timestamp)
            if grep -q "^${ip}\(,\|$\)" "$ip_list" 2>/dev/null; then
                # IP exists - mark for timestamp update if expiry enabled
                if [ "$expiry_days" != "0" ]; then
                    echo "$ip" >> "$update_ips_file"
                    updated_count=$((updated_count + 1))
                    log_and_print "  Will update timestamp for IP: $ip" 3
                fi
            else
                # New IP - add to new IPs list
                echo "$ip" >> "$new_ips_file"
                added_count=$((added_count + 1))
                log_and_print "  Will add new IP: $ip" 2
            fi
        done < "$temp_file"

        [ "$skipped_private" -gt 0 ] && log_and_print "Skipped $skipped_private private/invalid IPs for $name" 2

        # Only write to flash if there are changes
        if [ "$added_count" -gt 0 ] || [ "$updated_count" -gt 0 ]; then
            {
                # Process existing IPs - update timestamps where needed
                if [ -f "$ip_list" ]; then
                    while IFS= read -r line || [ -n "$line" ]; do
                        [ -z "$line" ] && continue
                        local existing_ip="${line%%,*}"
                        
                        # Check if this IP needs timestamp update
                        if grep -q "^${existing_ip}$" "$update_ips_file" 2>/dev/null; then
                            # Update timestamp
                            echo "${existing_ip},${current_time}"
                        else
                            # Keep as-is
                            echo "$line"
                        fi
                    done < "$ip_list"
                fi
                
                # Add new IPs
                while IFS= read -r new_ip || [ -n "$new_ip" ]; do
                    [ -z "$new_ip" ] && continue
                    if [ "$expiry_days" != "0" ]; then
                        echo "${new_ip},${current_time}"
                    else
                        echo "$new_ip"
                    fi
                done < "$new_ips_file"
            } > "$ip_list_tmp"
            
            # Atomic move to replace original
            mv "$ip_list_tmp" "$ip_list"
            log_and_print "Updated IP list for $name: $added_count added, $updated_count timestamps updated" 2
        fi
        
        # Cleanup temp files
        rm -f "$new_ips_file" "$update_ips_file"

        # Trigger geolocation update only if new IPs were added
        if [ "$added_count" -gt 0 ]; then
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
    
    # Write geolocation status after processing
    write_geolocation_status
}

# Write geolocation status to JSON file for UI/CLI consumption
# This is called once per cycle (every 30 min) - minimal performance impact
write_geolocation_status() {
    local status_file="${GEOMATE_RUNTIME_DIR}/geolocation_status.json"
    local current_time
    local next_cycle
    local last_geolocate=0
    local geolocate_interval=1800
    local pending_ips=0
    local last_daily=0
    local geolocation_mode_cfg
    
    current_time=$(date +%s)
    next_cycle=$((current_time + CHECK_INTERVAL))
    
    # Get config values
    config_load 'geomate'
    local operational_mode_cfg
    config_get operational_mode_cfg global operational_mode 'dynamic'
    config_get geolocation_mode_cfg global geolocation_mode 'frequent'
    
    # Read geolocation timing info (frequent mode)
    [ -f "${GEOMATE_RUNTIME_DIR}/last_geolocate_run" ] && last_geolocate=$(cat "${GEOMATE_RUNTIME_DIR}/last_geolocate_run")
    [ -f "${GEOMATE_RUNTIME_DIR}/last_geolocate_run.interval" ] && geolocate_interval=$(cat "${GEOMATE_RUNTIME_DIR}/last_geolocate_run.interval")
    [ -f "${GEOMATE_RUNTIME_DIR}/new_ips.txt" ] && pending_ips=$(wc -l < "${GEOMATE_RUNTIME_DIR}/new_ips.txt" 2>/dev/null || echo 0)
    
    # Read daily geolocation timing
    [ -f "${GEOMATE_RUNTIME_DIR}/last_geolocate_run.daily" ] && last_daily=$(cat "${GEOMATE_RUNTIME_DIR}/last_geolocate_run.daily")
    
    # Start JSON
    printf '{\n' > "$status_file"
    printf '  "timestamp": %s,\n' "$current_time" >> "$status_file"
    printf '  "next_cycle": %s,\n' "$next_cycle" >> "$status_file"
    printf '  "cycle_interval": %s,\n' "${CHECK_INTERVAL:-1800}" >> "$status_file"
    printf '  "operational_mode": "%s",\n' "$operational_mode_cfg" >> "$status_file"
    printf '  "geolocation_mode": "%s",\n' "$geolocation_mode_cfg" >> "$status_file"
    
    # Geolocation info (frequent)
    printf '  "geolocation": {\n' >> "$status_file"
    printf '    "last_run": %s,\n' "$last_geolocate" >> "$status_file"
    printf '    "interval": %s,\n' "$geolocate_interval" >> "$status_file"
    printf '    "next_run": %s,\n' "$((last_geolocate + geolocate_interval))" >> "$status_file"
    printf '    "pending_ips": %s\n' "$pending_ips" >> "$status_file"
    printf '  },\n' >> "$status_file"
    
    # Daily geolocation info
    printf '  "geolocation_daily": {\n' >> "$status_file"
    printf '    "last_run": %s,\n' "$last_daily" >> "$status_file"
    printf '    "interval": 86400,\n' >> "$status_file"
    printf '    "next_run": %s\n' "$((last_daily + 86400))" >> "$status_file"
    printf '  },\n' >> "$status_file"
    
    # Collect filter stats
    printf '  "filters": {\n' >> "$status_file"
    
    local first_filter=1
    collect_filter_stats() {
        local name ip_list geo_data_file
        local total_ips=0 geolocated_ips=0
        
        config_get name "$1" 'name'
        config_get ip_list "$1" 'ip_list'
        geo_data_file="${GEOMATE_DATA_DIR}/${name}_geo_data.json"
        
        # Count IPs in list file
        [ -f "$ip_list" ] && total_ips=$(wc -l < "$ip_list" 2>/dev/null || echo 0)
        
        # Count geolocated IPs (lines in geo_data.json)
        [ -f "$geo_data_file" ] && geolocated_ips=$(wc -l < "$geo_data_file" 2>/dev/null || echo 0)
        
        # Add comma before all but first filter
        if [ "$first_filter" = "1" ]; then
            first_filter=0
        else
            printf ',\n' >> "$status_file"
        fi
        
        # Escape filter name for JSON (replace quotes)
        local escaped_name
        escaped_name=$(echo "$name" | sed 's/"/\\"/g')
        
        printf '    "%s": {\n' "$escaped_name" >> "$status_file"
        printf '      "total_ips": %s,\n' "$total_ips" >> "$status_file"
        printf '      "geolocated": %s\n' "$geolocated_ips" >> "$status_file"
        printf '    }' >> "$status_file"
    }
    
    config_load 'geomate'
    config_foreach collect_filter_stats 'geo_filter'
    
    printf '\n  }\n' >> "$status_file"
    printf '}\n' >> "$status_file"
    
    log_and_print "Geolocation status updated: $status_file" 2
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

    # PERFORMANCE OPTIMIZATION: Process ALL IPs in a SINGLE awk process
    # Instead of spawning a new awk process for each IP (11000+ processes),
    # we do everything in one pass: parse regions, calculate haversine, categorize IPs
    # Output format: First line = comma-separated allowed IPs, Second line = comma-separated blocked IPs
    local result
    result=$(jq -r '. | [.query, .lat, .lon] | @tsv' "$geo_data_file" 2>/dev/null | \
        awk -v regions="$allowed_regions" '
        function haversine(lat1, lon1, lat2, lon2) {
            # Convert degrees to radians
            lat1 = lat1 * 3.14159265359 / 180
            lon1 = lon1 * 3.14159265359 / 180
            lat2 = lat2 * 3.14159265359 / 180
            lon2 = lon2 * 3.14159265359 / 180
            
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            
            a = sin(dlat/2)^2 + cos(lat1) * cos(lat2) * sin(dlon/2)^2
            c = 2 * atan2(sqrt(a), sqrt(1-a))
            return 6371000 * c  # Earth radius in meters
        }
        BEGIN {
            FS = "\t"
            allowed_list = ""
            blocked_list = ""
            # Parse all regions (format: "circle:lat:lon:radius circle:lat:lon:radius ...")
            n_regions = split(regions, region_arr, " ")
            for (i = 1; i <= n_regions; i++) {
                n_parts = split(region_arr[i], parts, ":")
                if (parts[1] == "circle" && n_parts >= 4) {
                    region_type[i] = "circle"
                    region_lat[i] = parts[2] + 0  # Force numeric
                    region_lon[i] = parts[3] + 0
                    region_radius[i] = parts[4] + 0
                }
            }
        }
        {
            ip = $1
            lat = $2 + 0  # Force numeric
            lon = $3 + 0
            
            # Skip invalid entries
            if (ip == "" || $2 == "" || $3 == "") next
            
            # Check if IP is within ANY allowed region
            allowed = 0
            for (i = 1; i <= n_regions; i++) {
                if (region_type[i] == "circle") {
                    dist = haversine(lat, lon, region_lat[i], region_lon[i])
                    if (dist <= region_radius[i]) {
                        allowed = 1
                        break
                    }
                }
            }
            
            # Append to appropriate list
            if (allowed) {
                if (allowed_list != "") allowed_list = allowed_list ","
                allowed_list = allowed_list ip
            } else {
                if (blocked_list != "") blocked_list = blocked_list ","
                blocked_list = blocked_list ip
            }
        }
        END {
            # Output two lines: allowed IPs, then blocked IPs
            print allowed_list
            print blocked_list
        }')

    # Parse the two-line result
    local allowed_ips blocked_ips
    allowed_ips=$(echo "$result" | sed -n '1p')
    blocked_ips=$(echo "$result" | sed -n '2p')

    # Count IPs for logging
    local allowed_count=0 blocked_count=0
    [ -n "$allowed_ips" ] && allowed_count=$(echo "$allowed_ips" | tr ',' '\n' | wc -l)
    [ -n "$blocked_ips" ] && blocked_count=$(echo "$blocked_ips" | tr ',' '\n' | wc -l)
    log_and_print "Geo processing for $name: $allowed_count allowed, $blocked_count blocked IPs" 1

    # Batch update the sets - handling potential large IP lists
    add_ips_to_set() {
        local set_name="$1"
        local ip_list="$2"
        local chunk_size=1000
        local total_ips
        local start=1
        local success=1
        local end chunk nft_cmd error_output ret
        
        [ -z "$ip_list" ] && return 0
        
        total_ips=$(echo "$ip_list" | tr ',' '\n' | wc -l)
        log_and_print "Adding IPs to $set_name, total IPs: $total_ips" 2
        
        # Process in smaller chunks to avoid command line limits
        while [ "$start" -le "$total_ips" ]; do
            end=$((start + chunk_size - 1))
            [ "$end" -gt "$total_ips" ] && end="$total_ips"
            
            # Extract chunk of IPs
            chunk=$(echo "$ip_list" | tr ',' '\n' | sed -n "${start},${end}p" | tr '\n' ',' | sed 's/,$//')
            
            log_and_print "Processing IPs $start to $end of $total_ips" 3
            
            # Execute nft command for this chunk
            nft_cmd="nft add element inet geomate \"$set_name\" { $chunk }"
            error_output=$(eval "$nft_cmd" 2>&1)
            ret=$?
            
            if [ "$ret" -ne 0 ]; then
                log_and_print "ERROR: Failed to add IPs (chunk $start-$end) to set $set_name: $error_output" 0
                success=0
            fi
            
            start=$((end + 1))
        done
        
        return "$success"
    }
    
    # Add allowed IPs to set
    [ -n "$allowed_ips" ] && add_ips_to_set "$allowed_set" "$allowed_ips"
    
    # Add blocked IPs to set
    [ -n "$blocked_ips" ] && add_ips_to_set "$blocked_set" "$blocked_ips"

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

    if [ "$(awk -v distance="$distance" -v radius="$radius" 'BEGIN {print (distance <= radius) ? 1 : 0}')" -eq 1 ]; then
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
    
    # Count actual rules (not just chain definitions)
    local prerouting_rule_count=$(echo "$table_output" | sed -n '/chain prerouting {/,/}/p' | grep -c 'update\|counter\|accept\|drop' || echo "0")
    local forward_rule_count=$(echo "$table_output" | sed -n '/chain forward {/,/}/p' | grep -c 'update\|counter\|accept\|drop' || echo "0")
    
    log_and_print "Rule count analysis:" 1
    log_and_print "  Prerouting chain: $prerouting_rule_count rules" 1
    log_and_print "  Forward chain: $forward_rule_count rules" 1
    
    # Critical warnings if chains are empty
    if [ "$prerouting_rule_count" -eq 0 ]; then
        log_and_print "WARNING: No rules in prerouting chain! IP collection will NOT work!" 0
        log_and_print "This usually means there was an error creating the nft rules." 0
        log_and_print "Check $NFT_ERROR_LOG for details." 0
    else
        log_and_print "✓ Prerouting chain has rules - IP collection should work" 1
    fi
    
    if [ "$forward_rule_count" -eq 0 ] && [ "$operational_mode" != "monitor" ]; then
        log_and_print "WARNING: No rules in forward chain! Filtering will NOT work!" 0
        log_and_print "This usually means there was an error creating the nft rules." 0
        log_and_print "Check $NFT_ERROR_LOG for details." 0
    else
        if [ "$operational_mode" = "monitor" ]; then
            log_and_print "Monitor mode: Forward chain rules not required" 1
        else
            log_and_print "✓ Forward chain has rules - filtering should work" 1
        fi
    fi
    
    # Show the actual rules in prerouting
    local prerouting_rules=$(echo "$table_output" | sed -n '/chain prerouting {/,/}/p')
    if [ -n "$prerouting_rules" ]; then
        log_and_print "Rules in prerouting chain:" 2
        echo "$prerouting_rules"
    fi
    
    # Show the actual rules in forward
    local forward_rules=$(echo "$table_output" | sed -n '/chain forward {/,/}/p')
    if [ -n "$forward_rules" ]; then
        log_and_print "Rules in forward chain:" 2
        echo "$forward_rules"
    fi
    
    # Check if dynamic sets have been created
    local dynamic_sets=$(echo "$table_output" | sed -n '/set.*dynamic/,/}/p')
    if [ -z "$dynamic_sets" ]; then
        log_and_print "No dynamic sets found!" 0
    else
        log_and_print "Dynamic sets:" 2
        echo "$dynamic_sets"
    fi
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

    # Clean up expired IPs before loading filters
    cleanup_all_expired_ips

    # Create loading flag file
    log_and_print "Creating loading flag file at /tmp/geomate_loading" 1
    touch /tmp/geomate_loading

    setup_nftables_and_filters

    # Remove loading flag file
    log_and_print "Removing loading flag file at /tmp/geomate_loading" 1
    rm -f /tmp/geomate_loading

    # Write initial geolocation status
    write_geolocation_status

    log_and_print "Service is running" 0
    echo $$ > "/var/run/geomate.pid"
    
    # Log operational mode at startup
    if [ "$operational_mode" = "monitor" ]; then
        log_and_print "MONITOR MODE ACTIVE - Connections are tracked but NOT blocked" 0
    elif [ "$operational_mode" = "static" ]; then
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
