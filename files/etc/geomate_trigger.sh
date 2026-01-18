#!/bin/sh

# shellcheck shell=ash
# shellcheck disable=SC3043  # ash supports local variables
# shellcheck disable=SC2317  # Functions are called by OpenWrt's system
# shellcheck disable=SC2329  # Functions are invoked indirectly via config_foreach
# shellcheck disable=SC2155  # Combined declaration and assignment is fine for our use case
# shellcheck disable=SC1091  # OpenWrt's /lib/functions.sh is not available during shellcheck
# shellcheck disable=SC2154  # Variables are assigned by OpenWrt's config_load
# shellcheck disable=SC2181  # Using $? is intentional for clarity in error handling

. /lib/functions.sh
config_load 'geomate'
config_get debug_level global debug_level '0'

GEOMATE_DATA_DIR="/etc/geomate.d"
GEOMATE_RUNTIME_DIR="${GEOMATE_DATA_DIR}/runtime"
LAST_RUN_FILE="${GEOMATE_RUNTIME_DIR}/last_geolocate_run"
NEW_IPS_FILE="${GEOMATE_RUNTIME_DIR}/new_ips.txt"
MIN_GEOLOCATE_INTERVAL=1800  # Minimum interval in seconds (30 minutes)
MAX_GEOLOCATE_INTERVAL=3600  # Maximum interval in seconds (1 hour)
RATE_LIMIT=15  # Maximum number of API calls per minute

# Logs and prints messages based on the debug level
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

# Checks if geolocation should be run and executes it if necessary
check_and_run_geolocate() {
    local current_time=$(date +%s)
    local last_geolocate_time=0
    local geolocate_interval=$MIN_GEOLOCATE_INTERVAL
    local new_ips_count=0
    local geolocation_mode
    
    config_get geolocation_mode global geolocation_mode 'frequent'

    [ -f "$LAST_RUN_FILE" ] && last_geolocate_time=$(cat "$LAST_RUN_FILE")
    [ -f "${LAST_RUN_FILE}.interval" ] && geolocate_interval=$(cat "${LAST_RUN_FILE}.interval")

    check_new_ips

    new_ips_count=$(wc -l < "$NEW_IPS_FILE")

    # Check if it's time for the daily update
    local last_daily_update=0
    [ -f "${LAST_RUN_FILE}.daily" ] && last_daily_update=$(cat "${LAST_RUN_FILE}.daily")
    if [ $((current_time - last_daily_update)) -ge 86400 ]; then  # 86400 seconds = 24 hours
        log_and_print "Geomate_Trigger: Starting daily update of all IPs" 1
        /etc/geolocate.sh daily
        echo "$current_time" > "${LAST_RUN_FILE}.daily"
    fi

    # Only do frequent updates if mode is 'frequent'
    if [ "$geolocation_mode" = "frequent" ] && [ $((current_time - last_geolocate_time)) -ge "$geolocate_interval" ]; then
        local time_since_last_run=$((current_time - last_geolocate_time))
        local api_calls_allowed=$((RATE_LIMIT * (time_since_last_run / 60 + 1)))
        local ips_to_process=$((new_ips_count < api_calls_allowed ? new_ips_count : api_calls_allowed))

        if [ $ips_to_process -gt 0 ]; then
            log_and_print "Geomate_Trigger: Processing $ips_to_process new IPs for geolocation" 1
            process_batch_specific_ips "$ips_to_process"
            last_geolocate_time=$current_time
        fi

        # Trigger geolocation update only if new IPs have been added
        if [ $ips_to_process -gt 0 ]; then
            geolocate_interval=$MIN_GEOLOCATE_INTERVAL
        else
            geolocate_interval=$((geolocate_interval * 2))
            [ $geolocate_interval -gt $MAX_GEOLOCATE_INTERVAL ] && geolocate_interval=$MAX_GEOLOCATE_INTERVAL
        fi
        echo "$geolocate_interval" > "${LAST_RUN_FILE}.interval"
        echo "$current_time" > "$LAST_RUN_FILE"
    fi
}

# Checks for new IPs and logs the information
check_new_ips() {
    touch "$NEW_IPS_FILE"
    config_load 'geomate'
    config_foreach collect_new_ips 'geo_filter'
    log_and_print "New IPs file content:" 2
    log_and_print "$(cat "$NEW_IPS_FILE")" 2
}

# Collects new IPs from the configuration (only valid public IPs)
collect_new_ips() {
    local name ip_list last_processed_file temp_new_ips
    config_get name "$1" 'name'
    config_get ip_list "$1" 'ip_list'
    last_processed_file="${GEOMATE_RUNTIME_DIR}/${name}_last_processed"
    temp_new_ips="${GEOMATE_RUNTIME_DIR}/${name}_temp_new_ips.txt"

    if [ -f "$ip_list" ]; then
        if [ ! -f "$last_processed_file" ]; then
            while read -r ip; do
                # Skip private/invalid IPs
                is_valid_public_ip "$ip" && echo "$name|$ip" >> "$NEW_IPS_FILE"
            done < "$ip_list"
        else
            # Write the new IPs to a temporary file
            awk 'NR==FNR{a[$0];next} !($0 in a)' "$last_processed_file" "$ip_list" > "$temp_new_ips"
            while read -r ip; do
                # Skip private/invalid IPs
                is_valid_public_ip "$ip" && echo "$name|$ip" >> "$NEW_IPS_FILE"
            done < "$temp_new_ips"
            rm -f "$temp_new_ips"
        fi
    fi
}

# Updates the last processed file for a specific filter
update_last_processed_file() {
    local game_name="$1"
    local ip_list last_processed_file
    config_load 'geomate'
    config_foreach get_ip_list_for_game 'geo_filter' "$game_name"
    if [ -n "$ip_list" ] && [ -f "$ip_list" ]; then
        last_processed_file="${GEOMATE_RUNTIME_DIR}/${game_name}_last_processed"
        cp "$ip_list" "$last_processed_file"
    fi
}

# Retrieves the IP list for a specific filter/game
get_ip_list_for_game() {
    local name
    config_get name "$1" 'name'
    if [ "$name" = "$2" ]; then
        config_get ip_list "$1" 'ip_list'
    fi
}

# Processes a batch of specific IPs for geolocation
process_batch_specific_ips() {
    local ips_to_process="$1"
    local processed_ips=0
    local game_name=""
    local ips=""
    local current_game=""
    local temp_ips_file="${GEOMATE_RUNTIME_DIR}/temp_ips_to_process.txt"

    # Write the IPs to be processed to a temporary file
    head -n "$ips_to_process" "$NEW_IPS_FILE" > "$temp_ips_file"

    log_and_print "Processing batch of $ips_to_process IPs" 2

    while IFS='|' read -r game ip; do
        if [ "$game" != "$current_game" ]; then
            # Process the previous batch if present
            if [ -n "$current_game" ] && [ -n "$ips" ]; then
                log_and_print "Calling geolocate.sh for $current_game with IPs: $ips" 2
                /etc/geolocate.sh specific "$current_game" "$ips"

                # Update last_processed_file for the current filter/game
                update_last_processed_file "$current_game"
            fi
            current_game="$game"
            ips="$ip"
        else
            ips="$ips $ip"
        fi
        processed_ips=$((processed_ips + 1))
    done < "$temp_ips_file"

    # Process the last batch
    if [ -n "$current_game" ] && [ -n "$ips" ]; then
        log_and_print "Calling geolocate.sh for $current_game with IPs: $ips" 2
        /etc/geolocate.sh specific "$current_game" "$ips"

        # Update last_processed_file for the current filter/game
        update_last_processed_file "$current_game"
    fi

    # Remove the processed IPs from NEW_IPS_FILE
    if [ $processed_ips -gt 0 ]; then
        sed -i "1,${processed_ips}d" "$NEW_IPS_FILE"
    fi

    rm -f "$temp_ips_file"

    # Invalidate cache for the UI
    rm -f /tmp/geomate_ip_cache.json
    if [ $? -eq 0 ]; then
        log_and_print "Cache invalidated by deleting /tmp/geomate_ip_cache.json" 2
    else
        log_and_print "Failed to invalidate cache by deleting /tmp/geomate_ip_cache.json" 1
    fi
}

# Execute the main function
check_and_run_geolocate
