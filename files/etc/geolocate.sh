#!/bin/sh

# shellcheck shell=ash
# shellcheck disable=SC3043  # ash supports local variables
# shellcheck disable=SC2317  # Functions are called by OpenWrt's system
# shellcheck disable=SC2155  # Combined declaration and assignment is fine for our use case
# shellcheck disable=SC1091  # OpenWrt's /lib/functions.sh is not available during shellcheck

. /lib/functions.sh
config_load 'geomate'
config_get debug_level global debug_level '0'

GEOMATE_DATA_DIR="/etc/geomate.d"
GEOMATE_TMP_DIR="/tmp/geomate"
IP_API_URL="http://ip-api.com/batch"
BATCH_SIZE=90
RATE_LIMIT=15
RATE_LIMIT_WINDOW=60
LOCK_FILE="$GEOMATE_TMP_DIR/geolocation.lock"

log_and_print() {
    local message="$1"
    local level="${2:-1}"
    if [ "$level" -le "$debug_level" ]; then
        logger -t geolocate "$message"
        echo "geolocate: $message"
    fi
}

cleanup() {
    log_and_print "Removing lock file: $LOCK_FILE" 2
    rm -f "$LOCK_FILE"
}

# Create temporary directory if it doesn't exist
mkdir -p "$GEOMATE_TMP_DIR"
chmod 755 "$GEOMATE_TMP_DIR"

# Create lock file
touch "$LOCK_FILE"
log_and_print "Created lock file: $LOCK_FILE" 2

# Ensure lock file is removed on script exit
trap cleanup EXIT

# Retrieves geographic information for a batch of IPs
get_geo_info_batch() {
    local batch="$1"
    local response
    
    log_and_print "API request sent for $(echo "$batch" | wc -w) IPs" 2
    response=$(curl -s --retry 3 "$IP_API_URL" \
        -H "Content-Type: application/json" \
        -d "[$(echo "$batch" | sed 's/[[:space:]]\+/","/g' | sed 's/^/"/;s/$/"/')]" \
        2>/dev/null)
    
    if [ -n "$response" ]; then
        echo "$response"
        return 0
    else
        return 1
    fi
}

# Processes IPs for a specific filter/game and updates the geo data file
process_game_ips() {
    local game_name="$1"
    local ip_list="$2"
    local output_file="${GEOMATE_DATA_DIR}/${game_name}_geo_data.json"
    local temp_output_file="${output_file}.tmp"
    local start_time=$(date +%s)
    local request_count=0
    local batch=""
    local batch_count=0
    local processed_count=0

    if [ ! -f "$output_file" ]; then
        log_and_print "Creating new geo data file for $game_name"
        touch "$output_file"
        chmod 644 "$output_file"
    fi

    log_and_print "Total IPs in list for $game_name: $(wc -l < "$ip_list")" 2

    > "$temp_output_file"
    log_and_print "Temporary file created and emptied" 2

    while IFS= read -r ip || [ -n "$ip" ]; do
        ip=$(echo "$ip" | tr -d '[:space:]')
        [ -z "$ip" ] && continue

        batch="$batch $ip"
        batch_count=$((batch_count + 1))

        if [ "$batch_count" -eq "$BATCH_SIZE" ]; then
            process_batch "$batch" "$temp_output_file"
            processed_count=$((processed_count + batch_count))
            log_and_print "Processed $processed_count IPs for $game_name" 2
            batch=""
            batch_count=0
            request_count=$((request_count + 1))

            current_time=$(date +%s)
            elapsed=$((current_time - start_time))
            log_and_print "Elapsed time: $elapsed seconds, Requests: $request_count" 2
            if [ "$elapsed" -lt "$RATE_LIMIT_WINDOW" ] && [ "$request_count" -ge "$RATE_LIMIT" ]; then
                sleep_time=$((RATE_LIMIT_WINDOW - elapsed + 1))
                log_and_print "Rate limit reached. Sleeping for $sleep_time seconds." 1
                sleep "$sleep_time"
                start_time=$(date +%s)
                request_count=0
            fi
        fi
    done < "$ip_list"

    # Process the last batch if it exists
    if [ -n "$batch" ]; then
        process_batch "$batch" "$temp_output_file"
        processed_count=$((processed_count + batch_count))
        log_and_print "Processed final batch. Total $processed_count IPs for $game_name" 2
    fi

    if [ -s "$temp_output_file" ]; then
        log_and_print "Temporary file size: $(wc -l < "$temp_output_file") lines" 2
        mv "$temp_output_file" "$output_file"
        log_and_print "Updated geo data for $game_name. New file size: $(wc -l < "$output_file") lines" 1
    else
        log_and_print "Error: No data processed for $game_name" 0
        rm -f "$temp_output_file"
    fi
}

# Processes a single batch of IPs and updates the output file with successful responses
process_batch() {
    local batch="$1"
    local output_file="$2"
    local batch_size=$(echo "$batch" | wc -w)
    local response
    
    log_and_print "Processing batch of $batch_size IPs: $batch" 2
    response=$(get_geo_info_batch "$batch")
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | sed 's/^\[//;s/\]$//;s/},{/}\n{/g' | while IFS= read -r line; do
            if [ -n "$line" ] && echo "$line" | grep -q '"status":"success"'; then
                echo "$line" >> "$output_file"
                log_and_print "Added to output: $line" 2
            fi
        done
        log_and_print "Batch processed successfully" 2
        return 0
    else
        log_and_print "API request failed for batch" 1
        return 1
    fi
}

process_geo_filter() {
    local name ip_list enabled

    config_get name "$1" 'name'
    config_get ip_list "$1" 'ip_list'
    config_get enabled "$1" 'enabled' '0'

    [ "$enabled" = "0" ] && return

    if [ -f "$ip_list" ]; then
        log_and_print "Geolocate: Processing IPs for $name" 1
        process_game_ips "$name" "$ip_list"
    else
        log_and_print "Geolocate: IP list file not found for $name: $ip_list" 1
    fi
}

# Performs a daily update of all IPs
daily_update() {
    log_and_print "Starting daily update of all IPs" 1
    config_load 'geomate'
    config_foreach process_geo_filter 'geo_filter'
    log_and_print "Daily update completed" 1
}

# Processes specific IPs for a given filter/game name
process_specific_ips() {
    local game_name="$1"
    shift
    # Deduplicate IPs before processing
    local ips=$(echo "$*" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    local output_file="${GEOMATE_DATA_DIR}/${game_name}_geo_data.json"
    local temp_output_file="${output_file}.tmp"
    local lock_file="${output_file}.lock"
    local total_ips=$(echo "$ips" | wc -w)

    log_and_print "Processing specific IPs for $game_name: $ips" 2
    log_and_print "Total IPs: $total_ips" 2

    # Use a simple lock mechanism to prevent concurrent processing
    while [ -f "$lock_file" ]; do
        sleep 1
    done
    touch "$lock_file"

    > "$temp_output_file"

    local batch=""
    local count=0
    for ip in $ips; do
        batch="$batch $ip"
        count=$((count + 1))
        if [ "$count" -eq "$BATCH_SIZE" ]; then
            log_and_print "Processing batch of $count IPs" 2
            process_batch "$batch" "$temp_output_file"
            batch=""
            count=0
            sleep 4  # Wait 4 seconds between batches
        fi
    done

    # Process remainder batch if it exists
    if [ "$count" -gt 0 ]; then
        log_and_print "Processing remaining $count IPs" 2
        process_batch "$batch" "$temp_output_file"
    fi

    if [ -s "$temp_output_file" ]; then
        log_and_print "Temporary file size: $(wc -l < "$temp_output_file") lines" 2
        if [ -f "$output_file" ] && [ -s "$output_file" ]; then
            cat "$output_file" "$temp_output_file" | sort -u > "${output_file}.new"
            mv "${output_file}.new" "$output_file"
        else
            mv "$temp_output_file" "$output_file"
        fi
        log_and_print "Updated geo data for $game_name. New file size: $(wc -l < "$output_file") lines" 1
    else
        log_and_print "Error: No data processed for $game_name" 0
    fi

    rm -f "$temp_output_file"
    rm -f "$lock_file"
}

# Main function to handle different execution modes
main() {
    case "$1" in
        daily)
            daily_update
            ;;
        specific)
            shift
            process_specific_ips "$@"
            ;;
        *)
            config_load 'geomate'
            config_foreach process_geo_filter 'geo_filter'
            ;;
    esac
}

main "$@"
status=$?

if [ $status -eq 0 ]; then
    log_and_print "Geolocation completed successfully, restarting geomate service"
    /etc/init.d/geomate restart
    restart_status=$?
    if [ $restart_status -eq 0 ]; then
        log_and_print "Service restart successful"
    else
        log_and_print "Service restart failed with status $restart_status"
        status=$restart_status
    fi
fi

exit $status
