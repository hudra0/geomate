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
GEOMATE_TMP_DIR="/tmp/geomate"
IP_API_URL="http://ip-api.com/batch"
BATCH_SIZE=90
RATE_LIMIT=15
RATE_LIMIT_WINDOW=60
LOCK_FILE="$GEOMATE_TMP_DIR/geolocation.lock"
FILTER_LOCK_FILE=""  # Per-filter lock of the 'specific' mode, removed on exit
FAILED_BATCHES=0     # Batches without a usable API answer
GEO_DATA_CHANGED=0   # Set to 1 when a geo data file was rewritten

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
    rm -f "$LOCK_FILE" ${FILTER_LOCK_FILE:+"$FILTER_LOCK_FILE"}
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
    
    # ip-api answers with a JSON array; anything else (e.g. an error page) counts as failed
    if [ "${response#\[}" != "$response" ]; then
        echo "$response"
        return 0
    else
        return 1
    fi
}

# Puts the complete new content ($1) in place of the geo data file ($2) if it differs,
# so an unchanged result causes neither a flash write nor a service restart
install_geo_data() {
    local new_data="$1" geo_file="$2"
    local name="${geo_file##*/}"
    name="${name%_geo_data.json}"

    if cmp -s "$new_data" "$geo_file"; then
        rm -f "$new_data"
        log_and_print "Geo data for $name unchanged" 1
    elif mv "$new_data" "$geo_file"; then
        GEO_DATA_CHANGED=1
        log_and_print "Updated geo data for $name. New file size: $(wc -l < "$geo_file") lines" 1
    else
        rm -f "$new_data"
        log_and_print "Error: Failed to update geo data for $name" 0
        return 1
    fi
}

# Merges new ip-api results ($1) into the geo data file ($2): one line per IP, a new
# entry replaces the old entry of the same IP, all other old entries are kept
merge_geo_data() {
    local new_data="$1" geo_file="$2"
    local merged="${GEOMATE_TMP_DIR}/merged_geo_data.$$"

    # Nothing to merge with: the new results become the geo data
    [ -s "$geo_file" ] || { install_geo_data "$new_data" "$geo_file"; return; }

    awk '{ key = match($0, /"query":"[^"]*"/) ? substr($0, RSTART, RLENGTH) : $0 }
        !(key in seen) { seen[key]; print }' "$new_data" "$geo_file" > "$merged" || {
        rm -f "$merged"
        log_and_print "Error: Failed to merge new geo data into $geo_file" 0
        return 1
    }
    install_geo_data "$merged" "$geo_file"
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
    local failed_before="$FAILED_BATCHES"

    if [ ! -f "$output_file" ]; then
        log_and_print "Creating new geo data file for $game_name"
        touch "$output_file"
        chmod 644 "$output_file"
    fi

    log_and_print "Total IPs in list for $game_name: $(wc -l < "$ip_list")" 2

    : > "$temp_output_file"
    log_and_print "Temporary file created and emptied" 2

    while IFS= read -r line || [ -n "$line" ]; do
        # Support both formats: "IP" and "IP,timestamp"
        ip="${line%%,*}"  # Extract IP (everything before comma)
        ip=$(echo "$ip" | tr -d '[:space:]')
        [ -z "$ip" ] && continue

        batch="${batch:+$batch }$ip"
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
        if [ "$FAILED_BATCHES" -gt "$failed_before" ]; then
            # Replacing the file would drop the coordinates of the failed batches' IPs
            log_and_print "Some API requests failed for $game_name, keeping the existing entries" 1
            merge_geo_data "$temp_output_file" "$output_file"
        else
            install_geo_data "$temp_output_file" "$output_file"
        fi
    else
        log_and_print "Error: No data processed for $game_name" 0
    fi
    rm -f "$temp_output_file"
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
        FAILED_BATCHES=$((FAILED_BATCHES + 1))
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
    # Deduplicate IPs before processing; strip a ",timestamp" taken over from a list line
    local ips=$(echo "$*" | tr ' ' '\n' | cut -d, -f1 | sort -u | tr '\n' ' ')
    local output_file="${GEOMATE_DATA_DIR}/${game_name}_geo_data.json"
    local temp_output_file="${output_file}.tmp"
    local lock_file="${GEOMATE_TMP_DIR}/${game_name}_geo_data.lock"
    local total_ips=$(echo "$ips" | wc -w)

    log_and_print "Processing specific IPs for $game_name: $ips" 2
    log_and_print "Total IPs: $total_ips" 2

    # Prevent concurrent processing of the same filter. The lock lives in RAM and holds
    # the owner's PID, so neither a reboot nor a killed owner leaves it stuck
    while [ -f "$lock_file" ] && kill -0 "$(cat "$lock_file" 2>/dev/null)" 2>/dev/null; do
        sleep 1
    done
    [ -f "$lock_file" ] && log_and_print "Taking over stale lock $lock_file" 1
    echo "$$" > "$lock_file"
    FILTER_LOCK_FILE="$lock_file"

    : > "$temp_output_file"

    local batch=""
    local count=0
    for ip in $ips; do
        batch="${batch:+$batch }$ip"
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
        merge_geo_data "$temp_output_file" "$output_file"
    else
        log_and_print "Error: No data processed for $game_name" 0
    fi

    rm -f "$temp_output_file"
    rm -f "$lock_file"
    FILTER_LOCK_FILE=""
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

# Only new geo data needs a restart (the nft sets are built from these files at start)
if [ "$GEO_DATA_CHANGED" = "1" ]; then
    log_and_print "Geolocation completed successfully, restarting geomate service"
    /etc/init.d/geomate restart
    restart_status=$?
    if [ $restart_status -eq 0 ]; then
        log_and_print "Service restart successful"
    else
        log_and_print "Service restart failed with status $restart_status"
        status=$restart_status
    fi
elif [ "$FAILED_BATCHES" -gt 0 ]; then
    log_and_print "No geo data updated, $FAILED_BATCHES API request(s) failed. Skipping service restart"
    status=1
else
    log_and_print "Geo data unchanged, skipping service restart"
fi

exit $status
