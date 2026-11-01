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
# Provider settings: request budget is shared across full and specific runs.
GEO_PROVIDER_URL="http://ip-api.com/batch?fields=status,message,country,countryCode,city,lat,lon,isp,org,query"
BATCH_SIZE=100
RATE_LIMIT=15
RATE_LIMIT_WINDOW=60
RATE_DIR="$GEOMATE_TMP_DIR/ratelimit"
# Lock of the full runs (manual and daily): the owner's PID on line 1, its start time
# (Unix epoch) on line 2. The web interface reads it to show a running geolocation
LOCK_FILE="$GEOMATE_TMP_DIR/geolocation.lock"
LOCK_HELD=0          # Set to 1 once this process owns LOCK_FILE
EXIT_RUNNING=3       # Exit code: another full run is active, nothing was done
EXIT_NO_LOCK=4       # Exit code: the full run could not create its lock, nothing was done
FILTER_LOCK_FILE=""  # Per-filter lock of the 'specific' mode, removed on exit
FAILED_BATCHES=0     # Batches without a usable API answer
GEO_DATA_CHANGED=0   # Set to 1 when a geo data file was rewritten
PID_FILE="/var/run/geomate.pid"  # PID of the run loop of the service
# Left for the run loop when this run was started by its trigger and reload_geo failed
GEO_RESTART_FLAG="$GEOMATE_TMP_DIR/geo_restart_needed"

log_and_print() {
    local message="$1"
    local level="${2:-1}"
    if [ "$level" -le "$debug_level" ]; then
        logger -t geolocate "$message"
        echo "geolocate: $message"
    fi
}

cleanup() {
    if [ "$LOCK_HELD" = "1" ]; then
        log_and_print "Removing lock file: $LOCK_FILE" 2
        rm -f "$LOCK_FILE"
    fi
    rm -f ${FILTER_LOCK_FILE:+"$FILTER_LOCK_FILE"}
}

# Prints the PID of the full run that owns LOCK_FILE; returns 1 when there is none: no
# lock, no PID in it (written by an older version), or the process is gone or is no
# longer a full geolocate.sh run (PID reused, for example by a 'specific' run)
full_run_owner() {
    local pid cmdline
    read -r pid 2>/dev/null < "$LOCK_FILE"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    # Each argument ends with a NUL, so the converted cmdline ends with a space
    cmdline=$(tr '\0' ' ' 2>/dev/null < "/proc/$pid/cmdline") || return 1
    case "$cmdline" in
        *geolocate.sh\ specific\ *|*geolocate.sh\ start\ ) return 1 ;;
        *geolocate.sh\ *) printf '%s\n' "$pid" ;;
        *) return 1 ;;
    esac
}

# Takes LOCK_FILE for a full run, exits with EXIT_RUNNING while another full run is
# alive. ln creates the lock atomically and only when it does not exist, so the file
# never appears without its content. A stale lock is taken over; exits with EXIT_NO_LOCK
# when the lock cannot be created
acquire_full_run_lock() {
    local tmp_lock="${LOCK_FILE}.$$" pid tries=0
    printf '%s\n%s\n' "$$" "$(date +%s)" > "$tmp_lock" || {
        log_and_print "Error: Failed to create lock file $tmp_lock" 0; exit "$EXIT_NO_LOCK"; }
    until ln "$tmp_lock" "$LOCK_FILE" 2>/dev/null; do
        if pid=$(full_run_owner); then
            rm -f "$tmp_lock"
            log_and_print "Geolocation is already running (PID $pid), not starting another run" 0
            exit "$EXIT_RUNNING"
        fi
        tries=$((tries + 1))
        if [ "$tries" -gt 3 ]; then
            rm -f "$tmp_lock"
            log_and_print "Error: Failed to take lock file $LOCK_FILE" 0
            exit "$EXIT_NO_LOCK"
        fi
        log_and_print "Taking over stale lock $LOCK_FILE" 1
        rm -f "$LOCK_FILE"
    done
    rm -f "$tmp_lock"
    LOCK_HELD=1
    log_and_print "Created lock file: $LOCK_FILE" 2
}

# Starts a manual full run detached from the caller and returns at once, for the web
# interface (a request that runs the whole geolocation would time out). Prints one line.
# Exit 0: started (the run may have ended already); EXIT_RUNNING: a full run is active
# already; 1: the run could not create its lock
start_detached() {
    local pid child rc waited=0
    # The answer line is printed whatever the debug level, and logged like other messages
    report() { log_and_print "$1" "$2" >/dev/null; printf '%s\n' "$1"; }
    
    if pid=$(full_run_owner); then
        report "Geolocation is already running (PID $pid)" 0
        return "$EXIT_RUNNING"
    fi
    # No inherited stdout/stderr: the caller gets its answer without waiting for the run.
    # The subshell redirects with exec before it starts the run, and the exec keeps its PID.
    # With the redirections on the command itself, rpcd's file exec (the web interface)
    # waited until its 30 s timeout although the run had its own stdout
    if command -v setsid >/dev/null 2>&1; then
        ( exec </dev/null >/dev/null 2>&1; exec setsid /bin/sh "$0" ) &
    else
        ( exec </dev/null >/dev/null 2>&1; exec /bin/sh "$0" ) &
    fi
    child=$!
    # Wait until the run owns the lock (a second start sees it from then on) or has ended
    while [ "$waited" -lt 50 ]; do
        pid=$(full_run_owner) && [ "$pid" = "$child" ] && break
        kill -0 "$child" 2>/dev/null || break
        sleep 0.1 2>/dev/null || sleep 1
        waited=$((waited + 1))
    done
    if [ "$pid" != "$child" ] && ! kill -0 "$child" 2>/dev/null; then
        # The run ended between two polls, for example with no filter to process. Only
        # exit 3 and 4 mean it did nothing: another full run held the lock, or no lock
        wait "$child"
        rc=$?
        if [ "$rc" -eq "$EXIT_RUNNING" ]; then
            if pid=$(full_run_owner); then
                report "Geolocation is already running (PID $pid)" 0
            else
                report "Geolocation is already running" 0
            fi
            return "$EXIT_RUNNING"
        elif [ "$rc" -eq "$EXIT_NO_LOCK" ]; then
            report "Error: Failed to start geolocation" 0
            return 1
        fi
    fi
    # The run owns the lock, has ended, or is still starting on a busy router
    report "Geolocation started (PID $child)" 1
}

# Create temporary directory if it doesn't exist
mkdir -p "$GEOMATE_TMP_DIR"
chmod 755 "$GEOMATE_TMP_DIR"

# Ensure the locks this process owns are removed on script exit
trap cleanup EXIT

# Monotonic seconds: wall-clock corrections must not reopen the request budget.
rate_now() {
    local uptime rest
    read -r uptime rest < /proc/uptime || return 1
    printf '%s\n' "${uptime%%.*}"
}

# Short, non-blocking lock shared by every geolocation process. A stale-owner claim
# prevents two waiters from removing a lock that a third process just acquired.
acquire_rate_lock() {
    local owner claim waited=0
    mkdir -p "$RATE_DIR" || return 1
    until ln -snT "$$" "$RATE_DIR/lock" 2>/dev/null; do
        owner=$(readlink "$RATE_DIR/lock" 2>/dev/null)
        # The owner may have unlocked between ln and readlink.
        case "$owner" in '') continue ;; *[!0-9]*) return 1 ;; esac
        claim="$RATE_DIR/stale.$owner"
        if ! kill -0 "$owner" 2>/dev/null && mkdir "$claim" 2>/dev/null; then
            if [ "$(readlink "$RATE_DIR/lock" 2>/dev/null)" = "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
                rm -f "$RATE_DIR/lock"
            fi
            rmdir "$claim"
            continue
        fi
        [ "$waited" -lt 60 ] || return 1
        sleep 1
        waited=$((waited + 1))
    done
}

release_rate_lock() {
    [ "$(readlink "$RATE_DIR/lock" 2>/dev/null)" != "$$" ] || rm -f "$RATE_DIR/lock"
}

# Reserve one request in the rolling window, including partial batches and retries.
# Sleeping never holds the lock. The extra second covers the clock's whole-second
# precision, so requests at the edges of a 60-second window cannot exceed the limit.
reserve_request() {
    local now count first wait_for until_time tmp="$RATE_DIR/requests.$$"
    while :; do
        acquire_rate_lock || return 1
        now=$(rate_now) || { release_rate_lock; return 1; }
        until_time=0
        read -r until_time 2>/dev/null < "$RATE_DIR/until"
        case "$until_time" in ''|*[!0-9]*) until_time=0 ;; esac
        : > "$tmp" || { release_rate_lock; return 1; }
        if [ -f "$RATE_DIR/requests" ]; then
            awk -v now="$now" -v window="$RATE_LIMIT_WINDOW" \
                '$0 ~ /^[0-9]+$/ && now - $0 <= window { print }' \
                "$RATE_DIR/requests" > "$tmp" || { release_rate_lock; return 1; }
        fi
        count=$(wc -l < "$tmp")
        wait_for=$((until_time - now))
        if [ "$count" -ge "$RATE_LIMIT" ]; then
            read -r first < "$tmp"
            [ "$wait_for" -ge $((first + RATE_LIMIT_WINDOW + 1 - now)) ] ||
                wait_for=$((first + RATE_LIMIT_WINDOW + 1 - now))
        fi
        if [ "$wait_for" -le 0 ]; then
            printf '%s\n' "$now" >> "$tmp" && mv "$tmp" "$RATE_DIR/requests" || {
                release_rate_lock; return 1; }
            release_rate_lock
            return 0
        fi
        rm -f "$tmp"
        release_rate_lock
        sleep "$wait_for"
    done
}

# Provider headers can delay requests, but never grant extra slots. Ignore malformed
# hints and cap a wait at 65 seconds. Retry-After's numeric form also works with other
# providers; the local rolling window remains authoritative when headers are absent.
record_rate_hint() {
    local headers="$1" status="$2" hint remaining ttl retry now old
    hint=$(awk '
        /^HTTP\// { rl = ""; ttl = ""; retry = "" }
        { key = tolower($1); value = $2; sub(/\r$/, "", value) }
        key == "x-rl:" && value ~ /^[0-9]+$/ { rl = (value + 0 == 0 ? 0 : 1) }
        key == "x-ttl:" && value ~ /^[0-9]+$/ { ttl = (value + 0 > 65 ? 65 : value + 0) }
        key == "retry-after:" && value ~ /^[0-9]+$/ { retry = (value + 0 > 65 ? 65 : value + 0) }
        END { print (rl == "" ? "-" : rl), (ttl == "" ? "-" : ttl), (retry == "" ? "-" : retry) }
    ' "$headers")
    read -r remaining ttl retry <<EOF
$hint
EOF
    # The arithmetic only sees small integers, even for an invalid oversized header.
    hint=0
    if [ "$status" = 429 ] || [ "$remaining" = 0 ]; then
        case "$ttl" in -) ;; ?????* ) hint=65 ;; *) hint=$((ttl + 1)) ;; esac
        case "$retry" in -) ;; ?????* ) hint=65 ;; *) [ "$hint" -ge "$retry" ] || hint="$retry" ;; esac
        [ "$hint" -gt 0 ] || hint="$RATE_LIMIT_WINDOW"
        [ "$hint" -le 65 ] || hint=65
    fi
    [ "$hint" -gt 0 ] || return 0
    acquire_rate_lock || return 1
    now=$(rate_now) || { release_rate_lock; return 1; }
    old=0
    read -r old 2>/dev/null < "$RATE_DIR/until"
    case "$old" in ''|*[!0-9]*) old=0 ;; esac
    [ "$old" -ge $((now + hint)) ] || printf '%s\n' "$((now + hint))" > "$RATE_DIR/until"
    release_rate_lock
}

# Retrieves geographic information for a batch of IPs. curl never retries on its
# own: a 429 gets one separately budgeted attempt, with a fresh response body.
get_geo_info_batch() {
    local batch="$1" response status attempt=0 curl_status
    local headers="$GEOMATE_TMP_DIR/geo_headers.$$" body="$GEOMATE_TMP_DIR/geo_body.$$"
    while :; do
        reserve_request || { log_and_print "Error: could not reserve a geolocation request" 0 >&2; return 1; }
        : > "$headers"
        : > "$body"
        log_and_print "API request sent for $(echo "$batch" | wc -w) IPs" 2 >&2
        status=$(curl -s --connect-timeout 10 --max-time 30 "$GEO_PROVIDER_URL" \
            -D "$headers" -o "$body" -w '%{http_code}' \
            -H "Content-Type: application/json" \
            -d "[$(echo "$batch" | sed 's/[[:space:]]\+/","/g' | sed 's/^/"/;s/$/"/')]" \
            2>/dev/null)
        curl_status=$?
        record_rate_hint "$headers" "$status" || {
            rm -f "$headers" "$body"; return 1; }
        if [ "$curl_status" -eq 0 ] && [ "$status" = 429 ] && [ "$attempt" -eq 0 ]; then
            attempt=1
            continue
        fi
        response=$(cat "$body")
        rm -f "$headers" "$body"
        [ "$curl_status" -eq 0 ] && [ "$status" = 200 ] || return 1
        # A partial response or an error page must not replace existing coordinates.
        [ "${response#\[}" != "$response" ] && [ "${response%\]}" != "$response" ] || return 1
        printf '%s\n' "$response" | jq -e 'type == "array"' >/dev/null 2>&1 || return 1
        printf '%s\n' "$response"
        return 0
    done
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
    local temp_output_file="${GEOMATE_TMP_DIR}/geo_output.$$"
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
    local temp_output_file="${GEOMATE_TMP_DIR}/geo_output.$$"
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

# Main function to handle different execution modes:
#   geolocate.sh             manual full run of all enabled filters
#   geolocate.sh start       manual full run, detached; returns at once (exit 0, 3 or 1)
#   geolocate.sh daily       full run of the trigger's daily update
#   geolocate.sh specific <filter name> "<ip> ..."   new IPs of one filter (trigger)
# Full runs share LOCK_FILE: while one is alive, another exits with 3 and does nothing;
# a full run that cannot create the lock exits with 4
main() {
    case "$1" in
        start)
            # Returns before the run ends: no restart handling here
            start_detached
            exit $?
            ;;
        daily)
            acquire_full_run_lock
            daily_update
            ;;
        specific)
            shift
            process_specific_ips "$@"
            ;;
        *)
            acquire_full_run_lock
            config_load 'geomate'
            config_foreach process_geo_filter 'geo_filter'
            ;;
    esac
}

# Return 0 when the trigger of the running service loop started this run: GEOMATE_FROM_LOOP
# holds the PID of the loop, which still owns PID_FILE. A run whose loop has gone, for
# example after a restart, acts on its own
started_by_loop() {
    local pid
    [ -n "$GEOMATE_FROM_LOOP" ] || return 1
    read -r pid 2>/dev/null < "$PID_FILE"
    [ "$pid" = "$GEOMATE_FROM_LOOP" ] && kill -0 "$pid" 2>/dev/null
}

main "$@"
status=$?

# Only new geo data needs action (the nft sets are built from these files). reload_geo
# refills the sets of the changed filters in place; an older geomate.sh without it prints
# its usage and exits 1, which restarts as before. A run of the loop's trigger leaves the
# restart to the loop: inside the service it would kill itself (and the trigger before it
# recorded its progress) with procd since 2026-10-18
if [ "$GEO_DATA_CHANGED" = "1" ]; then
    if /etc/geomate.sh reload_geo; then
        log_and_print "Geolocation completed successfully, new geo data applied without a restart"
    elif started_by_loop; then
        if printf '' > "$GEO_RESTART_FLAG"; then
            log_and_print "Geolocation completed successfully, the service restarts after the geolocation"
        else
            log_and_print "Error: could not request a safe service restart" 0
            status=1
        fi
    else
        log_and_print "Geolocation completed successfully, restarting geomate service"
        /etc/init.d/geomate restart
        restart_status=$?
        if [ $restart_status -eq 0 ]; then
            log_and_print "Service restart successful"
        else
            log_and_print "Service restart failed with status $restart_status"
            status=$restart_status
            # Exit codes 3 and 4 are reserved for full runs that did nothing
            case "$status" in "$EXIT_RUNNING"|"$EXIT_NO_LOCK") status=1 ;; esac
        fi
    fi
elif [ "$FAILED_BATCHES" -gt 0 ]; then
    log_and_print "No geo data updated, $FAILED_BATCHES API request(s) failed. Skipping service restart"
    status=1
else
    log_and_print "Geo data unchanged, skipping service restart"
fi

exit $status
