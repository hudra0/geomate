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

. /lib/functions.sh

GEOMATE_DATA_DIR="/etc/geomate.d"
GEOMATE_RUNTIME_DIR="${GEOMATE_DATA_DIR}/runtime"
GEOMATE_TMP_DIR="/tmp/geomate"
NFT_ERROR_LOG="/tmp/geomate_nft_errors.log"
NFT_SET_PREFIX="geomate_"
SETS_LOCK="${GEOMATE_TMP_DIR}/sets.lock"           # Held while IP lists or sets are rewritten
BUILT_CONFIG_DIR="${GEOMATE_TMP_DIR}/config"       # Copy of the configuration the running sets were built from
UCI_PENDING_CHANGES="/tmp/.uci/geomate"            # Changes of uci set without commit, applied by every uci read
CHECK_INTERVAL=1800  # Interval in seconds (30 minutes) - used for geolocation status
harvest_refresh_per_day=0  # A harvest refreshes list timestamps this many seconds old per expiry day (0: all)
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

# Lock shared by the loop's harvest, the 'harvest' command and the live reload, so
# they never rewrite the same IP list or set at once. The lock is a symlink to the
# owner's PID, which ln creates atomically. The lock of an owner that is gone is taken
# over by one waiter only: mkdir of a claim named after that owner is atomic, and only
# the claim holder removes a lock of that owner, so no waiter deletes a newer lock.
# A claim left by a process killed inside it is removed at the next service start
acquire_sets_lock() {
    local owner claim took_over waited=0
    mkdir -p "$GEOMATE_TMP_DIR"
    until ln -snT "$$" "$SETS_LOCK" 2>/dev/null; do
        owner=$(readlink "$SETS_LOCK" 2>/dev/null)
        claim="${SETS_LOCK}.stale.${owner}"
        if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null && mkdir "$claim" 2>/dev/null; then
            took_over=0
            if [ "$(readlink "$SETS_LOCK" 2>/dev/null)" = "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
                rm -f "$SETS_LOCK"
                took_over=1
            fi
            rmdir "$claim"
            [ "$took_over" -eq 1 ] && log_and_print "Took over stale lock $SETS_LOCK of PID $owner" 1
            continue
        fi
        [ "$waited" -eq 0 ] && log_and_print "Waiting for lock $SETS_LOCK held by PID ${owner:-?}" 2
        if [ "$waited" -ge 60 ]; then
            log_and_print "Error: lock $SETS_LOCK still held by PID ${owner:-?} after 60 s" 0
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

release_sets_lock() {
    rm -f "$SETS_LOCK"
}

# Copy the live configuration file into directory $1, plus the pending uci changes
# (as file "pending"), which config_load and show_config apply on top of it
copy_config() {
    mkdir -p "$1" && cp "${UCI_CONFIG_DIR:-/etc/config}/geomate" "$1/geomate" || return 1
    if [ -f "$UCI_PENDING_CHANGES" ]; then
        cp "$UCI_PENDING_CHANGES" "$1/pending"
    else
        : > "$1/pending"
    fi
}

# Configuration as 'uci show' lines, with the section IDs that config_load uses.
# $1: configuration directory, default the live one
show_config() {
    local dir="${1:-$UCI_CONFIG_DIR}"
    uci ${dir:+-c "$dir"} -q -X show geomate
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

    [ -n "$ip_list" ] || { log_and_print "Filter $name has no ip_list configured, skipping IP list creation" 1; return 0; }

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
    
    # Every rebuild starts with an empty nft error log (nft_exec appends to it) and without
    # the markers of rejected allowed_ip and blocked_ips lists (add_filter_entries)
    : > "$NFT_ERROR_LOG"
    rm -f "$GEOMATE_TMP_DIR"/*.entries_failed

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

# Return 0 when $1 is a dotted IPv4 address: four decimal octets 0-255, no leading zeros
is_ipv4_addr() {
    local IFS=. octet
    case "$1" in
        *[!0-9.]*|.*|*.|*..*) return 1 ;;
    esac
    set -- $1
    [ $# -eq 4 ] || return 1
    for octet in "$@"; do
        case "$octet" in
            [0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;
            *) return 1 ;;
        esac
    done
}

# Return 0 when $1 is an IPv4 address, a.b.c.d/0-32 or a.b.c.d-e.f.g.h
is_ipv4_entry() {
    case "$1" in
        */*)
            case "${1#*/}" in
                [0-9]|[12][0-9]|3[0-2]) is_ipv4_addr "${1%/*}" ;;
                *) return 1 ;;
            esac
            ;;
        *-*) is_ipv4_addr "${1%-*}" && is_ipv4_addr "${1#*-}" ;;
        *) is_ipv4_addr "$1" ;;
    esac
}

# Build the nft match for the Source IP of a filter into the global src_match, shared
# by the forward and the prerouting rules. $1: the src_ip value, entries separated by
# whitespace (config_get joins a 'list src_ip' with spaces).
#   empty: src_match='' (all devices)
#   one entry without '!', or whitespace only: 'ip saddr <value>', passed to nft
#   unchecked as before
#   otherwise every entry, after an optional '!=' or '!' (exception), must be an IPv4
#   address, a.b.c.d/0-32 or a.b.c.d-e.f.g.h. Duplicates are dropped. Like qosmate's
#   gen_rule: 'ip saddr != <exceptions>' first, then 'ip saddr <entries>'; one value
#   without braces, several as '{ a, b }'
#   any other value, such as nft's own '!= a.b.c.d' or '{ a, b }': 'ip saddr <value>'
#   unchecked as before, so nft decides. Dropping only the bad entries could match
#   more devices; a value nft rejects leaves the filter without rules
# Sets src_exceptions_only to 1 when the value has exceptions only, else 0.
# Returns 1 when a value with several entries or '!' was passed to nft unchecked
build_src_match() {
    local value="$1" entry addr pos="" neg="" glob_off=0
    src_match=""
    src_exceptions_only=0
    [ -n "$value" ] || return 0

    # Split at whitespace without expanding wildcards, then restore the -f state
    case "$-" in *f*) glob_off=1 ;; esac
    set -f
    set -- $value
    [ "$glob_off" -eq 1 ] || set +f

    if [ $# -le 1 ]; then
        case "$1" in
            '!'*) ;;
            *) src_match="ip saddr $value"; return 0 ;;
        esac
    fi

    for entry in "$@"; do
        case "$entry" in
            '!='*) addr="${entry#!=}" ;;
            '!'*) addr="${entry#!}" ;;
            *) addr="$entry" ;;
        esac
        is_ipv4_entry "$addr" || { src_match="ip saddr $value"; return 1; }
        if [ "$addr" = "$entry" ]; then
            case "$pos " in *" $addr "*) ;; *) pos="$pos $addr" ;; esac
        else
            case "$neg " in *" $addr "*) ;; *) neg="$neg $addr" ;; esac
        fi
    done

    pos="${pos# }"
    neg="${neg# }"
    case "$neg" in *' '*) neg="{ ${neg// /, } }" ;; esac
    case "$pos" in *' '*) pos="{ ${pos// /, } }" ;; esac
    [ -n "$neg" ] && src_match="ip saddr != $neg"
    if [ -n "$pos" ]; then
        src_match="${src_match:+$src_match }ip saddr $pos"
    else
        src_exceptions_only=1
    fi
    return 0
}

# Return 1 when $1, which passed is_ipv4_entry, is a range a.b.c.d-e.f.g.h whose first
# address is above its last one: nft rejects it with the whole element list
ipv4_range_ordered() {
    case "$1" in *-*) ;; *) return 0 ;; esac
    local IFS=.
    set -- ${1%-*} ${1#*-}
    [ $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )) -le $(( ($5 << 24) + ($6 << 16) + ($7 << 8) + $8 )) ]
}

# awk functions for set elements, shared by merge_set_entries and split_geo_data.
# ip2n(a): address a.b.c.d as a number. parse_entry(t): set e_lo and e_hi to the first
# and last address of t; return 1 for an address, 2 for a prefix or range, 0 for a
# host name. The addresses passed check_set_entries, so each has one spelling
AWK_IPV4_ENTRY='
function ip2n(a,    o) { split(a, o, "."); return ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4] }
function parse_entry(t,    q, size) {
    if (t ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { e_lo = e_hi = ip2n(t); return 1 }
    if (t ~ /^[0-9.]+\/[0-9]+$/) {
        split(t, q, "/")
        size = 2 ^ (32 - q[2])
        e_lo = int(ip2n(q[1]) / size) * size
        e_hi = e_lo + size - 1
        return 2
    }
    if (t ~ /^[0-9.]+-[0-9.]+$/) { split(t, q, "-"); e_lo = ip2n(q[1]); e_hi = ip2n(q[2]); return 2 }
    return 0
}'

# The _allowed and _blocked sets have no auto-merge, so nft rejects overlapping elements.
# Drop the entries of element list $3 (option $2 of filter $1) that lie inside another
# entry (of two equal ones the later one) and merge partly overlapping entries into one
# range at the place of the first. Host names stay. Prints a log line per change, then
# the new list as the last line.
# Only prefixes and ranges are compared pair by pair: an address lies inside an equal
# address (first[] finds the first one) or a prefix or range, and an address that lies
# inside no other entry overlaps none, so only prefixes and ranges are merged
merge_set_entries() {
    awk -v filter="$1" -v option="$2" -v list="$3" "$AWK_IPV4_ENTRY"'
        function n2ip(n) { return int(n / 16777216) "." int(n / 65536) % 256 "." int(n / 256) % 256 "." n % 256 }
        BEGIN {
            n = split(list, tok, ",")
            for (i = 1; i <= n; i++) {
                kind[i] = parse_entry(tok[i]); lo[i] = e_lo; hi[i] = e_hi
                if (kind[i] == 1 && !(tok[i] in first)) first[tok[i]] = i
                else if (kind[i] == 2) rng[++r] = i
            }
            for (i = 1; i <= n; i++) {
                if (!kind[i]) continue
                # j: the first entry that contains entry i, n + 1 for none
                j = n + 1
                a = (kind[i] == 1 ? tok[i] : (lo[i] == hi[i] ? n2ip(lo[i]) : ""))
                if ((a in first) && first[a] < i) j = first[a]
                for (c = 1; c <= r && rng[c] < j; c++) {
                    k = rng[c]
                    if (k == i || lo[k] > lo[i] || hi[i] > hi[k]) continue
                    if (k < i || lo[k] < lo[i] || hi[i] < hi[k]) j = k
                }
                if (j <= n) {
                    printf "Filter %s: %s entry %s lies inside %s, skipped\n", filter, option, tok[i], tok[j]
                    drop[i] = 1
                } else if (kind[i] == 2) kept[++m] = i
            }
            # Sort the remaining prefixes and ranges by first address (insertion sort)
            for (a = 2; a <= m; a++) {
                k = kept[a]
                for (b = a - 1; b >= 1 && lo[kept[b]] > lo[k]; b--) kept[b + 1] = kept[b]
                kept[b + 1] = k
            }
            for (a = 1; a <= m; a = b) {
                lead = kept[a]; top = hi[lead]; names = tok[lead]
                for (b = a + 1; b <= m && lo[kept[b]] <= top; b++) {
                    k = kept[b]
                    names = names ", " tok[k]
                    if (hi[k] > top) top = hi[k]
                    if (k < lead) { drop[lead] = 1; lead = k } else drop[k] = 1
                }
                if (b > a + 1) {
                    tok[lead] = n2ip(lo[kept[a]]) "-" n2ip(top)
                    printf "Filter %s: %s entries %s overlap, merged into %s\n", filter, option, names, tok[lead]
                }
            }
            for (i = 1; i <= n; i++) if (!drop[i]) out = out (out == "" ? "" : ",") tok[i]
            print out
        }'
}

# Turn the value of a set option into an element list nft accepts. Sets set_entries to
# the kept tokens, comma-separated. $1: filter name, $2: option name, $3: set name,
# $4: value, entries separated by commas, tokens of an entry by whitespace, $5: 1 to log
# skipped and merged entries and add skipped ones to $NFT_ERROR_LOG, 0 to stay quiet.
# A token is kept when it is an IPv4 address, a.b.c.d/0-32 or an ordered range
# a.b.c.d-e.f.g.h, or a host name, which nft resolves when it loads the set: letters,
# digits, '.' and '-', with a letter, and with a dot unless it is its entry's only token,
# so the nft keywords of a broken entry such as '1.1.1.1; flush ruleset' never reach nft.
# Any other token would make nft reject the whole list or inject nft commands
check_set_entries() {
    local name="$1" option="$2" set="$3" value="$4" report="$5"
    local part token count line result kept="" glob_off=0 IFS nl='
'
    case "$-" in *f*) glob_off=1 ;; esac
    set -f
    IFS=,
    for part in $value; do
        unset IFS  # split at whitespace; the local IFS ends with the function
        count=0
        for token in $part; do count=$((count + 1)); done
        for token in $part; do
            if is_ipv4_entry "$token" && ipv4_range_ordered "$token"; then
                kept="$kept,$token"
                continue
            fi
            case "$token" in
                *[!A-Za-z0-9.-]*|[.-]*|*[.-]) ;;
                *[A-Za-z]*.*|*.*[A-Za-z]*) kept="$kept,$token"; continue ;;
                *[A-Za-z]*) [ "$count" -eq 1 ] && { kept="$kept,$token"; continue; } ;;
            esac
            [ "$report" -eq 1 ] || continue
            log_and_print "Error: filter $name, $option: skipped '$token', not an IPv4 address, prefix, range or host name" 0
            printf '[%s] %s of filter %s: %s -> Error: not an IPv4 address, prefix, range or host name, skipped (@%s)\n' \
                "$(date '+%Y-%m-%d %H:%M:%S')" "$option" "$name" "$token" "$set" >> "$NFT_ERROR_LOG"
        done
    done
    kept="${kept#,}"

    # Overlaps are only possible with several entries or a range
    case "$kept" in
        *[,-]*)
            if result=$(merge_set_entries "$name" "$option" "$kept"); then
                kept="${result##*"$nl"}"
                IFS="$nl"
                if [ "$report" -eq 1 ] && [ "$result" != "$kept" ]; then
                    for line in ${result%"$nl"*}; do log_and_print "$line" 1; done
                fi
            else
                log_and_print "Error: failed to check the $option entries of $name for overlaps" 0
            fi
            ;;
    esac
    [ "$glob_off" -eq 1 ] || set +f
    set_entries="$kept"
}

# Element lists of filter section $1 for its sets, shared by the start, the live reload
# and the loop harvest (check_set_entries): sets allowed_entries from the allowed_ip list
# and blocked_entries from the comma-separated blocked_ips option. $2: filter name,
# $3: set name prefix, $4: 1 to report skipped and merged entries, 0 to stay quiet
filter_set_entries() {
    local allowed_ips="" blocked_ips set_entries
    config_list_foreach "$1" 'allowed_ip' append_allowed_ip
    check_set_entries "$2" allowed_ip "${3}_allowed" "$allowed_ips" "$4"
    allowed_entries="$set_entries"
    config_get blocked_ips "$1" 'blocked_ips'
    check_set_entries "$2" blocked_ips "${3}_blocked" "$blocked_ips" "$4"
    blocked_entries="$set_entries"
}

# Add element list $2 (filter_set_entries) to set $1 at start; $3: allowed or blocked,
# for the log. When nft rejects the list (such as a host name that does not resolve),
# log it with the set reference that marks the filter in the status, write the marker
# that tells the loop harvest the list is not in the set, and return 1
add_filter_entries() {
    local error_output nl='
'
    [ -n "$2" ] || return 0
    log_and_print "Manually adding $3 IPs: $2" 2
    error_output=$(nft add element inet geomate "$1" { "$2" } 2>&1) && return 0
    log_and_print "Error: nft rejected the $3 IPs of set $1: $error_output" 0
    # First line only: nft repeats the whole command after it
    printf '[%s] nft add element inet geomate %s { %s } -> Error: %s (@%s)\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" "${error_output%%"$nl"*}" "$1" >> "$NFT_ERROR_LOG"
    : > "${GEOMATE_TMP_DIR}/${1}.entries_failed"
    return 1
}

# Set up a geo filter based on configuration
setup_geo_filter() {
    local name protocol src_ip src_port dest_port enabled
    local allowed_entries blocked_entries
    local allowed_regions=""
    
    config_get name "$1" 'name'
    config_get protocol "$1" 'protocol'
    config_get src_ip "$1" 'src_ip'
    config_get src_port "$1" 'src_port'
    config_get dest_port "$1" 'dest_port'
    config_get enabled "$1" 'enabled' '0'

    # Collect allowed_region entries
    config_list_foreach "$1" 'allowed_region' append_allowed_region

    [ "$enabled" = "0" ] && return

    local set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"

    log_and_print "Setting up geo filter for $name" 1

    # Create sets for this filter
    nft_exec add set inet geomate "${set_name}_allowed" { type ipv4_addr\; flags interval\; }
    nft_exec add set inet geomate "${set_name}_blocked" { type ipv4_addr\; flags interval\; }

    # Add allowed and blocked IPs. A list nft rejects (such as a host name that does not
    # resolve) is missing from its set, so it covers no geolocated IPs: they go to the
    # set themselves, here and in the loop harvest
    filter_set_entries "$1" "$name" "$set_name" 1
    add_filter_entries "${set_name}_allowed" "$allowed_entries" allowed || allowed_entries=""
    add_filter_entries "${set_name}_blocked" "$blocked_entries" blocked || blocked_entries=""

    # Process all allowed regions together
    if [ -n "$allowed_regions" ]; then
        log_and_print "Processing geo data for $name with allowed regions: $allowed_regions" 2
        process_geo_data "$name" "${set_name}_allowed" "${set_name}_blocked" "$allowed_regions" \
            "$allowed_entries" "$blocked_entries"
    fi

    # Add rules for allowed and blocked IPs. If nft rejects the Source IP, nft_exec logs
    # it with @<set>_allowed and the filter gets no rules, as before
    build_src_match "$src_ip" || \
        log_and_print "Source IP '$src_ip' of filter $name is not a list of IPv4 entries: passed to nft unchanged" 1
    [ "$src_exceptions_only" -eq 1 ] && \
        log_and_print "Source IP of $name has exceptions only: the filter applies to all other devices" 0
    local base_rule="$src_match"
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
    if nft_exec add rule inet geomate forward "$base_rule" ip daddr @"${set_name}"_allowed counter accept; then
        log_and_print "Successfully added forward rule for allowed IPs in $name" 2
    else
        log_and_print "ERROR: Failed to add forward rule for $name! Check $NFT_ERROR_LOG" 0
    fi
    
    # Only add drop rule if not in monitor mode
    if [ "$operational_mode" != "monitor" ]; then
        log_and_print "Adding drop rule: $base_rule ip daddr @${set_name}_blocked counter drop" 2
        if nft_exec add rule inet geomate forward "$base_rule" ip daddr @"${set_name}"_blocked counter drop; then
            log_and_print "Successfully added drop rule for blocked IPs in $name" 2
        else
            log_and_print "ERROR: Failed to add drop rule for $name! Check $NFT_ERROR_LOG" 0
        fi
    else
        log_and_print "Monitor mode: Not adding drop rule for blocked IPs in $name" 2
    fi

    # Strict mode rule - only apply if not in monitor mode
    if [ "$strict_mode" = "1" ] && [ "$operational_mode" != "monitor" ]; then
        log_and_print "Strict mode: Adding default drop rule: $base_rule counter drop" 2
        if nft_exec add rule inet geomate forward "$base_rule" counter drop; then
            log_and_print "Strict mode: Successfully added default drop rule for $name" 2
        else
            log_and_print "ERROR: Strict mode - Failed to add default drop rule for $name!" 0
        fi
    fi

    log_and_print "Geo filter for $name set up successfully" 1
    log_and_print "Added allowed IPs from config: $allowed_entries" 2
    log_and_print "Added blocked IPs: $blocked_entries" 2
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

    # Create the base rule. setup_geo_filter has logged an unchecked Source IP already
    build_src_match "$src_ip"
    local base_rule="$src_match"
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
    if nft_exec add rule inet geomate prerouting "$base_rule" update @"${set_name}"_ui_dynamic { ip daddr }; then
        log_and_print "Successfully added UI dynamic set rule for $name" 2
    else
        log_and_print "ERROR: Failed to add UI dynamic set rule for $name! Check $NFT_ERROR_LOG" 0
    fi

    # Add rule for the main dynamic set only in dynamic mode
    if [ "$operational_mode" != "static" ]; then
        log_and_print "Adding prerouting rule for dynamic set: $base_rule update @${set_name}_dynamic { ip daddr }" 2
        if nft_exec add rule inet geomate prerouting "$base_rule" update @"${set_name}"_dynamic { ip daddr }; then
            log_and_print "Successfully added main dynamic set rule for $name" 2
        else
            log_and_print "ERROR: Failed to add main dynamic set rule for $name! Check $NFT_ERROR_LOG" 0
        fi
    fi

    log_and_print "Sets for $name set up successfully" 1
}

# Merge the public IPs of a filter's _dynamic set into its ip_list. Shared by the loop
# (process_dynamic_set) and the 'harvest' command; the caller holds the sets lock.
# List lines are "IP", or "IP,<unix time>" with ip_expiry_days > 0: then a known IP
# gets the current time once its time is ip_expiry_days * harvest_refresh_per_day
# seconds old, at most a day. New IPs are appended. Sets harvest_added to their number
harvest_dynamic_set() {
    local name ip_list expiry_days set_name elements
    harvest_added=0
    config_get name "$1" 'name'
    config_get ip_list "$1" 'ip_list'
    config_get expiry_days "$1" 'ip_expiry_days' '0'
    [ -n "$ip_list" ] || { log_and_print "Filter $name has no ip_list configured, skipping harvest" 2; return 0; }
    set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"

    # Only filters that were enabled outside static mode at the last start have this set
    elements=$(nft list set inet geomate "${set_name}_dynamic" 2>/dev/null) || return 0

    log_and_print "Processing dynamic set for $name" 2

    local set_file="${GEOMATE_TMP_DIR}/${set_name}_harvest.txt"
    local public_file="${GEOMATE_TMP_DIR}/${set_name}_public.txt"
    local new_file="${GEOMATE_TMP_DIR}/${set_name}_new.txt"
    local counts_file="${GEOMATE_TMP_DIR}/${set_name}_counts.txt"
    local list_tmp="${GEOMATE_TMP_DIR}/${set_name}_list.tmp"
    local ip old_list="$ip_list" skipped_private=0 updated_count=0

    printf '%s\n' "$elements" | sed -n '/elements = {/,/}/p' | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u > "$set_file"

    : > "$public_file"
    while IFS= read -r ip; do
        if is_valid_public_ip "$ip"; then
            echo "$ip" >> "$public_file"
        else
            skipped_private=$((skipped_private + 1))
            log_and_print "  Skipped private/invalid IP: $ip" 3
        fi
    done < "$set_file"
    [ "$skipped_private" -gt 0 ] && log_and_print "Skipped $skipped_private private/invalid IPs for $name" 2

    if [ ! -s "$public_file" ]; then
        log_and_print "No new IPs in dynamic set for $name" 2
        rm -f "$set_file" "$public_file"
        return 0
    fi

    # One pass over the list: refresh the timestamps of known IPs (expiry enabled),
    # append the new IPs in sorted order, count both
    [ -f "$ip_list" ] || old_list=/dev/null
    awk -F, -v now="$(date +%s)" -v expiry="$expiry_days" -v per_day="$harvest_refresh_per_day" \
        -v counts="$counts_file" -v new_file="$new_file" '
        BEGIN { min_age = expiry * per_day; if (min_age > 86400) min_age = 86400 }
        FILENAME == ARGV[1] { harvested[$0] = 1; order[++n] = $0; next }
        $0 == "" { next }
        ($1 in harvested) {
            known[$1] = 1
            if (expiry != "0" && (min_age == 0 || now - $2 >= min_age)) { print $1 "," now; updated++; next }
        }
        { print }
        END {
            printf "" > new_file
            for (i = 1; i <= n; i++) {
                if (order[i] in known) continue
                if (expiry != "0") print order[i] "," now
                else print order[i]
                print order[i] > new_file
                added++
            }
            print added + 0, updated + 0 > counts
        }' "$public_file" "$old_list" > "$list_tmp" || {
        log_and_print "Error: failed to merge the dynamic set of $name into $ip_list" 0
        rm -f "$set_file" "$public_file" "$new_file" "$counts_file" "$list_tmp"
        return 0
    }
    read -r harvest_added updated_count < "$counts_file"

    if [ "$harvest_added" -gt 0 ]; then
        log_and_print "New IPs found in dynamic set for $name:" 2
    else
        log_and_print "No new IPs in dynamic set for $name" 2
    fi
    while IFS= read -r ip; do
        log_and_print "  Will add new IP: $ip" 2
    done < "$new_file"

    # Only write to flash if there are changes
    if [ "$harvest_added" -gt 0 ] || [ "$updated_count" -gt 0 ]; then
        if cmp -s "$list_tmp" "$ip_list"; then
            rm -f "$list_tmp"
        elif mv "$list_tmp" "$ip_list"; then
            log_and_print "Updated IP list for $name: $harvest_added added, $updated_count timestamps updated" 2
        else
            log_and_print "Error: failed to update IP list $ip_list for $name" 0
            harvest_added=0
        fi
    fi

    rm -f "$set_file" "$public_file" "$new_file" "$counts_file" "$list_tmp"
}

# Loop harvest: merge the _dynamic set into the IP list, then add the geolocated IPs of
# the list to the filter's sets when the list gained new IPs
process_dynamic_set() {
    local name set_name allowed_regions="" allowed_entries blocked_entries
    harvest_dynamic_set "$1"
    [ "$harvest_added" -gt 0 ] || return 0

    config_get name "$1" 'name'
    # Read the regions as a list, like the start and the live reload do
    config_list_foreach "$1" 'allowed_region' append_allowed_region
    [ -n "$allowed_regions" ] || return 0
    set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"
    # The start has reported skipped entries already
    filter_set_entries "$1" "$name" "$set_name" 0
    # A list nft rejected at start covers nothing (add_filter_entries). A live reload
    # never runs after such a start: its nft error makes the reload restart instead
    [ -f "${GEOMATE_TMP_DIR}/${set_name}_allowed.entries_failed" ] && allowed_entries=""
    [ -f "${GEOMATE_TMP_DIR}/${set_name}_blocked.entries_failed" ] && blocked_entries=""

    process_geo_data "$name" "${set_name}_allowed" "${set_name}_blocked" "$allowed_regions" \
        "$allowed_entries" "$blocked_entries"
}

# Update dynamic IPs based on configuration. The config is read on every run, so a
# live reload of the regions reaches the next harvest
update_dynamic_ips() {
    if acquire_sets_lock; then
        config_load 'geomate'
        config_foreach process_dynamic_set 'geo_filter'
        release_sets_lock
    fi

    # Write geolocation status after processing
    write_geolocation_status
}

# Harvest before a stop: merge every _dynamic set into its IP list so a restart loses
# no collected IP. Reads the configuration the sets were built from, so a renamed filter
# still finds its set. Leaves the sets, the geo data and the status file alone
harvest_all() {
    local UCI_CONFIG_DIR="$UCI_CONFIG_DIR"
    [ -f "$BUILT_CONFIG_DIR/geomate" ] && UCI_CONFIG_DIR="$BUILT_CONFIG_DIR"
    # The loop refreshes timestamps every 30 minutes. A stop refreshes only timestamps
    # one hour old per expiry day (at most a day): it rarely writes the list to flash
    # for known IPs, and a timestamp it leaves is far younger than the expiry window,
    # so the cleanup at the next start never drops an IP of the _dynamic set (1 h timeout)
    harvest_refresh_per_day=3600
    acquire_sets_lock || return 1
    config_load 'geomate'
    config_foreach harvest_dynamic_set 'geo_filter'
    release_sets_lock
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

# Split the geolocated IPs of a filter by its regions (Haversine, R = 6371000 m).
# Shared by the start, the loop harvest and the live reload.
# $1 = geo data file, $2 = regions ("circle:lat:lon:radius_m ..."), $3 and $4 = element
# lists of allowed_ip and blocked_ips (filter_set_entries). An in-region IP inside an
# entry of $3 is left out of the allowed IPs, an out-of-region IP inside an entry of $4
# out of the blocked IPs: the entry matches it already, and the sets reject overlaps
# PERFORMANCE OPTIMIZATION: Process ALL IPs in a SINGLE awk process
# Instead of spawning a new awk process for each IP (11000+ processes),
# we do everything in one pass: parse regions, calculate haversine, categorize IPs
# Output format: First line = comma-separated allowed IPs, Second line = comma-separated blocked IPs,
# third line = the numbers of allowed and blocked IPs left out
split_geo_data() {
    jq -r '. | [.query, .lat, .lon] | @tsv' "$1" 2>/dev/null | \
        awk -v regions="$2" -v allowed_cover="$3" -v blocked_cover="$4" "$AWK_IPV4_ENTRY"'
        # Load element list "list": its addresses as keys of ips[], its prefixes and ranges
        # into lo[] and hi[]. Returns the number of prefixes and ranges
        function load_cover(list, ips, lo, hi,    t, n, i, k, kind) {
            n = split(list, t, ",")
            for (i = 1; i <= n; i++) {
                kind = parse_entry(t[i])
                if (kind == 1) ips[t[i]] = 1
                else if (kind == 2) { k++; lo[k] = e_lo; hi[k] = e_hi }
            }
            return k + 0
        }
        # One lookup for the addresses, a scan over the n prefixes and ranges
        function covered(ip, ips, n, lo, hi,    x, i) {
            if (ip in ips) return 1
            if (!n) return 0
            x = ip2n(ip)
            for (i = 1; i <= n; i++) if (x >= lo[i] && x <= hi[i]) return 1
            return 0
        }
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
            split("", acover_ip); split("", bcover_ip)
            n_acover = load_cover(allowed_cover, acover_ip, acover_lo, acover_hi)
            n_bcover = load_cover(blocked_cover, bcover_ip, bcover_lo, bcover_hi)
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
                if (allowed_cover != "" && covered(ip, acover_ip, n_acover, acover_lo, acover_hi)) { left_allowed++; next }
                if (allowed_list != "") allowed_list = allowed_list ","
                allowed_list = allowed_list ip
            } else {
                if (blocked_cover != "" && covered(ip, bcover_ip, n_bcover, bcover_lo, bcover_hi)) { left_blocked++; next }
                if (blocked_list != "") blocked_list = blocked_list ","
                blocked_list = blocked_list ip
            }
        }
        END {
            # Output three lines: allowed IPs, blocked IPs, the numbers left out
            print allowed_list
            print blocked_list
            print left_allowed + 0, left_blocked + 0
        }'
}

# Process geo data from the JSON file
# $1: name, $2: allowed set, $3: blocked set, $4: allowed regions, $5 and $6: element
# lists of allowed_ip and blocked_ips (filter_set_entries)
process_geo_data() {
    local name="$1"
    local allowed_set="$2"
    local blocked_set="$3"
    local allowed_regions="$4"
    local geo_data_file="${GEOMATE_DATA_DIR}/${name}_geo_data.json"

    [ ! -f "$geo_data_file" ] && { log_and_print "Geo data file not found: $geo_data_file" 0; return; }
    [ -z "$allowed_regions" ] && { log_and_print "No allowed regions specified for $name" 0; return; }

    log_and_print "Processing geo data for $name with allowed regions: $allowed_regions" 2

    local result
    result=$(split_geo_data "$geo_data_file" "$allowed_regions" "$5" "$6")

    # Parse the result: allowed IPs, blocked IPs, the numbers left out
    local allowed_ips blocked_ips left_out
    allowed_ips=$(echo "$result" | sed -n '1p')
    blocked_ips=$(echo "$result" | sed -n '2p')
    left_out=$(echo "$result" | sed -n '3p')

    # Count IPs for logging
    local allowed_count=0 blocked_count=0
    [ -n "$allowed_ips" ] && allowed_count=$(echo "$allowed_ips" | tr ',' '\n' | wc -l)
    [ -n "$blocked_ips" ] && blocked_count=$(echo "$blocked_ips" | tr ',' '\n' | wc -l)
    log_and_print "Geo processing for $name: $allowed_count allowed, $blocked_count blocked IPs" 1
    [ "${left_out:-0 0}" = "0 0" ] || \
        log_and_print "Geo processing for $name: left out ${left_out% *} allowed IPs inside allowed_ip entries, ${left_out#* } blocked IPs inside blocked_ips entries" 2

    # Batch update the sets - handling potential large IP lists
    add_ips_to_set() {
        local set_name="$1"
        local ip_list="$2"
        local chunk_size=1000
        local total_ips
        local start=1
        local success=1
        local end chunk error_output ret nl='
'
        
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
            
            # Add this chunk to the set (no eval: the set name comes from the filter name)
            error_output=$(nft add element inet geomate "$set_name" { "$chunk" } 2>&1)
            ret=$?
            
            if [ "$ret" -ne 0 ]; then
                log_and_print "ERROR: Failed to add IPs (chunk $start-$end) to set $set_name: $error_output" 0
                # First line only: nft repeats the whole command after it. The set
                # reference marks the filter in the status like an nft_exec error
                printf '[%s] nft add element inet geomate %s { IPs %s-%s of %s } -> Error: %s (@%s)\n' \
                    "$(date '+%Y-%m-%d %H:%M:%S')" "$set_name" "$start" "$end" "$total_ips" \
                    "${error_output%%"$nl"*}" "$set_name" >> "$NFT_ERROR_LOG"
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

# Print 'add element' commands for a comma-separated IP list, 1000 IPs per command
print_set_elements() {
    [ -n "$2" ] || return 0
    printf '%s\n' "$2" | tr ',' '\n' | awk -v set="$1" '
        { chunk = chunk (n++ % 1000 ? "," : "") $0 }
        n % 1000 == 0 { print "add element inet geomate " set " { " chunk " }"; chunk = "" }
        END { if (chunk != "") print "add element inet geomate " set " { " chunk " }" }'
}

# config_foreach callback of reload_regions: for a changed, enabled filter append the
# commands that refill its _allowed and _blocked sets to $reload_batch, with the same
# content as at start (allowed_ip, blocked_ips, geolocated IPs split by region)
reload_filter_sets() {
    local name enabled set_name result geo_data_file allowed_entries blocked_entries
    local allowed_regions="" geo_allowed="" geo_blocked=""
    local allowed_count=0 blocked_count=0

    case "$reload_sections" in *" $1 "*) ;; *) return 0 ;; esac
    config_get enabled "$1" 'enabled' '0'
    [ "$enabled" = "0" ] && return 0

    config_get name "$1" 'name'
    config_list_foreach "$1" 'allowed_region' append_allowed_region
    set_name="${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"
    filter_set_entries "$1" "$name" "$set_name" 1
    geo_data_file="${GEOMATE_DATA_DIR}/${name}_geo_data.json"

    if [ -n "$allowed_regions" ] && [ -f "$geo_data_file" ]; then
        result=$(split_geo_data "$geo_data_file" "$allowed_regions" "$allowed_entries" "$blocked_entries")
        geo_allowed=$(echo "$result" | sed -n '1p')
        geo_blocked=$(echo "$result" | sed -n '2p')
    fi
    [ -n "$geo_allowed" ] && allowed_count=$(echo "$geo_allowed" | tr ',' '\n' | wc -l)
    [ -n "$geo_blocked" ] && blocked_count=$(echo "$geo_blocked" | tr ',' '\n' | wc -l)

    {
        printf 'flush set inet geomate %s\n' "${set_name}_allowed" "${set_name}_blocked"
        [ -n "$allowed_entries" ] && printf 'add element inet geomate %s { %s }\n' "${set_name}_allowed" "$allowed_entries"
        [ -n "$blocked_entries" ] && printf 'add element inet geomate %s { %s }\n' "${set_name}_blocked" "$blocked_entries"
        print_set_elements "${set_name}_allowed" "$geo_allowed"
        print_set_elements "${set_name}_blocked" "$geo_blocked"
    } >> "$reload_batch"
    echo "Live reload of $name: $allowed_count allowed, $blocked_count blocked geolocated IPs" >> "${reload_batch}.log"
}

# Print configuration file $1 without its 'list allowed_region' and 'list allowed_ip' lines
strip_reloadable_lists() {
    sed '/^[[:space:]]*list[[:space:]][[:space:]]*allowed_\(region\|ip\)[[:space:]]/d' "$1"
}

# config_foreach callback: print the set name prefix of an enabled filter
print_enabled_set_name() {
    local name enabled
    config_get enabled "$1" 'enabled' '0'
    [ "$enabled" = "0" ] && return 0
    config_get name "$1" 'name'
    echo "${NFT_SET_PREFIX}$(echo "$name" | tr ' ' '_')"
}

# Live reload (reload_service): when only allowed_region or allowed_ip lists changed since
# the configuration copy of the last start, refill the _allowed and _blocked sets of
# the changed, enabled filters in one nft transaction. Rules, counters, _dynamic and
# _ui_dynamic stay, so the collected IPs and the harvest timer survive. The caller
# removes the work directory. Returns 1 when the service has to be restarted instead
reload_regions() {
    local work="${GEOMATE_TMP_DIR}/reload" changed line
    local UCI_CONFIG_DIR="$UCI_CONFIG_DIR"
    reload_batch="${work}/batch.nft"
    reload_sections=""

    if [ ! -f "$BUILT_CONFIG_DIR/geomate" ] || [ -f /tmp/geomate_loading ]; then
        log_and_print "Live reload: no finished start to compare with, restarting" 1
        return 1
    fi
    if ! nft list chain inet geomate prerouting >/dev/null 2>&1; then
        log_and_print "Live reload: table inet geomate is missing, restarting" 1
        return 1
    fi
    if [ -s "$NFT_ERROR_LOG" ]; then
        log_and_print "Live reload: the last start had nft errors, restarting" 1
        return 1
    fi
    rm -rf "$work"
    if ! copy_config "$work/config" || ! show_config "$work/config" > "$work/new.txt" || \
        ! show_config "$BUILT_CONFIG_DIR" > "$work/old.txt"; then
        log_and_print "Error: failed to read the configuration" 0
        return 1
    fi
    # show_config applies the current pending changes to both copies, but the sets
    # were built with those of the start
    if ! cmp -s "$work/config/pending" "$BUILT_CONFIG_DIR/pending"; then
        log_and_print "Live reload: pending uci changes differ from the last start, restarting" 1
        return 1
    fi
    # uci show prints a one-element list like an option, but the sets read only lists.
    # Both copies come from the same uci writer, so any file change besides 'list
    # allowed_region' and 'list allowed_ip' lines (such as an option turned into a list)
    # needs a restart
    strip_reloadable_lists "$BUILT_CONFIG_DIR/geomate" > "$work/old.conf"
    strip_reloadable_lists "$work/config/geomate" > "$work/new.conf"
    if ! cmp -s "$work/old.conf" "$work/new.conf"; then
        log_and_print "Live reload: configuration lines other than allowed_region and allowed_ip lists changed, restarting" 1
        return 1
    fi

    # Lines that differ between the copy of the last start and the current configuration
    changed=$(awk 'FILENAME == ARGV[1] { old[$0] = 1; next }
        ($0 in old) { delete old[$0]; next }
        { print }
        END { for (line in old) print line }' "$work/old.txt" "$work/new.txt")
    if [ -z "$changed" ]; then
        log_and_print "Live reload: configuration unchanged" 1
        return 0
    fi

    # Section IDs of the changed allowed_region and allowed_ip lists; any other change
    # needs a restart
    reload_sections=$(printf '%s\n' "$changed" | awk '
        { key = substr($0, 1, index($0, "=") - 1) }
        key !~ /^geomate\.[A-Za-z0-9_]+\.allowed_(region|ip)$/ { bad = 1; exit }
        { split(key, part, "."); if (!(part[2] in seen)) { seen[part[2]] = 1; printf " %s", part[2] } }
        END { if (bad) exit 1; print " " }') || {
        log_and_print "Live reload: options other than allowed_region and allowed_ip changed, restarting" 1
        return 1
    }

    # Read the copy, so the sets and the next comparison see the same configuration
    UCI_CONFIG_DIR="$work/config"
    config_load 'geomate'
    # Filters whose names give the same set name share their sets at start
    if [ -n "$(config_foreach print_enabled_set_name 'geo_filter' | sort | uniq -d)" ]; then
        log_and_print "Live reload: enabled filters share a set name, restarting" 1
        return 1
    fi

    : > "$reload_batch"
    : > "${reload_batch}.log"
    config_foreach reload_filter_sets 'geo_filter'

    if [ -s "$reload_batch" ]; then
        if ! nft -f "$reload_batch" 2> "${reload_batch}.err"; then
            log_and_print "Error: live reload failed, restarting: $(head -n 1 "${reload_batch}.err" | cut -c 1-200)" 0
            return 1
        fi
        while IFS= read -r line; do
            log_and_print "$line" 1
        done < "${reload_batch}.log"
    else
        log_and_print "Live reload: only regions or allowed IPs of disabled filters changed" 1
    fi

    mv "$work/config/geomate" "$BUILT_CONFIG_DIR/geomate"
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

# Main function to run the service
run() {
    # Copy of the configuration the sets are built from: the live reload compares
    # against it, the stop harvest takes the set names from it
    rm -rf "$BUILT_CONFIG_DIR" "${BUILT_CONFIG_DIR}.new"
    # Takeover claims of a process killed while taking over a stale sets lock
    rm -rf "${SETS_LOCK}.stale."*
    copy_config "${BUILT_CONFIG_DIR}.new" || log_and_print "Error: failed to copy the configuration" 0

    load_config
    setup_geomate_d

    # Clean up expired IPs before loading filters
    cleanup_all_expired_ips

    # Create loading flag file
    log_and_print "Creating loading flag file at /tmp/geomate_loading" 1
    touch /tmp/geomate_loading

    setup_nftables_and_filters
    [ -f "${BUILT_CONFIG_DIR}.new/geomate" ] && mv "${BUILT_CONFIG_DIR}.new" "$BUILT_CONFIG_DIR"

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
    rm -rf "$BUILT_CONFIG_DIR"
    log_and_print "nftables rules cleaned up" 1
}

# Handle script arguments
case "$1" in
    cleanup)
        cleanup_nftables
        ;;
    harvest)
        # Called by stop_service while the table still exists
        load_config
        harvest_all || exit 1
        ;;
    reload)
        # Called by reload_service; exit 1 means a restart is needed
        load_config
        acquire_sets_lock || exit 1
        reload_regions
        reload_status=$?
        rm -rf "${GEOMATE_TMP_DIR}/reload"
        release_sets_lock
        exit "$reload_status"
        ;;
    capabilities)
        # Stable contract for the web interface: one line of space-separated feature
        # tokens. Tokens are only added, never renamed or removed. Reads no
        # configuration, takes no lock and writes nothing. An older geomate.sh prints
        # the usage and exits 1, which means no capabilities.
        # src_ip_multi: Source IP accepts several entries and exceptions with ! or !=
        printf '%s\n' 'src_ip_multi'
        ;;
    run)
        run
        ;;
    *)
        echo "Usage: $0 {run|cleanup|harvest|reload|capabilities}"
        exit 1
esac

exit 0
