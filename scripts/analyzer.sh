#!/usr/bin/env bash

# ===============================================================
# WINDOWS FORENSICS - PROJECT: ANALYZER (NX212)
# Student name: Javor Mirchev
# Student code: s3
# Unit code: TCB-2511
# Lecturer: Yuri Tsenkov
# ===============================================================

set -u
set -o pipefail
umask 027

START_TIME=$(date +%s)
IMAGE_FILE=""
OUTPUT_DIR=""
REPORT_FILE=""
ARCHIVE_FILE=""
INITIAL_HASH=""
FINAL_HASH=""
IMAGE_KIND="unknown"
MEMORY_PROFILE="Not applicable"
APT_UPDATED=0
VOL_COMMAND=""

RUN_USER=""
USER_HOME=""
USER_VOLATILITY=""


# Prints a message and saves it in the report.
log() {
    echo "[*] $1" | tee -a "$REPORT_FILE"
}


# The project must be started as root.
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run the script with: sudo $0"
        exit 1
    fi
}


# Gets the image path from an argument or asks the user for it.
choose_image() {
    if [[ -n "${1:-}" ]]; then
        IMAGE_FILE="$1"
    else
        read -r -p "Enter the HDD or memory image path: " IMAGE_FILE
    fi

    if [[ ! -f "$IMAGE_FILE" ]]; then
        echo "[ERROR] File not found: $IMAGE_FILE"
        exit 1
    fi

    if [[ ! -r "$IMAGE_FILE" ]]; then
        echo "[ERROR] File is not readable: $IMAGE_FILE"
        exit 1
    fi

    IMAGE_FILE=$(readlink -f -- "$IMAGE_FILE")
}


# Creates one directory for all results.
create_output() {
    local name timestamp

    name=$(basename "$IMAGE_FILE")
    name=${name//[^a-zA-Z0-9._-]/_}
    timestamp=$(date +%Y%m%d_%H%M%S)

    OUTPUT_DIR="$(pwd)/analysis_${name}_${timestamp}"
    REPORT_FILE="$OUTPUT_DIR/report.txt"
    ARCHIVE_FILE="${OUTPUT_DIR}.zip"

    mkdir -p \
        "$OUTPUT_DIR/logs" \
        "$OUTPUT_DIR/strings" \
        "$OUTPUT_DIR/volatility"

    touch "$REPORT_FILE"

    {
        echo "WINDOWS FORENSICS ANALYZER"
        echo "=================================="
        echo
        echo "Started: $(date)"
        echo "Image: $IMAGE_FILE"
        echo "Output: $OUTPUT_DIR"
        echo
    } >> "$REPORT_FILE"
}


# Returns generated files to the user who started sudo.
restore_ownership() {
    local user_group

    if [[ "$RUN_USER" == "root" ]] || ! id "$RUN_USER" >/dev/null 2>&1; then
        return
    fi

    user_group=$(id -gn "$RUN_USER")

    chown -R "$RUN_USER:$user_group" "$OUTPUT_DIR" 2>/dev/null || true

    if [[ -n "$ARCHIVE_FILE" && -e "$ARCHIVE_FILE" ]]; then
        chown "$RUN_USER:$user_group" "$ARCHIVE_FILE" 2>/dev/null || true
    fi
}


# Keeps partial results if the analysis is interrupted.
handle_interrupt() {
    trap - INT TERM
    echo
    log "Analysis interrupted. Partial results were kept in: $OUTPUT_DIR"
    restore_ownership
    exit 130
}


# Installs one missing program with apt.
install_if_missing() {
    local command_name=$1
    local package_name=$2

    if command -v "$command_name" >/dev/null 2>&1; then
        log "$command_name is installed."
        return 0
    fi

    if [[ $APT_UPDATED -eq 0 ]]; then
        log "Updating the Kali package list..."

        if ! apt-get update \
            >> "$OUTPUT_DIR/logs/installation.log" 2>&1; then
            log "The Kali package list could not be updated."
            return 1
        fi

        APT_UPDATED=1
    fi

    log "Installing $package_name..."

    if apt-get install -y "$package_name" \
        >> "$OUTPUT_DIR/logs/installation.log" 2>&1; then
        log "$package_name was installed."
        return 0
    fi

    log "$package_name could not be installed."
    return 1
}


# Finds the available Volatility 3 command.
find_volatility() {
    VOL_COMMAND=""

    if command -v vol.py >/dev/null 2>&1; then
        VOL_COMMAND=$(command -v vol.py)
    elif command -v vol >/dev/null 2>&1; then
        VOL_COMMAND=$(command -v vol)
    elif [[ -x "$USER_VOLATILITY" ]]; then
        VOL_COMMAND="$USER_VOLATILITY"
    fi

    [[ -n "$VOL_COMMAND" ]]
}


# Checks all programs used by the project.
install_tools() {
    install_if_missing bulk_extractor bulk-extractor || true
    install_if_missing binwalk binwalk || true
    install_if_missing foremost foremost || true
    install_if_missing strings binutils || true
    install_if_missing file file || true
    install_if_missing zip zip || true

    if ! find_volatility; then
        install_if_missing vol volatility3 || true
    fi

    if find_volatility; then
        log "Volatility 3 is installed."
    else
        log "Volatility 3 is missing."
    fi
}


# Saves file type, size and the initial hash.
collect_basic_info() {
    log "Collecting basic image information..."

    INITIAL_HASH=$(sha256sum -- "$IMAGE_FILE" | awk '{print $1}')

    if [[ -z "$INITIAL_HASH" ]]; then
        log "The initial SHA-256 hash could not be calculated."
        return 1
    fi

    {
        echo "BASIC IMAGE INFORMATION"
        echo "-----------------------"
        file -- "$IMAGE_FILE"
        echo "Size: $(stat -c '%s bytes' -- "$IMAGE_FILE")"
        echo "SHA-256 before analysis: $INITIAL_HASH"
        echo
    } >> "$REPORT_FILE"
}


# Chooses memory mode or HDD/file mode before extraction starts.
detect_image_type() {
    local info_file lower_name

    info_file="$OUTPUT_DIR/volatility/windows_info.txt"
    lower_name="${IMAGE_FILE,,}"

    if [[ -z "$VOL_COMMAND" ]]; then
        if [[ "$lower_name" =~ \.(mem|vmem|dmp)$ ]]; then
            log "The file looks like a memory image, but Volatility 3 is unavailable."
            return 1
        fi

        IMAGE_KIND="disk"
        MEMORY_PROFILE="Not applicable (HDD/file image)"
        log "Volatility 3 is unavailable. HDD/file mode was selected."
        return 0
    fi

    log "Checking the input type with Volatility 3..."

    if "$VOL_COMMAND" -f "$IMAGE_FILE" windows.info \
        > "$info_file" 2>&1 &&
        grep -q '^Kernel Base[[:space:]]' "$info_file"; then

        IMAGE_KIND="memory"

        MEMORY_PROFILE=$(awk \
            '$1 == "Major/Minor" {print $2; exit}' \
            "$info_file")

        [[ -n "$MEMORY_PROFILE" ]] || \
            MEMORY_PROFILE="Volatility 3 automatic symbols"

        log "Supported Windows memory image detected."
        log "Memory profile/build: $MEMORY_PROFILE"
        return 0
    fi

    if [[ "$lower_name" =~ \.(mem|vmem|dmp)$ ]]; then
        IMAGE_KIND="memory-error"
        MEMORY_PROFILE="Detection failed"
        log "The memory image could not be analyzed by Volatility 3."
        log "See: $info_file"
        return 1
    fi

    IMAGE_KIND="disk"
    MEMORY_PROFILE="Not applicable (HDD/file image)"
    log "HDD/file image detected. Volatility memory plugins will be skipped."
}


# Runs file and artefact extraction tools in HDD/file mode.
run_carvers() {
    if command -v bulk_extractor >/dev/null 2>&1; then
        log "Running Bulk Extractor..."

        bulk_extractor \
            -o "$OUTPUT_DIR/bulk_extractor" \
            "$IMAGE_FILE" \
            > "$OUTPUT_DIR/logs/bulk_extractor.log" 2>&1 \
            || log "Bulk Extractor finished with a warning."
    else
        log "Bulk Extractor is missing and was skipped."
    fi

    if command -v foremost >/dev/null 2>&1; then
        log "Running Foremost..."

        foremost \
            -t all \
            -i "$IMAGE_FILE" \
            -o "$OUTPUT_DIR/foremost" \
            > "$OUTPUT_DIR/logs/foremost.log" 2>&1 \
            || log "Foremost finished with a warning."
    else
        log "Foremost is missing and was skipped."
    fi

    if command -v binwalk >/dev/null 2>&1; then
        log "Running Binwalk..."

        mkdir -p "$OUTPUT_DIR/binwalk"

        (
            cd "$OUTPUT_DIR/binwalk" &&
            binwalk -e --run-as=root "$IMAGE_FILE"
        ) > "$OUTPUT_DIR/logs/binwalk.log" 2>&1 \
            || log "Binwalk finished with a warning."
    else
        log "Binwalk is missing and was skipped."
    fi
}


# Finds selected readable text without saving every string.
extract_strings() {
    local account_file executable_file

    if ! command -v strings >/dev/null 2>&1; then
        log "Strings is missing. Text extraction was skipped."
        return
    fi

    account_file="$OUTPUT_DIR/strings/usernames_and_passwords.txt"
    executable_file="$OUTPUT_DIR/strings/executable_names.txt"

    log "Extracting selected human-readable text..."

    LC_ALL=C strings -a -n 6 "$IMAGE_FILE" |
        grep -Eai 'password|passwd|username|user=' \
        > "$account_file" || true

    LC_ALL=C strings -a -n 6 "$IMAGE_FILE" |
        grep -Eai '\.(exe|dll|sys|msi)([^[:alnum:]_]|$)' \
        > "$executable_file" || true
}


# Displays the location and size of possible HDD network evidence.
find_network_data() {
    local list="$OUTPUT_DIR/network_files.txt"

    find "$OUTPUT_DIR" -type f \( \
        -iname '*.pcap' -o \
        -iname '*.pcapng' -o \
        -name 'ip.txt' -o \
        -name 'tcp.txt' -o \
        -name 'domain.txt' -o \
        -name 'url.txt' \
        \) -size +0c -print > "$list"

    if [[ ! -s "$list" ]]; then
        log "No network traffic files were found."
        return
    fi

    log "Possible network data was found:"

    while IFS= read -r network_file; do
        echo "    $network_file ($(du -h "$network_file" | awk '{print $1}'))" \
            | tee -a "$REPORT_FILE"
    done < "$list"
}


# Runs Volatility plugins only in Windows memory mode.
analyze_memory() {
    local vol_dir="$OUTPUT_DIR/volatility"
    local dump_root="$vol_dir/registry_dumps"
    local dump_log="$vol_dir/registry_dump.log"
    local line remainder hive_offset hive_path hive_dir
    local detected_hives=0
    local dumped_hives=0
    local unavailable_hives=0
    local dump_ok

    mkdir -p "$dump_root"
    : > "$dump_log"

    log "Running Volatility 3 memory analysis."

    log "Extracting running processes..."
    if ! "$VOL_COMMAND" -f "$IMAGE_FILE" windows.pslist \
        > "$vol_dir/processes.txt" 2>&1; then
        log "Process extraction finished with a warning."
    fi

    log "Extracting network connections..."
    if ! "$VOL_COMMAND" -f "$IMAGE_FILE" windows.netscan \
        > "$vol_dir/network_connections.txt" 2>&1; then
        log "Network extraction finished with a warning."
    fi

    log "Listing registry hives..."
    if ! "$VOL_COMMAND" -f "$IMAGE_FILE" windows.registry.hivelist \
        > "$vol_dir/registry_hives.txt" 2>&1; then
        log "Registry hive listing finished with a warning."
    fi

    while IFS= read -r line; do
        [[ "$line" == *$'\t'* ]] || continue

        hive_offset=${line%%$'\t'*}
        remainder=${line#*$'\t'}
        hive_path=${remainder%%$'\t'*}

        [[ "$hive_offset" =~ ^0x[0-9a-fA-F]+$ ]] || continue
        [[ -n "$hive_path" ]] || continue

        ((detected_hives += 1))

        hive_dir="$dump_root/${hive_offset#0x}"
        mkdir -p "$hive_dir"
        dump_ok=0

        {
            echo "Hive: $hive_path"
            echo "Offset: $hive_offset"
        } >> "$dump_log"

        if "$VOL_COMMAND" -f "$IMAGE_FILE" \
            -o "$hive_dir" \
            windows.registry.hivelist --filter "$hive_path" --dump \
            >> "$dump_log" 2>&1; then

            if [[ -n "$(find "$hive_dir" -type f -size +0c -print -quit)" ]]; then
                dump_ok=1
            fi
        fi

        if [[ $dump_ok -eq 1 ]]; then
            ((dumped_hives += 1))
            echo "Result: successfully dumped" >> "$dump_log"
        else
            ((unavailable_hives += 1))
            rm -r -- "$hive_dir"
            echo "Result: unavailable or incomplete" >> "$dump_log"
        fi

        echo >> "$dump_log"
    done < "$vol_dir/registry_hives.txt"

    log "Named registry hives detected: $detected_hives"
    log "Registry hives dumped successfully: $dumped_hives"

    if [[ $unavailable_hives -gt 0 ]]; then
        log "Registry hives unavailable for complete dumping: $unavailable_hives"
    fi
}


# Compare hashes before creating a successful report or archive.
verify_image_integrity() {
    if ! FINAL_HASH=$(sha256sum -- "$IMAGE_FILE" | awk '{print $1}'); then
        log "The final SHA-256 hash could not be calculated."
        return 1
    fi
    if [[ -z "$INITIAL_HASH" || -z "$FINAL_HASH" || "$FINAL_HASH" != "$INITIAL_HASH" ]]; then
        log "MISMATCH - verify the input image."
        return 1
    fi
}

# Writes statistics, verifies integrity and creates the ZIP archive.
finish_analysis() {
    local elapsed result_count analysis_count total_size
    local count_label mode_text integrity_status
    local result_bytes free_bytes archive_created

    log "Verifying input image integrity..."

    if ! verify_image_integrity; then
        log "Analysis stopped: an integrity failure must not be reported as success."
        restore_ownership
        trap - INT TERM
        return 1
    fi
    integrity_status="MATCH - input image unchanged"

    elapsed=$(( $(date +%s) - START_TIME ))
    result_count=$(find "$OUTPUT_DIR" -type f | wc -l | tr -d ' ')
    total_size=$(du -sh "$OUTPUT_DIR" | awk '{print $1}')

    if [[ "$IMAGE_KIND" == "memory" ]]; then
        mode_text="Windows memory"
        count_label="Volatility result files"
        analysis_count=$(find \
            "$OUTPUT_DIR/volatility" \
            -type f 2>/dev/null | wc -l | tr -d ' ')
    else
        mode_text="HDD/file"
        count_label="Files produced by HDD/file tools"
        analysis_count=$(find \
            "$OUTPUT_DIR/bulk_extractor" \
            "$OUTPUT_DIR/foremost" \
            "$OUTPUT_DIR/binwalk" \
            "$OUTPUT_DIR/strings" \
            -type f 2>/dev/null | wc -l | tr -d ' ')
    fi

    {
        echo
        echo "FINAL STATISTICS"
        echo "----------------"
        echo "Finished: $(date)"
        echo "Analysis mode: $mode_text"
        echo "Analysis time: $elapsed seconds"
        echo "$count_label: $analysis_count"
        echo "Total result files, including logs: $result_count"
        echo "Results size: $total_size"
        echo "Memory profile/build: $MEMORY_PROFILE"
        echo "SHA-256 after analysis: $FINAL_HASH"
        echo "Integrity check: $integrity_status"
        echo "ZIP archive path: $ARCHIVE_FILE"
        echo
        echo "RESULT FILES"
        echo "------------"
        find "$OUTPUT_DIR" -type f -printf '%s bytes\t%p\n' | sort -nr
    } >> "$REPORT_FILE"

    archive_created=0
    result_bytes=$(du -sb "$OUTPUT_DIR" | awk '{print $1}')
    free_bytes=$(df -PB1 "$OUTPUT_DIR" | awk 'NR == 2 {print $4}')

    if [[ -n "$free_bytes" && -n "$result_bytes" ]] &&
        (( free_bytes > result_bytes + 104857600 )); then

        log "Creating ZIP archive..."

        if (
            cd "$(dirname "$OUTPUT_DIR")" &&
            zip -rq "$(basename "$ARCHIVE_FILE")" "$(basename "$OUTPUT_DIR")"
        ); then
            archive_created=1
            echo "[*] ZIP archive created: $ARCHIVE_FILE"
        else
            log "ZIP archive creation failed."
            rm -f -- "$ARCHIVE_FILE"
        fi
    else
        log "ZIP archive skipped because there is not enough free disk space."
    fi

    restore_ownership
    trap - INT TERM

    echo
    echo "Analysis completed."
    echo "Results: $OUTPUT_DIR"
    echo "Report:  $REPORT_FILE"

    if [[ $archive_created -eq 1 ]]; then
        echo "Archive: $ARCHIVE_FILE"
    else
        echo "Archive: not created"
    fi
}


show_help() {
    cat <<'EOF'
Windows Forensics Analyzer
Usage: bash scripts/analyzer.sh [--help] [IMAGE_FILE]

Analyze an authorized disk or Windows memory image on Kali Linux.
Normal analysis requires root and may install missing APT packages.
Results contain sensitive forensic artifacts; keep them private.
--help performs no installation, analysis or network activity.
EOF
}

main() {
    if [[ ${1:-} == --help || ${1:-} == -h ]]; then
        [[ $# == 1 ]] || { printf 'Help takes no additional arguments.\n' >&2; return 2; }
        show_help
        return 0
    fi
    if (( $# > 1 )) || [[ ${1:-} == -* ]]; then
        printf 'Usage: bash scripts/analyzer.sh [IMAGE_FILE]\n' >&2
        return 2
    fi
    echo "========================================"
    echo "       WINDOWS FORENSICS ANALYZER"
    echo "========================================"

    check_root
    RUN_USER="${SUDO_USER:-root}"
    USER_HOME=$(getent passwd "$RUN_USER" | cut -d ':' -f 6)
    [[ -n "$USER_HOME" ]] || USER_HOME="/root"
    USER_VOLATILITY="$USER_HOME/.local/bin/vol"
    choose_image "${1:-}"
    create_output
    trap handle_interrupt INT TERM

    log "Starting analysis of: $IMAGE_FILE"

    install_tools

    if ! collect_basic_info; then
        log "Analysis stopped because the initial hash failed."
        restore_ownership
        exit 1
    fi

    if ! detect_image_type; then
        log "Analysis stopped before extraction."
        restore_ownership
        exit 1
    fi

    if [[ "$IMAGE_KIND" == "memory" ]]; then
        log "File-carving and Strings tools are skipped for memory images."
        analyze_memory
    else
        run_carvers
        extract_strings
        find_network_data
    fi

    finish_analysis
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
