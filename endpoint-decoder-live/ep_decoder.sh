#!/bin/bash

#*********************************************************************************************************************
#author luicontr
#
#Endpoint Live Decoder for binary epm or epmc logs on ACI Leaf nodes on 4.2 or higher version
#
#*********************************************************************************************************************

#Variable definition for path
EPM_LOGS=/var/sysmgr/tmp_logs
RESULT_PATH=/data/techsupport
BASE_PATH=$RESULT_PATH/ep_decoder
RAW_DATA=$BASE_PATH/raw_data
DECODED_DATA=$BASE_PATH/decoded_data
SEARCH_DATA=$BASE_PATH/search_data
DECODED_EP_LOGS=$DECODED_DATA/decoded-ep-logs.log

#Example usage information
function exampleUsage() {
    echo "Example Usage:"
    echo "      sh ep_decoder.sh"
    echo "        * Collect ALL EP logs, decode them and extract them to $DECODED_EP_LOGS"
    echo "      sh ep_decoder.sh -S 0000.0101.1101 -C 5"
    echo "        * OPTIMIZED: Only copy and process files containing 0000.0101.1101 plus/minus 5 lines"
    echo "        * Output to $RESULT_PATH/EPD_0000.0101.1101-C-25.log"
    echo "      sh ep_decoder.sh -S 10.1.1.111 -D 7"
    echo "        * OPTIMIZED: Only copy and process files from last 7 days containing 10.1.1.111"
    echo "        * Output to $RESULT_PATH/EPD_10.1.1.111-D-7.log"
    echo "      sh ep_decoder.sh -S 10.1.1.111 -D 7 -C 5"
    echo "        * OPTIMIZED: Only copy and process files from last 7 days containing 10.1.1.111 plus/minus 5 lines"
    echo "        * Output to $RESULT_PATH/EPD_10.1.1.111-C-5-D-7.log"
    echo "      sh ep_decoder.sh -S 10.1.1.111 -C 5 -D 7 -T true -P false -V true"
    echo "        * OPTIMIZED: Only copy and process files from last 7 days containing 10.1.1.111" 
    echo "        * Search decoded ep logs for 10.1.1.111 plus/minus 5 lines"  
    echo "        * Output to $RESULT_PATH/EPD_10.1.1.111-C-5-D-7.log"  
    echo "        * Tar the result to file to $RESULT_PATH/EPD_10.1.1.111-C-5-D-7.tgz "  
    echo "        * Keep the $BASE_PATH folder (no cleanup)"
    echo "        * Verbose information of the commands run on the leaf"
}

#Display Help
function display_help() {
    echo -e \\n"Help documentation for $0"\\n
    echo "Supported Options:"
    echo "S:    Search parameter - ALSO OPTIMIZES file selection"
cat << 'EOF'
            * IP = 10.1.1.111
            * MAC = 0000.0101.1101
            * Date 2026-01-01
When specified, only binary files containing this Search parameter will be copied and processed
EOF
    echo ""
    echo "C:    Context lines - will be used as egrep -C parameter (X lines before and after match)"
    echo "D:    Days - Only copy and process files from the last X days (optimized for performance)"
    echo "P:    Preserve files - Keep the source EPM/EPMC files on $BASE_PATH without the default cleanup (default: true - cleanup enabled)"
    echo "T:    Tar search result if there is one specific already define or Tar all to contents $SEARCH_DATA folder"
    echo "V:    Verbose result information with detail of commands been run on Leaf"
    echo "h:    Help"
    echo ""
    echo "Note: Search results are output directly to $RESULT_PATH/ folder and SORTED BY DATE"
    echo "      Default behavior is to cleanup temporary files unless -P false is specified"
    echo ""
    exampleUsage
    exit 0
}

#Used for logging with timestamp
function log() {
    ts=`date '+%Y-%m-%dT%H:%M:%S'`
    if [[ "$output" == "/dev/null" ]]; then
        echo "$ts $1" 1>>$output
    else
        echo "$ts $1"
    fi
}

#Used for logging with timestamp
function debug () {
    if [[ $DEBUG == "true" ]]; then
        log "Debug : $1" 
    fi
}

#Built epm/epmc directory files 
function built_epmc_directory_files() {
    log "$BASE_PATH does not exist or was purge, creating directories"
    mkdir -p $BASE_PATH $RAW_DATA $DECODED_DATA $SEARCH_DATA
}

#Check if file contains the endpoint - OPTIMIZATION FUNCTION
function file_contains_endpoint() {
    local file_path="$1"
    local endpoint="$2"
    
    if [[ -z "$endpoint" ]]; then
        return 0  # No endpoint specified, include all files
    fi
    
    debug "Checking if $file_path contains endpoint: $endpoint"
    
    # For compressed files, use zgrep; for uncompressed files, use grep
    if [[ "$file_path" == *.gz ]]; then
        # Check compressed file
        if zgrep -q "$endpoint" "$file_path" 2>/dev/null; then
            debug "MATCH: $file_path contains $endpoint"
            return 0
        else
            debug "NO MATCH: $file_path does not contain $endpoint"
            return 1
        fi
    else
        # Check uncompressed file
        if grep -q "$endpoint" "$file_path" 2>/dev/null; then
            debug "MATCH: $file_path contains $endpoint"
            return 0
        else
            debug "NO MATCH: $file_path does not contain $endpoint"
            return 1
        fi
    fi
}

#Copy epm/epmc files to raw_data - OPTIMIZED for endpoint and date range
function copy_ep_logs() {
    local files_copied=0
    local files_skipped_date=0
    local files_skipped_content=0
    local total_files_checked=0
    
    if [ ! -z "${EP}" ]; then
        log "OPTIMIZATION: Only copying files containing endpoint: $EP"
    fi
    
    if [ ! -z "${DAYS}" ]; then
        # Calculate cutoff timestamp for precise file filtering
        CUTOFF_TIMESTAMP=$(date -d "$DAYS days ago" '+%s')
        CUTOFF_DATE=$(date -d "$DAYS days ago" '+%Y-%m-%d')
        log "DATE FILTER: Only considering files from the last $DAYS days (since $CUTOFF_DATE)"
        debug "Cutoff timestamp: $CUTOFF_TIMESTAMP"
    fi
    
    # Copy current EPM/EPMC files with endpoint filtering
    if ls $EPM_LOGS/*epm* 1> /dev/null 2>&1; then
        log "Analyzing current EPM/EPMC files..."
        for file in $EPM_LOGS/*epm*; do
            if [[ -f "$file" ]]; then
                total_files_checked=$((total_files_checked + 1))
                
                # Check if file contains the endpoint (if specified)
                if [ ! -z "${EP}" ]; then
                    if ! file_contains_endpoint "$file" "$EP"; then
                        files_skipped_content=$((files_skipped_content + 1))
                        continue
                    fi
                fi
                
                # File passed endpoint check, copy it
                cp "$file" $RAW_DATA 2>/dev/null
                files_copied=$((files_copied + 1))
                debug "Copied current file: $(basename $file)"
            fi
        done
    fi
    
    # Process old directory files with date and endpoint filtering
    if ls $EPM_LOGS/old/*epm* 1> /dev/null 2>&1; then
        log "Analyzing historical EPM/EPMC files..."
        for file in $EPM_LOGS/old/*epm*; do
            if [[ -f "$file" ]]; then
                total_files_checked=$((total_files_checked + 1))
                
                # Check date filter first (if specified)
                if [ ! -z "${DAYS}" ]; then
                    file_timestamp=$(stat -c %Y "$file" 2>/dev/null)
                    if [[ -z "$file_timestamp" ]] || [[ "$file_timestamp" -lt "$CUTOFF_TIMESTAMP" ]]; then
                        files_skipped_date=$((files_skipped_date + 1))
                        if [[ $DEBUG == "true" ]]; then
                            file_date=$(date -d "@$file_timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
                            debug "Skipped old file: $(basename $file) (date: $file_date) - outside date range"
                        fi
                        continue
                    fi
                fi
                
                # Check if file contains the endpoint (if specified)
                if [ ! -z "${EP}" ]; then
                    if ! file_contains_endpoint "$file" "$EP"; then
                        files_skipped_content=$((files_skipped_content + 1))
                        continue
                    fi
                fi
                
                # File passed all checks, copy it
                cp "$file" $RAW_DATA 2>/dev/null
                files_copied=$((files_copied + 1))
                file_date=$(date -d "@$(stat -c %Y "$file")" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
                debug "Copied old file: $(basename $file) (date: $file_date)"
            fi
        done
    fi
    
    # Report optimization results
    log "OPTIMIZATION RESULTS:"
    log "  Total files checked: $total_files_checked"
    log "  Files copied: $files_copied"
    if [ ! -z "${DAYS}" ]; then
        log "  Files skipped (outside $DAYS day range): $files_skipped_date"
    fi
    if [ ! -z "${EP}" ]; then
        log "  Files skipped (no endpoint match for '$EP'): $files_skipped_content"
    fi
    
    # Calculate optimization percentage
    if [[ $total_files_checked -gt 0 ]]; then
        local optimization_percent=$(( (total_files_checked - files_copied) * 100 / total_files_checked ))
        log "  OPTIMIZATION: Avoided processing $optimization_percent% of files!"
    fi
    
    # Verify we have files to process
    if [[ $files_copied -eq 0 ]]; then
        if [ ! -z "${EP}" ]; then
            log "WARNING: No files found containing endpoint '$EP' within the specified criteria."
            log "         The endpoint may not exist in the logs or the date range may be too restrictive."
        else
            log "WARNING: No files found within the specified criteria."
        fi
        log "         You may need to adjust your search parameters."
    else
        log "READY: $files_copied optimized EPM/EPMC files ready for processing"
    fi
}

#Extract all epm/epmc files bigger than 1M - OPTIMIZED
function extract_ep_logs() {
    local file_count=$(find $RAW_DATA -name "*epm*vdc*" -size +1M 2>/dev/null | wc -l)
    
    if [[ $file_count -eq 0 ]]; then
        log "No compressed EPM/EPMC files larger than 1M found to extract"
        return
    fi
    
    log "Extract $file_count pre-filtered EPM/EPMC files bigger than 1M ..."
    
    for i in $(find $RAW_DATA -name "*epm*vdc*" -size +1M); do 
        debug "Extracting: $(basename $i)"
        gunzip -v -q $i 2>/dev/null
        if [[ $? -eq 0 ]]; then
            debug "Successfully extracted: $(basename $i)"
        else
            debug "Failed to extract or already extracted: $(basename $i)"
        fi
    done
    
    log "File extraction completed"
}

#Sort decoded logs by timestamp - FIXED FUNCTION for EPM log format
function sort_decoded_logs_by_date() {
    local input_file="$1"
    local temp_file="$input_file.temp_sort"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        debug "No file to sort or file is empty: $input_file"
        return
    fi
    
    log "Sorting decoded logs by timestamp (EPM format: sequence_number. YYYY-MM-DDTHH:MM:SS)..."
    debug "Sorting file: $input_file"
    
    # Sort by timestamp extracted from EPM log format
    # Format: "113709. 2025-12-03T11:22:15.763278000-05:00: ..."
    # Extract timestamp after the sequence number and dot
    awk '{
        # Look for pattern: number. YYYY-MM-DDTHH:MM:SS
        if (match($0, /^[0-9]+\. ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})/, arr)) {
            print arr[1] "|" $0
        } else if (match($0, /([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})/, arr)) {
            # Alternative pattern if no sequence number
            print arr[1] "|" $0
        } else {
            # Lines without recognizable timestamp - sort at end
            print "9999-99-99T99:99:99|" $0
        }
    }' "$input_file" | sort -t'|' -k1,1 | cut -d'|' -f2- > "$temp_file"
    
    if [[ $? -eq 0 ]] && [[ -s "$temp_file" ]]; then
        mv "$temp_file" "$input_file"
        log "Logs successfully sorted by timestamp"
        debug "Sorting completed for: $input_file"
    else
        log "Warning: Could not sort logs, keeping original order"
        rm -f "$temp_file" 2>/dev/null
    fi
}

#Decode all the files bigger than 1M and extract them - OPTIMIZED with sorting
function decode_ep_logs() {
    search_ep_file_delete $DECODED_EP_LOGS
    
    # Count files to be processed
    local vdc_files=$(find $RAW_DATA -name "*epm*vdc*" -size +1M 2>/dev/null | wc -l)
    local trace_files=$(find $RAW_DATA -name "*epm*-trace.txt*" 2>/dev/null | wc -l)
    local total_files=$((vdc_files + trace_files))
    
    if [[ $total_files -eq 0 ]]; then
        log "No EPM/EPMC files found to decode"
        return
    fi
    
    if [ ! -z "${EP}" ]; then
        log "OPTIMIZED DECODE: Processing $total_files pre-filtered EPM/EPMC files (containing '$EP') to $DECODED_EP_LOGS"
    elif [ ! -z "${DAYS}" ]; then
        log "OPTIMIZED DECODE: Processing $total_files EPM/EPMC files from the last $DAYS days to $DECODED_EP_LOGS"
    else
        log "Decoding $total_files EPM/EPMC files and extract them to $DECODED_EP_LOGS"
    fi
    
    local processed_files=0
    
    # Process binary VDC files
    for i in $(find $RAW_DATA -name "*epm*vdc*" -size +1M); do
        debug "Decoding binary file: $(basename $i)"
        nxos_binlog_decode "$i" >> $DECODED_EP_LOGS 2>/dev/null
        if [[ $? -eq 0 ]]; then
            processed_files=$((processed_files + 1))
            debug "Successfully decoded: $(basename $i)"
        else
            debug "Failed to decode: $(basename $i)"
        fi
    done
    
    # Process trace text files
    for i in $(find $RAW_DATA -name "*epm*-trace.txt*"); do
        debug "Processing trace file: $(basename $i)"
        cat "$i" >> $DECODED_EP_LOGS 2>/dev/null
        if [[ $? -eq 0 ]]; then
            processed_files=$((processed_files + 1))
            debug "Successfully processed: $(basename $i)"
        else
            debug "Failed to process: $(basename $i)"
        fi
    done
    
    log "DECODE RESULTS: Successfully processed $processed_files out of $total_files pre-filtered files"
    
    # Check if we have decoded content and sort it
    if [[ -f "$DECODED_EP_LOGS" ]] && [[ -s "$DECODED_EP_LOGS" ]]; then
        local line_count=$(wc -l < "$DECODED_EP_LOGS")
        log "Generated decoded log with $line_count lines"
        
        # Sort the decoded logs by timestamp
        sort_decoded_logs_by_date "$DECODED_EP_LOGS"
        
        if [[ $PRESERVE != "false" ]]; then
            log "You can check the sorted results at 'less $DECODED_EP_LOGS'"
        fi
    else
        log "WARNING: No decoded content was generated. Check if files contain valid data."
    fi
    
    # Clean up raw data
    folder_delete $RAW_DATA
}

#Delete EP file
function search_ep_file_delete() {
    if [ -f $1 ]; then
        debug "Delete EP file $1"
        rm -rf $1
    fi
}

#Delete Folder
function folder_delete() {
    if [ -d $1 ]; then
        debug "Delete Folder $1"
        rm -rf $1
    fi
}

#Sort search results by timestamp - FIXED FUNCTION for EPM log format
function sort_search_results_by_date() {
    local search_file="$1"
    local temp_file="$search_file.temp_sort"
    
    if [[ ! -f "$search_file" ]] || [[ ! -s "$search_file" ]]; then
        return
    fi
    
    log "Sorting search results by timestamp (EPM format)..."
    debug "Sorting search results: $search_file"
    
    # Sort by timestamp extracted from EPM log format
    awk '{
        # Look for pattern: number. YYYY-MM-DDTHH:MM:SS
        if (match($0, /^[0-9]+\. ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})/, arr)) {
            print arr[1] "|" $0
        } else if (match($0, /([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})/, arr)) {
            # Alternative pattern if no sequence number
            print arr[1] "|" $0
        } else {
            # Lines without recognizable timestamp - sort at end
            print "9999-99-99T99:99:99|" $0
        }
    }' "$search_file" | sort -t'|' -k1,1 | cut -d'|' -f2- > "$temp_file"
    
    if [[ $? -eq 0 ]] && [[ -s "$temp_file" ]]; then
        mv "$temp_file" "$search_file"
        log "Search results successfully sorted by timestamp"
        debug "Search result sorting completed for: $search_file"
    else
        log "Warning: Could not sort search results, keeping original order"
        rm -f "$temp_file" 2>/dev/null
    fi
}

#Search ep logs result - MODIFIED to output to RESULT_PATH with sorting and EPD_ prefix
function search_result_check() {
    local search_file="$RESULT_PATH/EPD_$1.log"
    debug "Search ep logs result for $search_file"
    if [ ! -s "$search_file" ]; then 
        log "No result for the provided search parameters removing empty file EPD_$1"
        rm -rf "$search_file"
    else 
        # Sort the search results by date
        sort_search_results_by_date "$search_file"
        
        SEARCH_RESULT="EPD_$1"
        local match_count=$(wc -l < "$search_file")
        log "Search completed: Found $match_count matching lines (sorted by date)"
        log "********************************************************************"        
        log "Logs saved and available for SCP or SFTP download from:"        
        log "less $search_file"
        log "********************************************************************"
        chmod 644 "$search_file"
        log "To remove files when done run"
        log "rm -f $search_file"
    fi
}

#Search decoded ep logs - MODIFIED to output directly to RESULT_PATH with EPD_ prefix
function search_ep() {
    local filename="$EP"
    if [ ! -z "${DAYS}" ]; then
        filename="$EP-D-$DAYS"
    fi
    
    local output_file="$RESULT_PATH/EPD_$filename.log"
    search_ep_file_delete "$output_file"
    debug "egrep $EP $DECODED_EP_LOGS >> $output_file"
    log "CREATING FILE : $output_file"
    egrep "$EP" "$DECODED_EP_LOGS" >> "$output_file" 2>/dev/null
    search_result_check $filename
}

#Search ep context - MODIFIED for EPM format with context preservation and EPD_ prefix
function search_ep_context() {
    local filename="$EP-C-$CONTEXT"
    if [ ! -z "${DAYS}" ]; then
        filename="$EP-C-$CONTEXT-D-$DAYS"
    fi
    
    local output_file="$RESULT_PATH/EPD_$filename.log"
    local temp_file="$output_file.temp"
    
    search_ep_file_delete "$output_file"
    debug "egrep -B $CONTEXT -A $CONTEXT $EP $DECODED_EP_LOGS >> $temp_file"
    log "CREATING FILE : $output_file"
    
    # First create temp file with context lines
    egrep -B "$CONTEXT" -A "$CONTEXT" "$EP" "$DECODED_EP_LOGS" >> "$temp_file" 2>/dev/null
    
    # Process the temp file to maintain context while sorting by match timestamps
    if [[ -f "$temp_file" ]] && [[ -s "$temp_file" ]]; then
        log "Processing context lines and sorting by match timestamps (EPM format)..."
        
        # Enhanced AWK script for EPM log format with context grouping
        awk -v search_term="$EP" -v context="$CONTEXT" '
        BEGIN { 
            group_num = 0 
            in_group = 0
            context_before = 0
            context_after = 0
        }
        /^--$/ { 
            if (in_group) {
                group_num++
                in_group = 0
                context_before = 0
                context_after = 0
            }
            next 
        }
        {
            # Check if this line contains our search term
            line_matches = (match($0, search_term) > 0)
            
            # Extract timestamp from EPM format: "number. YYYY-MM-DDTHH:MM:SS"
            timestamp = "9999-99-99T99:99:99"
            if (match($0, /^[0-9]+\. ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})/, arr)) {
                timestamp = arr[1]
            } else if (match($0, /([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})/, arr)) {
                timestamp = arr[1]
            }
            
            if (line_matches) {
                if (!in_group) {
                    group_num++
                    in_group = 1
                }
                match_timestamp = timestamp
                context_after = context
                printf "%s|%06d|%03d|%s\n", timestamp, group_num, 500, $0
            } else {
                # Context line
                if (in_group) {
                    # After context
                    if (context_after > 0) {
                        printf "%s|%06d|%03d|%s\n", match_timestamp, group_num, (500 + (context - context_after + 1)), $0
                        context_after--
                        if (context_after == 0) {
                            in_group = 0
                        }
                    }
                } else {
                    # This might be before context for next match - store it temporarily
                    if (group_num > 0) {
                        # Associate with previous group as after-context
                        printf "%s|%06d|%03d|%s\n", timestamp, group_num, (500 + context + 10), $0
                    } else {
                        # First lines before any match
                        printf "%s|%06d|%03d|%s\n", timestamp, group_num + 1, (500 - context), $0
                    }
                }
            }
        }
        ' "$temp_file" | sort -t'|' -k1,1 -k2,2n -k3,3n | cut -d'|' -f4- > "$output_file"
        
        rm -f "$temp_file"
    fi
    
    search_result_check $filename
}

#Search decoded ep logs 
function search() {
    # Verify decoded logs exist before searching
    if [[ ! -f "$DECODED_EP_LOGS" ]] || [[ ! -s "$DECODED_EP_LOGS" ]]; then
        log "ERROR: No decoded logs found to search. Decoded log file is empty or missing."
        return
    fi
    
    if [ ! -z "${EP}" ]; then
        log "Search optimized decoded ep logs for $EP"
        if [ ! -z "${DAYS}" ]; then
            log "(from pre-filtered files in last $DAYS days only)"
        fi
    else
        log "Search decoded ep logs for $EP"
    fi
    
    if [ ! -z "${CONTEXT}"  ]; then
        debug "search_ep_context"        
        search_ep_context
    else 
        debug "search_ep"
        search_ep
    fi
}

#Tar file - MODIFIED to work with new output location and EPD_ prefix
function tar_file() {
    log "Compressing files..."
    if [[ ! -z "${SEARCH_RESULT}" ]]; then
        local search_file="$RESULT_PATH/$SEARCH_RESULT.log"
        if [[ -f "$search_file" ]]; then
            tar --force-local -zcf $RESULT_PATH/$SEARCH_RESULT.tgz "$search_file" 2>/dev/null
            chmod 644 $RESULT_PATH/$SEARCH_RESULT.tgz
            log "Compression completed - Logs available for SCP or SFTP download from $RESULT_PATH/$SEARCH_RESULT.tgz"
        else
            log "ERROR: Search result file not found for compression: $search_file"
        fi
    else 
        tar --force-local -zcf $RESULT_PATH/decoded_data.log.tgz $DECODED_DATA 2>/dev/null
        chmod 644 $RESULT_PATH/decoded_data.log.tgz
        log "Compression completed - Logs available for SCP or SFTP download from $RESULT_PATH/decoded_data.log.tgz"   
    fi
}

# Check current available space at $RESULT_PATH is at least or equal to 3 GB
function checkAvailableSpace() {
    debug "Check current available space at $RESULT_PATH is at least or equal to 3 GB"
    SIZE=$(df -h $RESULT_PATH | grep data | awk '{print $4}')
    SIZEFloat=${SIZE::-1}
    SIZEInt=${SIZEFloat%.*}

    if [ ! $SIZEInt -ge 3 ]; then
        log "Current available space at $RESULT_PATH is NOT Greater than or equal to 3 GB \n please clean up space and retry running the script"
        exit 1
    fi  
}

#Force Data Collection - OPTIMIZED
function forceDataCollection() {
    debug "Force Data Collection - Optimized"
    folder_delete $BASE_PATH
    built_epmc_directory_files   
    copy_ep_logs      # Now optimized for endpoint content and date range
    extract_ep_logs   # Now processes fewer, pre-filtered files
    decode_ep_logs    # Now processes fewer, pre-filtered files with sorting
}

#Default cleanup function
function default_cleanup() {
    if [[ $PRESERVE != "false" ]]; then
        log "Performing default cleanup of temporary files"
        if [[ ! -z "${SEARCH_RESULT}" ]]; then
            # Keep search result, it's already in RESULT_PATH
            debug "Search result already saved to $RESULT_PATH/$SEARCH_RESULT.log"
        else 
            # Copy decoded logs to RESULT_PATH if no search was performed
            if [[ -f "$DECODED_EP_LOGS" ]] && [[ -s "$DECODED_EP_LOGS" ]]; then
                cp "$DECODED_EP_LOGS" "$RESULT_PATH/EPD_decoded-ep-logs.log" 2>/dev/null
                chmod 644 "$RESULT_PATH/EPD_decoded-ep-logs.log"
                log "Copied sorted decoded logs to $RESULT_PATH/EPD_decoded-ep-logs.log"
            fi
        fi
        folder_delete $BASE_PATH
        log "Cleanup completed - temporary files removed"
    else
        log "Cleanup disabled - temporary files preserved in $BASE_PATH"
        if [[ ! -z "${SEARCH_RESULT}" ]]; then
            log "Search result available at: $RESULT_PATH/$SEARCH_RESULT.log"
        fi
        log "You can also check decoded logs at: $DECODED_EP_LOGS"
    fi
}

#Take Args from Customer input
optspec="S:C:D:P:T:V:h"
while getopts "$optspec" optchar; do
  case $optchar in
    S)
        EP=$OPTARG
        ;;
    C)
        CONTEXT=$OPTARG
        ;;
    D)
        DAYS=$OPTARG
        # Validate days parameter
        if ! [[ "$DAYS" =~ ^[0-9]+$ ]] || [[ "$DAYS" -le 0 ]]; then
            echo "Error: -D parameter must be a positive integer" >&2
            exit 1
        fi
        ;;
    P)
        PRESERVE=$OPTARG
        ;;
    T)
        TAR=$OPTARG
        ;; 
    V)
        DEBUG=$OPTARG
        ;;
    h)
        display_help
        exit 0
        ;;        
    :)
        echo "Option $OPTARG requires an argument." >&2
        exit 1
        ;;
    \?)
        echo "Invalid option: \"-$OPTARG\"" >&2
        exit 1
        ;;
  esac
done

# Check current available space at $RESULT_PATH is at least or equal to 3 GB
checkAvailableSpace

# Always force data collection (now optimized)
debug "forceDataCollection TRUE (optimized behavior)"
forceDataCollection

#Search for existing EP
if [ ! -z "${EP}"  ]; then 
    search
fi

#tar file
if [ ! -z "${TAR}"  ]; then 
    if [[ $TAR == "true" ]]; then
        tar_file
    fi
fi
 
#Default cleanup (unless -P false is specified)
default_cleanup