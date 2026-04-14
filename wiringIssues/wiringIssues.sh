#!/bin/bash
#*********************************************************************************************************************
#author aahacket
#
#This script checks APIC wiring-issues for an APIC that will not join the cluster
#*********************************************************************************************************************

# --- Global Variables / Constants ---
# Define ANSI color codes for better output readability
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly NC='\033[0m' # No Color

# Initialize overall status variables for summary report
overall_status_pod_id="PASSED"
overall_status_fabric_name="PASSED"
overall_status_uuid="PASSED"
overall_status_infra_vlan_match="PASSED"
overall_status_wiring_mismatch="PASSED"
overall_status_unapproved_sn="PASSED"
overall_status_infra_vlan_in_use="PASSED"
overall_status_fabric_mode="PASSED"
overall_status_ssl_cert="PASSED"
overall_status_ca_cert="PASSED"
overall_status_ucs_pid="PASSED"
overall_status_target_mb_sn="PASSED"
overall_status_leaf_cert="PASSED"

# NOTE: The script populates shared arrays (nodeIdNumber, nodeOobMgmt, leafInfo,
# wiringIssues, etc.) across gather/connect/print stages and reuses them in checks.

# --- Main Function ---
function main() {
    # Define output directory and filenames
    local output_dir="/data/techsupport"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="${output_dir}/apic_wiring_report_${timestamp}.log"
    local debug_file="${output_dir}/apic_wiring_debug_${timestamp}.log"

    # Ensure output directory exists
    if [[ ! -d "$output_dir" ]]; then
        mkdir -p "$output_dir" || { echo -e "${RED}Error: Could not create output directory $output_dir. Exiting.${NC}" >&2; exit 1; }
    fi

    # --- Step 1: Gather login info BEFORE redirecting stderr ---
    # This ensures prompts and error messages from loginInfo are visible on the terminal.
    loginInfo

    # --- Step 2: Redirect stderr for debug output ONLY to file ---
    # This happens AFTER loginInfo, so its prompts are visible.
    # The 'tee' command's stdout is redirected to /dev/null to prevent it from printing to the terminal.
    exec 2> >(tee "$debug_file" >/dev/null)

    # Enable debug tracing (set -x)
    set -x

    # --- Step 3: Wrap the main script execution for report file and terminal output ---
    # All subsequent stdout will be piped to tee, which writes to report_file and original stdout.
    # The curly braces create a command group whose stdout can be redirected.
    {
    display_check_header "Operations You Must Avoid"
    echo "These are operations that must be avoided, as they will make the clustering issue worse, and potentially unrecoverable."
    echo ""
    echo -e "${RED}Operations You Must Avoid When Cluster is Diverged${NC}"
    echo "1. Disrupt a healthy/fully-fit APIC to recover an unhealthy APIC"
    echo "2. Clean or Regular reload more than 1 APIC at a time"
    echo "3. Decommission more than 1 APIC at a time"
    echo ""
    echo -e "${RED}Operations You Must Avoid During an Upgrade/Downgrade${NC}"
    echo "1. Don't reload any APIC in the cluster."
    echo "2. Don't decommission any APIC in the cluster."
    echo "3. Don't change the firmware target version back to the original version."
    echo ""

    display_check_header "Starting Information Gathering"

        gatherApicInfo # Gathers APIC-specific information first

        gatherLldpInfo # Gathers LLDP information, relying on lldpApicIdGrep from gatherApicInfo

        connectToLeaf # Connects to identified leaves to gather more data

        printLldpInfo # Prints information gathered from LLDP

        printWiringIssue # Populates wiringIssues array used by other checks

        display_check_header "Starting APIC Wiring Checks"
        podIdMismatch
        fabricDomainMismatch
        ctrlrUuidMismatch
        infraVlanMismatch
        wiringMismatch
        unapprovedSN

        # Contains all checks for unapproved-ctrlr condition
        unapprovedControllerCheck

        # --- Summary of All Checks ---
        display_check_header "Summary of All Checks"
        printf "Pod ID Match:                                                             %b%s%b\n" "$(get_color "$overall_status_pod_id")" "$overall_status_pod_id" "$NC"
        printf "Fabric Name Match:                                                        %b%s%b\n" "$(get_color "$overall_status_fabric_name")" "$overall_status_fabric_name" "$NC"
        printf "Controller UUID Match:                                                    %b%s%b\n" "$(get_color "$overall_status_uuid")" "$overall_status_uuid" "$NC"
        printf "Infra VLAN Match:                                                         %b%s%b\n" "$(get_color "$overall_status_infra_vlan_match")" "$overall_status_infra_vlan_match" "$NC"
        printf "Wiring Mismatch:                                                          %b%s%b\n" "$(get_color "$overall_status_wiring_mismatch")" "$overall_status_wiring_mismatch" "$NC"
        printf "Unapproved Serial Number:                                                 %b%s%b\n" "$(get_color "$overall_status_unapproved_sn")" "$overall_status_unapproved_sn" "$NC"
        printf "Fabric Mode Check:                                                        %b%s%b\n" "$(get_color "$overall_status_fabric_mode")" "$overall_status_fabric_mode" "$NC"
        printf "SSL Certificate Date Check:                                               %b%s%b\n" "$(get_color "$overall_status_ssl_cert")" "$overall_status_ssl_cert" "$NC"
        printf "Missing CA Certificate Check:                                             %b%s%b\n" "$(get_color "$overall_status_ca_cert")" "$overall_status_ca_cert" "$NC"
        printf "UCS PID of APIC SN Check:                                                 %b%s%b\n" "$(get_color "$overall_status_ucs_pid")" "$overall_status_ucs_pid" "$NC"
        printf "Infra VLAN Deployed as EPG:                                               %b%s%b\n" "$(get_color "$overall_status_infra_vlan_in_use")" "$overall_status_infra_vlan_in_use" "$NC"
        printf "targetMbSn Check:                                                         %b%s%b\n" "$(get_color "$overall_status_target_mb_sn")" "$overall_status_target_mb_sn" "$NC"
        printf "Leaf SSL Certificate Date Check:                                          %b%s%b\n" "$(get_color "$overall_status_leaf_cert")" "$overall_status_leaf_cert" "$NC"

    } | tee "$report_file" # Redirect stdout of the block to report_file AND to original stdout (terminal)

    # Disable debug tracing
    set +x
    
    # Final messages about file locations
    display_check_header "Report and Debug File Locations"
    echo "Report saved to: ${report_file}"
    echo "Debug log saved to: ${debug_file}"
}

# --- Helper Function for Colors ---
# Assigns a color based on the status string
function get_color() {
    local status="$1"
    if [[ "$status" == "PASSED" ]]; then
        echo "$GREEN"
    elif [[ "$status" == "FAILED" ]]; then
        echo "$RED"
    elif [[ "$status" == "MANUAL CHECK REQUIRED" || "$status" == "SKIPPED" ]]; then
        echo "$YELLOW"
    else
        echo "$NC" # Default to no color
    fi
}

#Displays header for each section
function display_check_header() {
    local check_description="$1" # Assigns the first argument to a local variable

    echo "================================================================================"
    echo "${check_description}"
    echo "================================================================================"
}

# --- IP Address Validation ---
function is_valid_ip() {
    local ip="$1"
    if [[ -z "$ip" ]]; then
        return 1
    fi

    # IPv4
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets
        read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi

    # IPv6 (basic validation for hex groups and :: compression)
    if [[ "$ip" =~ ^([0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{0,4}$ || "$ip" =~ ^([0-9A-Fa-f]{1,4}:){1,7}:$ || "$ip" =~ ^:([0-9A-Fa-f]{1,4}:){1,7}$ || "$ip" =~ ^::$ ]]; then
        return 0
    fi

    return 1
}

# --- Unapproved Controller Checks Group ---
function unapprovedControllerCheck() {
    fabricStrictMode
    sslCertDate
    caCertPresent
    ucsPid
    infraVlanInUse
    targetMbSn
    leafCertDate
}

# --- Login Information ---
function loginInfo() {
    display_check_header "Leaf Login Information"
    # Prompt for username
    read -p "Enter your username: " username
    if [[ -z "$username" ]]; then
        echo -e "${RED}Error: Username cannot be empty. Exiting.${NC}" >&2 # This goes to current stderr (terminal)
        exit 1
    fi

    # Prompt for password, -s hides input, -p provides prompt
    read -sp "Enter your password: " password
    printf '\n' # Add a newline after password input
    if [[ -z "$password" ]]; then
        echo -e "${RED}Error: Password cannot be empty. Exiting.${NC}" >&2 # This goes to current stderr (terminal)
        exit 1
    fi
}

# --- Gather LLDP Information ---
function gatherLldpInfo() {
    printf "Gathering LLDP Information... "

    # Read bond0 interface information. Redirect stderr to /dev/null to suppress errors.
    local stringBond0info=$(cat /proc/net/bonding/bond0 2>/dev/null)
    if [[ -z "$stringBond0info" ]]; then
        printf "${RED}FAILED${NC}\n"
        echo -e "${RED}Error: Could not read /proc/net/bonding/bond0. Is this script running on an APIC? Exiting.${NC}" >&2
        exit 1
    fi

    # Extract physical interfaces (e.g., eth0, eth1) from bond0.
    # Using grep -oE for extended regex and more precise matching.
    local stringFabricInterfaces=$(echo "$stringBond0info" | grep -E 'Interface: eth' | grep -oE 'eth[0-9].[0-9]')
    if [[ -z "$stringFabricInterfaces" ]]; then
        printf "${YELLOW}WARNING${NC}\n"
        echo -e "${YELLOW}Warning: No fabric interfaces found in bond0. LLDP checks may be incomplete.${NC}"
        # arrayFabricInterfaces will be empty, causing loops to not run, which is acceptable.
    fi
    arrayFabricInterfaces=($stringFabricInterfaces)

    # lldpApicIdGrep is a global variable set in gatherApicInfo, which is called before this function.

    # Loop through each fabric interface to gather LLDP data
    for i in "${!arrayFabricInterfaces[@]}"; do
        local interface="${arrayFabricInterfaces[i]}"
        
        # Pull LLDP for each interface (inbound and outbound). Suppress errors.
        stringLldpIn[i]=$(acidiag run lldptool in "$interface" 2>/dev/null)
        stringLldpOut[i]=$(acidiag run lldptool out "$interface" 2>/dev/null)

        if [[ -z "${stringLldpIn[i]}" && -z "${stringLldpOut[i]}" ]]; then
            echo -e "${YELLOW}Warning: No LLDP information received for interface $interface. Skipping LLDP parsing for this interface.${NC}"
            continue # Skip to next interface if no LLDP data
        fi

        # Extract information using more robust parsing methods (awk, specific grep patterns, sed -nE).
        # `tr -d '\n'` is used to remove trailing newlines that can interfere with comparisons.
        nodeIdNumber[i]=$(echo "${stringLldpIn[i]}" | grep -E -A 1 'Node ID' | grep -Eo '[0-9].*[0-9]')
    # Management Address parsing attempts to handle IPv4/IPv6, but may capture malformed values.
    nodeOobMgmt[i]=$(echo "${stringLldpIn[i]}" | grep -E -A 1 'Management Address' | grep -Eo ':.*[0-9].*[0-9]' | grep -Eo '[0-9].*[0-9]')
        leafLocalInterface[i]=$(echo "${stringLldpIn[i]}" | grep -E 'pathep' | grep -Eo  '\[.*\]' | sed 's/\[//g' | sed 's/\]//g' )
        
        podIdLeaf[i]=$(echo "${stringLldpIn[i]}" | grep -A 1 'POD ID' | tail -n 1 | tr -d '\n')
        podIdApic[i]=$(echo "${stringLldpOut[i]}" | grep -A 1 'POD ID' | tail -n 1 | tr -d '\n')

        fabricNameLeaf[i]=$(echo "${stringLldpIn[i]}" | grep -A 1 'Fabric Name' | tail -n 1 | tr -d '\n')
        fabricNameApic[i]=$(echo "${stringLldpOut[i]}" | grep -A 1 'Fabric Name' | tail -n 1 | tr -d '\n')

        infraVlanLeaf[i]=$(echo "${stringLldpIn[i]}" | grep -A 1 'Infra VLAN' | tail -n 1 | tr -d '\n')
        infraVlanApic[i]=$(echo "${stringLldpOut[i]}" | grep -A 1 'Infra VLAN' | tail -n 1 | tr -d '\n')

        # Use the global lldpApicIdGrep for UUID extraction
        uuidLeaf[i]=$(echo "${stringLldpIn[i]}" | grep -E "$lldpApicIdGrep" -A 2 | grep 'UUID:' | sed 's/.*UUID: //g' | tr -d '\n')
        uuidApic[i]=$(echo "${stringLldpOut[i]}" | grep -E 'Appliance Vector TLV' -A 3 | grep 'UUID:' | sed 's/.*UUID: //g' | tr -d '\n')
    done
    printf "${GREEN}DONE${NC}\n"
}

# --- Print LLDP Information ---
function printLldpInfo() {
    display_check_header "Incoming LLDP Info"
    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found or LLDP information gathered."
        return
    fi
    for i in "${!arrayFabricInterfaces[@]}"; do
        echo "Interface: ${arrayFabricInterfaces[i]}"
        # Use parameter expansion ${var:-default_value} to show N/A if variable is empty
        echo "Node ID Number: ${nodeIdNumber[i]:-N/A}"
        echo "Out-of-Band Management IP: ${nodeOobMgmt[i]:-N/A}"
        echo "APIC-Connected Leaf Interface: ${leafLocalInterface[i]:-N/A}"
        echo ""
    done
}

# --- Connect to Leaf ---
function connectToLeaf() {
    if [[ ${#nodeIdNumber[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No leaf nodes identified via LLDP to connect to. Skipping leaf connection.${NC}"
        return
    fi

    for i in "${!nodeIdNumber[@]}"; do
        local ip="${nodeOobMgmt[i]}"
        local localInterface="${leafLocalInterface[i]}"
        local nodeId="${nodeIdNumber[i]}"

        # Skip connection if essential LLDP information is missing for this leaf
        if [[ -z "$ip" || -z "$localInterface" || -z "$nodeId" ]]; then
            printf "${YELLOW}Skipping connection to leaf for interface %s due to missing LLDP info (IP/Interface/Node ID).${NC}\n" "${arrayFabricInterfaces[i]:-N/A}"
            leafInfo[i]="" # Ensure array element is empty if we skip
            continue
        fi

        # Validate IP address; prompt for manual entry if LLDP reported a MAC or invalid value
        if ! is_valid_ip "$ip"; then
            # Manual entry is only used when LLDP reported a non-IP (e.g., MAC) or invalid address.
            echo -e "${YELLOW}Warning: Leaf ${nodeId} reported invalid management address '${ip}'.${NC}"
            read -p "Enter a valid IPv4/IPv6 address for Leaf ${nodeId} (or leave blank to skip): " manualIp
            if [[ -z "$manualIp" ]]; then
                printf "${YELLOW}Skipping connection to leaf %s due to invalid IP.${NC}\n" "$nodeId"
                leafInfo[i]=""
                continue
            fi
            if ! is_valid_ip "$manualIp"; then
                printf "${YELLOW}Skipping connection to leaf %s due to invalid manual IP entry.${NC}\n" "$nodeId"
                leafInfo[i]=""
                continue
            fi
            ip="$manualIp"
        fi

        printf "Connecting to Leaf %s (%s)... " "$nodeId" "$ip"

        # Modify interface name for /mit/sys/lldp/inst/if- path
        local modifiedLeafLocalInterface=$(echo "$localInterface" | sed 's/\//--/g')
        
        # Define commands to run on the remote leaf.
        # Corrected moquery syntax: sys/phys-[interface_name]
        # Added 'exit' to ensure the ssh session closes cleanly.
        local commands=$(echo "
                        cat /mit/sys/lldp/inst/if-[$modifiedLeafLocalInterface]/summary;
                        show vlan extended;
                        moquery -d sys/phys-[$localInterface];
                        moquery -c pkiFabricNodeSSLCertificate;
                        date
                        ")
        
        # Connects to the adjacent leaf using sshpass.
        # WARNING: sshpass is insecure for production environments. Consider using SSH keys for passwordless access.
        # Added -o ConnectTimeout and -o BatchMode for robustness.
        # -o StrictHostKeyChecking=no is used for automation, but implies security risk if not managed.

        #Turning off debugging so we do not get the user password stored
        set +x
        local tempLeafInfo=$(sshpass -p "$password" ssh -o StrictHostKeyChecking=no -q "$username@$ip" "$commands" 2>&1)
        local ssh_exit_status=$?
        #resume debugging
        set -x

        if [[ $ssh_exit_status -ne 0 ]]; then
            printf "${RED}FAILED${NC}\n"
            echo -e "${RED}Error: Failed to connect to Leaf %s (%s). SSH exit status: %d. Output: %s${NC}" "$nodeId" "$ip" "$ssh_exit_status" "$tempLeafInfo" >&2
            leafInfo[i]="" # Store empty string to indicate failure for this leaf
        else
            leafInfo[i]="$tempLeafInfo" # Store successful output
            printf "${GREEN}DONE${NC}\n"
        fi
    done
}

# --- Print Wiring Issue ---
function printWiringIssue() {
    display_check_header "Reported Wiring Issues"
    
    if [[ ${#nodeIdNumber[@]} -eq 0 ]]; then
        echo "No leaf nodes identified to check wiring issues."
        return
    fi

    for i in "${!nodeIdNumber[@]}"; do
        local nodeId="${nodeIdNumber[i]:-N/A}"
        if [[ -z "${leafInfo[i]}" ]]; then
            echo "Node ID Number: $nodeId"
            # Distinguish LLDP absence from SSH failure to improve troubleshooting guidance.
            if [[ -z "${stringLldpIn[i]}" && -z "${stringLldpOut[i]}" ]]; then
                echo -e "Wiring Issue: ${RED}Could not retrieve information (LLDP data missing).${NC}"
            else
                echo -e "Wiring Issue: ${RED}Could not retrieve information (SSH connection failed).${NC}"
            fi
            echo ""
            wiringIssues[i]="" # Ensure this is empty for failed connections
            continue
        fi

        # Use more precise grep for 'wiringIssues:' and remove newline
        wiringIssues[i]=$(echo "${leafInfo[i]}" | grep -E 'wiringIssues' | awk '{print $3}' | tr -d '\n')
        
        echo "Node ID Number: $nodeId"
        if [[ -z "${wiringIssues[i]}" ]]; then
            echo -e "Wiring Issue: ${GREEN}No Issue Reported${NC}"
        else
            echo -e "Wiring Issue: ${RED}${wiringIssues[i]}${NC}"
        fi
        echo ""
    done
}

# --- Gather APIC Information ---
function gatherApicInfo() {
    printf "Gathering APIC Information... "

    # Execute 'acidiag avread' and store output. Handle potential failure.
    acidiagAvread=$(acidiag avread 2>/dev/null)
    if [[ -z "$acidiagAvread" ]]; then
        printf "${RED}FAILED${NC}\n"
        echo -e "${RED}Error: 'acidiag avread' command failed or returned no output. Exiting.${NC}" >&2
        exit 1
    fi

    # Extract local APIC ID Number using awk for robustness.
    apicLocalNodeId=$(echo "$acidiagAvread" | awk -F'[ =]' '/Local appliance ID=/ {print $4}' | tr -d '\n')
    if [[ -z "$apicLocalNodeId" ]]; then
        printf "${RED}FAILED${NC}\n"
        echo -e "${RED}Error: Could not determine local APIC ID from 'acidiag avread'. Exiting.${NC}" >&2
        exit 1
    fi

    # Define lldpApicIdGrep globally for use in gatherLldpInfo.
    lldpApicIdGrep=$(echo "Id: ${apicLocalNodeId}")

    #
    acidiagApicIdGrep=$(echo "appliance id=${apicLocalNodeId}")

    # Gather other APIC-related files/commands. Handle warnings for non-critical failures.
    samlog=$(cat /data/data_admin/sam_exported.config 2>/dev/null)
    if [[ -z "$samlog" ]]; then
        echo -e "${YELLOW}Warning: Could not read /data/data_admin/sam_exported.config. Some checks may be affected.${NC}"
    fi

    avreada=$(avread -a 2>/dev/null)
    if [[ -z "$avreada" ]]; then
        echo -e "${YELLOW}Warning: 'avread -a' command failed or returned no output. Some checks may be affected.${NC}"
    fi

    # Get current APIC date in a standardized format for easier comparison.
    apicDate=$(date 2>/dev/null)
    if [[ -z "$apicDate" ]]; then
        printf "${RED}FAILED${NC}\n"
        echo -e "${RED}Error: Could not get current APIC date.${NC}" >&2
    fi

    verifyApic=$(acidiag verifyapic 2>/dev/null)
    if [[ -z "$verifyApic" ]]; then
        echo -e "${YELLOW}Warning: 'acidiag verifyapic' command failed or returned no output. Some checks may be affected.${NC}"
    fi

    # Extract APIC Serial Number. This parsing is still complex but improved for direct extraction.
    apicSn=$(echo "$acidiagAvread" | grep -E "$acidiagApicIdGrep" | grep -Eo 'cntrlSbst.*target' | awk '{print $2}' | sed 's/)//g')
    
    if [[ -z "$apicSn" ]]; then
        echo -e "${YELLOW}Warning: Could not determine APIC Serial Number. Some checks may be affected.${NC}"
    fi

    printf "${GREEN}DONE${NC}\n"
}

# --- Fabric Strict Mode Check ---
function fabricStrictMode() {
    local check_status="PASSED"
    # Extract fabricMode using grep -Eo and awk for robustness
    local fabricMode=$(echo "$avreada" | grep -Eo 'discoveryMode\s+(\S+)' | awk '{print $2}' | tr -d '\n')
    local strict_mode_value="STRICT"
    local unapproved_ctrlr_found="false"

    for issue in "${wiringIssues[@]}"; do
        if [[ -n "$issue" && "$issue" == *"unapproved-ctrlr"* ]]; then
            unapproved_ctrlr_found="true"
            break
        fi
    done

    display_check_header "Check 7: Fabric Mode"
    echo "Fabric Discovery Mode: ${fabricMode:-N/A}"
    # Only require manual approval in STRICT when unapproved-ctrlr is detected.
    if [[ "$strict_mode_value" == "$fabricMode" && "$unapproved_ctrlr_found" == "true" ]]; then
        printf "Fabric Mode Check:                                 %bMANUAL APIC APPROVAL REQUIRED%b\n" "$YELLOW" "$NC"
        check_status="MANUAL CHECK REQUIRED"
    else
        printf "Fabric Mode Check:                                                        %bPASSED%b\n" "$GREEN" "$NC"
    fi
    echo ""
    overall_status_fabric_mode="$check_status"
}

# --- SSL Certificate Date Check ---
function sslCertDate() {
    local check_status="PASSED"
    # Find the block with issuer containing Cisco Manufacturing CA, then extract notBefore/notAfter
    local certBlock=$(echo "$verifyApic" | awk '/issuer=.*Cisco Manufacturing CA/ {found=1} found && /notAfter=|notBefore=/ {print} /notAfter=/ {exit}')
    local certStartDateStr=$(echo "$certBlock" | grep 'notBefore=' | head -n1 | sed 's/.*notBefore=//')
    local certEndDateStr=$(echo "$certBlock" | grep 'notAfter=' | head -n1 | sed 's/.*notAfter=//')

    display_check_header "Check 8: SSL Certificate Date Check"
    echo "Certificate Start Date: ${certStartDateStr:-N/A}"
    echo "Certificate End Date: ${certEndDateStr:-N/A}"
    echo ""
    echo "Current APIC Date: ${apicDate:-N/A}"
    echo ""

    if [[ -z "$certStartDateStr" || -z "$certEndDateStr" || -z "$apicDate" ]]; then
        printf "Certificate Date Check:                                                   %bSKIPPED (Missing date info)%b\n" "$YELLOW" "$NC"
        check_status="SKIPPED"
    else
        # Convert dates to epoch time for reliable numerical comparison
        local unixStartDate=$(date -d "$certStartDateStr" +%s 2>/dev/null)
        local unixEndDate=$(date -d "$certEndDateStr" +%s 2>/dev/null)
        local unixApicDate=$(date -d "$apicDate" +%s 2>/dev/null)

        if [[ -z "$unixStartDate" || -z "$unixEndDate" || -z "$unixApicDate" ]]; then
            printf "Certificate Date Check:                                                   %bSKIPPED (Date conversion error)%b\n" "$YELLOW" "$NC"
            check_status="SKIPPED"
        elif (( unixStartDate < unixApicDate && unixApicDate < unixEndDate )); then
            printf "Certificate Date Check:                                                   %bPASSED%b\n" "$GREEN" "$NC"
        else
            printf "Certificate Date Check:                                                   %bFAILED%b\n" "$RED" "$NC"
            check_status="FAILED"
        fi
    fi
    echo ""
    overall_status_ssl_cert="$check_status"
}

# --- CA Certificate Present Check ---
function caCertPresent() {
    local check_status="PASSED"
    # Check for "file not found: /securedata/cacerts/cacert.crt" in verifyApic output
    local missingCaCert=$(echo "$verifyApic" | grep 'file not found:' | grep 'cacert' | sed 's/file not found: //g' | tr -d '\n')

    display_check_header "Check 9: Missing CA Certificate Check"

    if [[ -z "$missingCaCert" ]]; then
        printf "CA Certificate Check                                                      %bPASSED%b\n" "$GREEN" "$NC"
    else
        echo -e "Warning - File not Found: ${RED}$missingCaCert${NC}"
        printf "CA Certificate Check                                                      %bFAILED%b\n" "$RED" "$NC"
        check_status="FAILED"
    fi
    echo ""
    overall_status_ca_cert="$check_status"
}

# --- UCS PID Check ---
function ucsPid() {
    local check_status="PASSED"
    local ucsId="UCSC" # Identifier for UCS PID

    display_check_header "Check 10: UCS PID as APIC SN Check:"
    echo "APIC Serial Number: ${apicSn:-N/A}"
    # Use glob matching with [[ ... ]] for pattern matching
    if [[ "$apicSn" == *"$ucsId"* ]]; then
        printf "UCS PID Check:                                                            %bFAILED%b\n" "$RED" "$NC"
        check_status="FAILED"
    else
        printf "UCS PID Check:                                                            %bPASSED%b\n" "$GREEN" "$NC"
    fi
    echo ""
    overall_status_ucs_pid="$check_status"
}

# --- Infra VLAN in Use Check ---
function infraVlanInUse() {
    local check_status="PASSED"
    # Extract Infra VLAN from sam_exported.config
    local apicInfraVlan=$(echo "$samlog" | grep -E "infraVlan" | grep -oE "[0-9]*" | tr -d '\n')

    display_check_header "Check 11: Infra VLAN Deployed as EPG"
    echo "APIC Infra VLAN: ${apicInfraVlan:-N/A}"
    echo ""

    if [[ -z "$apicInfraVlan" ]]; then
        echo -e "${YELLOW}Warning: APIC Infra VLAN not found in sam_exported.config. Skipping detailed check.${NC}"
        printf "Infra VLAN Deployed as EPG Check:                                         %bSKIPPED%b\n" "$YELLOW" "$NC"
        check_status="SKIPPED"
    elif [[ ${#leafInfo[@]} -eq 0 ]]; then
        echo "No leaf information available to check Infra VLAN deployment."
        printf "Infra VLAN Deployed as EPG Check:                                         %bSKIPPED%b\n" "$YELLOW" "$NC"
        check_status="SKIPPED"
    else
        echo "Leaf Reported Infra VLAN Usage"
        echo "------------------------------"
        for i in "${!leafInfo[@]}"; do
            local nodeId="${nodeIdNumber[i]:-N/A}"
            if [[ -z "${leafInfo[i]}" ]]; then
                echo -e "Leaf ${nodeId}: ${YELLOW}No information available.${NC}"
                check_status="SKIPPED" #Check is skipped if leaf info is not present
                continue
            fi
            #Intialize to 0 right before counting; ensures starting point is consistent prior to counting
            local infraCount=0
            # Use word boundary (\b) for exact VLAN ID match to prevent partial matches
            local infraCount=$(echo "${leafInfo[i]}" | grep -c -E "\b$apicInfraVlan\b")
            if [[ "$infraCount" -gt 1 ]]; then 
                echo "Leaf ${nodeId}: Infra VLAN deployed ${infraCount} times"
                check_status="FAILED" # If any leaf fails, overall status is FAILED
            elif [[ "$infraCount" -eq 1 ]]; then 
                echo "Leaf ${nodeId}: Infra VLAN deployed ${infraCount} time"
            elif [[ "$infraCount" -eq 0 ]]; then 
                echo -e "Leaf ${nodeId}: ${YELLOW}Warning: Infra VLAN not deployed${NC}"
            fi
        done
    fi
    echo ""
    printf "Infra VLAN Deployed as EPG Check:                                         %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    overall_status_infra_vlan_in_use="$check_status"
    echo ""
}

# --- Target MB SN Check ---
function targetMbSn() {
    local check_status="PASSED"
    local badCtrlr="unapproved-ctrlr"
    # targetMbSn guidance is only relevant when unapproved-ctrlr appears in wiring issues.

    display_check_header "Check 12: targetMbSn Check"
    
    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found. Skipping targetMbSn check."
        check_status="SKIPPED"
    else
        for i in "${!arrayFabricInterfaces[@]}"; do
            # If wiringIssues[i] contains "unapproved-ctrlr", set status to MANUAL CHECK REQUIRED
            if [[ -n "${wiringIssues[i]}" && "${wiringIssues[i]}" == *"$badCtrlr"* ]]; then
                check_status="MANUAL CHECK REQUIRED"
                break # No need to check further if one is found
            fi
        done
    fi

    printf "targetMbSn Check:                                                         %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    echo ""
    
    if [[ "$check_status" == "MANUAL CHECK REQUIRED" ]]; then
        echo -e "${YELLOW}Please check the output of 'avread -a' or 'acidiag avread' for a targetMbSn value${NC}"
        echo -e "${YELLOW}on the other APICs that are in the cluster${NC}"
        echo -e "${YELLOW}If this value is present, please use 'replace-controller reset x' to correct it,${NC}"
        echo -e "${YELLOW}replacing the value of x with the APIC number that is not joining the cluster.${NC}"
        echo ""
    fi
    overall_status_target_mb_sn="$check_status"
}

# --- Leaf SSL Certificate Date Check ---
function leafCertDate() {
    local check_status="PASSED"
    local any_skipped=0
    
    display_check_header "Check 13: Leaf SSL Certificate Date Check"
    
    if [[ ${#nodeIdNumber[@]} -eq 0 ]]; then
        echo "No leaf nodes identified. Skipping Leaf Certificate check."
        check_status="SKIPPED"
        overall_status_leaf_cert="$check_status"
        echo ""
        return
    fi
    
    for i in "${!nodeIdNumber[@]}"; do
        local nodeId="${nodeIdNumber[i]:-N/A}"
        
        if [[ -z "${leafInfo[i]}" ]]; then
            echo "Leaf ${nodeId}: ${YELLOW}No information available (SSH connection failed)${NC}"
            any_skipped=1
            continue
        fi
        
        # Extract certificate validity dates from moquery output
        local certStartDateStr=$(echo "${leafInfo[i]}" | grep -E 'validityNotBefore' | awk -F': ' '{print $2}' | tr -d '\n')
        local certEndDateStr=$(echo "${leafInfo[i]}" | grep -E 'validityNotAfter' | awk -F': ' '{print $2}' | tr -d '\n')
        
        # Extract leaf current date (last 'date' command output)
        local leafDateStr=$(echo "${leafInfo[i]}" | grep -E '^[A-Z][a-z]{2} [A-Z][a-z]{2}' | tail -n 1 | tr -d '\n')
        
        echo "Leaf ${nodeId}:"
        echo "  Certificate Start Date: ${certStartDateStr:-N/A}"
        echo "  Certificate End Date: ${certEndDateStr:-N/A}"
        echo "  Current Leaf Date: ${leafDateStr:-N/A}"
        
        if [[ -z "$certStartDateStr" || -z "$certEndDateStr" || -z "$leafDateStr" ]]; then
            printf "  Leaf ${nodeId} Certificate Date Check:                                       %bSKIPPED (Missing date info)%b\n" "$YELLOW" "$NC"
            any_skipped=1
        else
            # Convert dates to epoch time for reliable numerical comparison
            local unixStartDate=$(date -d "$certStartDateStr" +%s 2>/dev/null)
            local unixEndDate=$(date -d "$certEndDateStr" +%s 2>/dev/null)
            local unixLeafDate=$(date -d "$leafDateStr" +%s 2>/dev/null)
            
            if [[ -z "$unixStartDate" || -z "$unixEndDate" || -z "$unixLeafDate" ]]; then
                printf "  Leaf ${nodeId} Certificate Date Check:                                       %bSKIPPED (Date conversion error)%b\n" "$YELLOW" "$NC"
                any_skipped=1
            elif (( unixStartDate < unixLeafDate && unixLeafDate < unixEndDate )); then
                printf "  Leaf ${nodeId} Certificate Date Check:                                       %bPASSED%b\n" "$GREEN" "$NC"
            else
                printf "  Leaf ${nodeId} Certificate Date Check:                                       %bFAILED%b\n" "$RED" "$NC"
                check_status="FAILED"
            fi
        fi
        echo ""
    done
    
    if [[ $any_skipped -eq 1 && $check_status == "PASSED" ]]; then
        check_status="SKIPPED"
    fi
    overall_status_leaf_cert="$check_status"
}

# --- Pod ID Mismatch Check ---
function podIdMismatch() {
    local check_status="PASSED"
    local compare_count=0

    display_check_header "Check 1: Pod ID Match"
    echo "Leaf Reported Pod IDs"
    echo "---------------------"

    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found. Skipping Pod ID check."
        check_status="SKIPPED"
    else
        for i in "${!arrayFabricInterfaces[@]}"; do
            local nodeId="${nodeIdNumber[i]:-N/A}"
            local leafPodId="${podIdLeaf[i]:-N/A}"
            local apicPodId="${podIdApic[i]:-N/A}"

            echo "Leaf ${nodeId}: ${leafPodId}"
            
            if [[ "$leafPodId" == "N/A" || "$apicPodId" == "N/A" ]]; then
                echo -e "${YELLOW}Warning: Missing Pod ID information for Leaf ${nodeId}. Skipping this leaf.${NC}"
            elif [[ "$apicPodId" -eq "$leafPodId" ]]; then # Numerical comparison
                : # Do nothing, status remains PASSED
                compare_count=$((compare_count + 1))
            else
                check_status="FAILED" # If any mismatch, overall status is FAILED
                compare_count=$((compare_count + 1))
            fi
        done
    fi
    echo ""
    # Assuming APIC Pod ID is consistent across its interfaces, show the first one.
    echo "APIC Reported Pod ID: ${podIdApic[0]:-N/A}"
    echo ""
    if [[ $compare_count -eq 0 ]]; then
        check_status="SKIPPED"
    fi
    printf "Pod ID Match:                                                             %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    overall_status_pod_id="$check_status"
    echo ""
}

# --- Fabric Domain Mismatch Check ---
function fabricDomainMismatch() {
    local check_status="PASSED"
    local compare_count=0

    display_check_header "Check 2: Fabric Name Match"
    echo "Leaf Reported Fabric Name"
    echo "-------------------------"

    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found. Skipping Fabric Name check."
        check_status="SKIPPED"
    else
        for i in "${!arrayFabricInterfaces[@]}"; do
            local nodeId="${nodeIdNumber[i]:-N/A}"
            local leafFabricName="${fabricNameLeaf[i]:-N/A}"
            local apicFabricName="${fabricNameApic[i]:-N/A}"

            echo "Leaf ${nodeId}: ${leafFabricName}"
            
            if [[ "$leafFabricName" == "N/A" || "$apicFabricName" == "N/A" ]]; then
                echo -e "${YELLOW}Warning: Missing Fabric Name information for Leaf ${nodeId}. Skipping this leaf.${NC}"
            elif [[ "$apicFabricName" == "$leafFabricName" ]]; then # String comparison
                : # Do nothing, status remains PASSED
                compare_count=$((compare_count + 1))
            else
                check_status="FAILED"
                compare_count=$((compare_count + 1))
            fi
        done
    fi
    echo ""
    echo "APIC Reported Fabric Name: ${fabricNameApic[0]:-N/A}"
    echo ""
    if [[ $compare_count -eq 0 ]]; then
        check_status="SKIPPED"
    fi
    printf "Fabric Name Match:                                                        %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    overall_status_fabric_name="$check_status"
    echo ""
}

# --- Controller UUID Mismatch Check ---
function ctrlrUuidMismatch() {
    local check_status="PASSED"
    local compare_count=0

    display_check_header "Check 3: Controller UUID Match"
    echo "Leaf Reported Controller UUID"
    echo "-----------------------------"

    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found. Skipping Controller UUID check."
        check_status="SKIPPED"
    else
        for i in "${!arrayFabricInterfaces[@]}"; do
            local nodeId="${nodeIdNumber[i]:-N/A}"
            local leafUuid="${uuidLeaf[i]:-N/A}"
            local apicUuid="${uuidApic[i]:-N/A}"

            echo "Leaf ${nodeId}: ${leafUuid}"
            
            if [[ "$leafUuid" == "N/A" || "$apicUuid" == "N/A" ]]; then
                printf "%bWarning: Missing UUID information for Leaf ${nodeId}. Skipping this leaf.%b\n" "$YELLOW" "$NC"
            elif [[ "$apicUuid" == "$leafUuid" ]]; then # String comparison
                : # Do nothing, status remains PASSED
                compare_count=$((compare_count + 1))
            else
                check_status="FAILED"
                compare_count=$((compare_count + 1))
            fi
        done
    fi
    echo ""
    echo "APIC Reported UUID: ${uuidApic[0]:-N/A}"
    echo ""
    if [[ $compare_count -eq 0 ]]; then
        check_status="SKIPPED"
    fi
    printf "Controller UUID Match:                                                    %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    overall_status_uuid="$check_status"
    echo ""
}

# --- Infra VLAN Mismatch Check ---
function infraVlanMismatch() {
    local check_status="PASSED"
    local compare_count=0

    display_check_header "Check 4: Infra VLAN Match"
    echo "Leaf Reported Infra VLAN"
    echo "------------------------"

    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found. Skipping Infra VLAN check."
        check_status="SKIPPED"
    else
        for i in "${!arrayFabricInterfaces[@]}"; do
            local nodeId="${nodeIdNumber[i]:-N/A}"
            local leafInfraVlan="${infraVlanLeaf[i]:-N/A}"
            local apicInfraVlan="${infraVlanApic[i]:-N/A}"

            echo "Leaf ${nodeId}: ${leafInfraVlan}"
            
            if [[ "$leafInfraVlan" == "N/A" || "$apicInfraVlan" == "N/A" ]]; then
                echo -e "${YELLOW}Warning: Missing Infra VLAN information for Leaf ${nodeId}. Skipping this leaf.${NC}"
            elif [[ "$apicInfraVlan" == "$leafInfraVlan" ]]; then # String comparison
                : # Do nothing, status remains PASSED
                compare_count=$((compare_count + 1))
            else
                check_status="FAILED"
                compare_count=$((compare_count + 1))
            fi
        done
    fi
    echo ""
    echo "APIC Reported Infra VLAN: ${infraVlanApic[0]:-N/A}" # Assuming APIC Infra VLAN is consistent
    echo ""
    if [[ $compare_count -eq 0 ]]; then
        check_status="SKIPPED"
    fi
    printf "Infra VLAN Match:                                                         %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    overall_status_infra_vlan_match="$check_status"
    echo ""
}

# --- Wiring Mismatch Check ---
function wiringMismatch() {
    local check_status="PASSED"
    local badPortUsage="fabric" # If port usage contains 'fabric', it's considered a FAILED wiring check.
    local compare_count=0

    display_check_header "Check 5: Wiring Mismatch"

    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found. Skipping Wiring Mismatch check."
        check_status="SKIPPED"
    else
        for i in "${!arrayFabricInterfaces[@]}"; do
            local nodeId="${nodeIdNumber[i]:-N/A}"
            local leafInterface="${leafLocalInterface[i]:-N/A}"
            # Extract port usage from leafInfo.
            if [[ -z "${leafInfo[i]}" ]]; then
                echo "Leaf Node ID: ${nodeId}"
                echo "  Leaf Interface: ${leafInterface}"
                echo -e "  Usage: ${YELLOW}N/A (missing LLDP/leaf data)${NC}"
                echo -e "  Wiring Mismatch Check: ${YELLOW}SKIPPED${NC}"
                echo ""
                continue
            fi

            local portUsage=$(echo "${leafInfo[i]}" | grep -E 'usage.*:' | awk '{print $3}' | tr -d '\n')

            echo "Leaf Node ID: ${nodeId}"
            echo "  Leaf Interface: ${leafInterface}"
            echo "  Usage: ${portUsage:-N/A}"

            if [[ -z "$portUsage" ]]; then
                printf "Wiring Mismatch Check:                                                    %bSKIPPED%b\n" "$YELLOW" "$NC"
            elif [[ "$portUsage" == *"$badPortUsage"* ]]; then
                printf "Wiring Mismatch Check:                                                    %bFAILED%b\n" "$RED" "$NC"
                check_status="FAILED"
                compare_count=$((compare_count + 1))
            else
                printf "Wiring Mismatch Check:                                                    %bPASSED%b\n" "$GREEN" "$NC"
                compare_count=$((compare_count + 1))
            fi
            echo ""
        done
    fi
    if [[ $compare_count -eq 0 ]]; then
        check_status="SKIPPED"
    fi
    # Report overall status for this check
    printf "Overall Wiring Mismatch Check:                                            %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    overall_status_wiring_mismatch="$check_status"
    echo ""
}

# --- Unapproved Serial Number Check ---
function unapprovedSN() {
    local check_status="PASSED"
    local badSnTxt="unapproved-serialnumber"

    display_check_header "Check 6: Unapproved Serial Number"
    echo "APIC Serial Number: ${apicSn:-N/A}"
    
    if [[ ${#arrayFabricInterfaces[@]} -eq 0 ]]; then
        echo "No fabric interfaces found. Skipping Unapproved Serial Number check."
        check_status="SKIPPED"
    else
        for i in "${!arrayFabricInterfaces[@]}"; do
            # If wiringIssues[i] is not empty and contains "unapproved-serialnumber", set status to FAILED.
            # If wiringIssues[i] is empty (e.g., due to SSH failure), it's treated as PASSED for this specific check.
            if [[ -n "${wiringIssues[i]}" ]]; then
                if [[ "${wiringIssues[i]}" == *"$badSnTxt"* ]]; then
                    check_status="FAILED"  
                    break # If one fails, the overall status is FAILED
                fi
            fi
        done
    fi
    printf "Serial Number Check:                                                      %b%s%b\n" "$(get_color "$check_status")" "$check_status" "$NC"
    overall_status_unapproved_sn="$check_status"
    echo ""
}

# Call main function to start the script
main
