#!/bin/bash

# Author          : Jean-Michel Cuvelier <jecuveli@cisco.com>
# Team            : TAC EMEA - ACI Team
# Release verion  : 3.1.0
# Last update     : 2023-10-26

#====================#
# Function - LOGGING #
#====================#

# This function logs events/messages to the system log using the logger command in Linux.
# Arguments:
#   1. SEVERITY: The severity level of the message to be logged. 
#      It can be one of the following:
#       - emerg
#       - alert 
#       - crit
#       - err
#       - warning 
#       - notice
#       - info
#       - debug
#      By default, if no severity is provided, the function will use 'info'.
#   2. MESSAGE: The message to be logged.
#
# Note: root access is needed to see the logs in : /var/log/messages
log() {

  # Check if at least a MESSAGE is provided
  if [ "$#" -gt 0 ] ; then
    
    # Default severity level to INFO if not provided.
    if [ "$#" -gt 1 ] ; then
      local SEVERITY="${1}"
      local MESSAGE="$2"
    else
      local SEVERITY="info"
      local MESSAGE="$1"
    fi

    # logger is only available on the controllers
    if [ "${LOCAL_NODE_TYPE}" == "controller" ] ; then

      # Get the current timestamp in the format 'YYYY-MM-DDTHH:MM:SS'
      local TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')

      # Logging to system log using the logger command within user facility
      logger -p "user.${SEVERITY}" -t "$0" "${TIMESTAMP}||${SEVERITY} ==> ${MESSAGE}"

    fi

    # Clean up local variables
    unset SEVERITY MESSAGE TIMESTAMP    

  fi
}

#=====================#
# Functions - commons #
#=====================#

# Function to convert a value from a specified unit (or bytes by default) to its appropriate size unit.
#
# Arguments:
#   $1 (INPUT_VALUE) - The value to be converted, followed optionally by a unit (e.g., "1024", "500 KB", "2 GB").
bytes_converter() {
  # Ensure an input is provided
  if [ -z "$1" ]; then
    log "error" "No argument provided to bytes_converter function."
    exit_due_to_code_issue
  fi

  local INPUT_VALUE="$1"
  local VALUE="${INPUT_VALUE% *}"    # Extract the numeric part of the input
  local UNIT="$(echo "${INPUT_VALUE#* }" | tr 'a-z' 'A-Z')"     # Extract the unit part and convert to lowercase
  local BYTES=0
  
  # Define constants for byte conversions
  local KB=$((1024))
  local MB=$((1024*KB))
  local GB=$((1024*MB))

  # If the input doesn't specify a unit, default to 'bytes'
  [[ $INPUT_VALUE == "$VALUE" ]] && UNIT="bytes"

  # Convert the input value to bytes based on its specified unit
  case "$UNIT" in
    BYTES|B) BYTES="$VALUE" ;;
    KB) BYTES=$((VALUE*KB)) ;;
    MB) BYTES=$((VALUE*MB)) ;;
    GB) BYTES=$((VALUE*GB)) ;;
    *) 
      log "error" "Unsupported unit: $UNIT. Supported units are bytes, KB, MB, and GB."
      exit_due_to_code_issue 
      ;;
  esac

  # Convert the byte value to the most appropriate size unit for output
  if [[ $BYTES -ge $GB ]]; then
    READ_VALUE="$(bc -l <<< "scale=2; $BYTES/$GB") GB"
  elif [[ $BYTES -ge $MB ]]; then
    READ_VALUE="$(bc -l <<< "scale=2; $BYTES/$MB") MB"
  elif [[ $BYTES -ge $KB ]]; then
    READ_VALUE="$(bc -l <<< "scale=2; $BYTES/$KB") KB"
  else
    READ_VALUE="$BYTES bytes"
  fi

  # Log the conversion result and output it
  log "info" "Converted $INPUT_VALUE to $READ_VALUE"

  # Unset local variables
  unset INPUT_VALUE VALUE UNIT BYTES KB MB GB
}




#=========================#
# Functions - EXIT PROMPT #
#=========================#

# This function interrupts the current script execution and request a new root password from the TAC user.
exit_and_ask_root_password() {

  # Display separation lines and spaces for clarity
  echo -e "\n\n ====> \n\n"

  # Inform the TAC user that root access is required
  echo -e "  Root access is required to continue with the script."

  # Display the debug token
  display "Please provide root access using the TOKEN: $(acidiag dbgtoken)"

  echo -e "  Once the root password is provided, rerun the script using the following option:\n"

  # Guide the user on how to run the script with the provided token in option
  echo -e "${0} --token \"ROOT_PASSWORD\""

  echo -e "\nThank you.\n----------"

  echo -e "\n\n <==== \n\n"

  exit 0

}

# This function interrupts the current script execution and require an escalation to a TAC engineer.
#
# Arguments:
#   MESSAGE (optional): Additional message to be displayed during the escalation process.
#
exit_and_escalate_to_TAC_engineer() {

  # Display separation lines and spaces for clarity
  echo -e "\n\n ====> \n\n"

  # Inform the user that a TAC engineer is needed to continue
  echo -e "  To continue with the script, a TAC engineer is required. Please reply to Sherlock Holmes at <noreply@cisco.com> with the following information in your email:\n"

  # Check if a custom message has been provided as an argument
  if [ "$#" -eq 1 ] ; then
    MESSAGE=$1

    # Check if the custom message starts with "The faults"
    if [ $(echo "$MESSAGE" | egrep -i -o "^The faults" | wc -l ) -eq 1 ] ; then
      
      # Declare local variables for faults
      local FAULTS
      local FAULT

      # Extract fault details from the message
      FAULTS=$(echo "$MESSAGE" | egrep -i -o "uni/[^ ]+|topology/[^ ]+" | tr '\n' ' ')
      
      # Update the message to reflect that faults are still present
      MESSAGE="The faults are still remaining."

      # Display a custom message with details for Sherlock
      display "Sherlock, please escalate the service request to a TAC engineer. MSG: ${MESSAGE}"

      # Display each extracted fault for better clarity
      for FAULT in ${FAULTS} ; do
        display "${FAULT}"
      done

      # Clean up local fault variables
      unset FAULTS FAULT

    else
      # If the message doesn't match the specific format, display the custom message as-is
      display "Sherlock, please escalate the service request to a TAC engineer. MSG: ${MESSAGE}"
    fi

    # Clean up the message variable
    unset MESSAGE  
  else
    # If no custom message provided, display a default escalation message
    display "Sherlock, please escalate the service request to a TAC engineer."
  fi

  # Notify the user about the escalation process
  echo -e "  The service request will be escalated.\n"
  echo -e "  Once the service request is picked up, a TAC engineer will contact you to continue with the script.\n"

  echo -e "\nThank you.\n----------"

  echo -e "\n\n <==== \n\n"

  # Exit the script 
  exit 0


}

# This function interrupts the current script execution and requires the credentials to be re-encoded.
exit_password_expired_or_wrong(){

  # Display separation lines for clarity
  echo -e "\n\n ====> \n\n"

  # If TAC_USER mode is active, generate and provide a new token for the TAC engineer
  if [ "${TAC_USER}" == "true" ] ; then
    display "Unable to connect to ${REMOTE_IP} (${REMOTE_HOSTNAME}). The password is either invalid or expired. New TOKEN: $(acidiag dbgtoken)."
    
    log "err" "exit_password_expired_or_wrong: Unable to connect due to invalid or expired password for user 'root' on ${REMOTE_IP} (${REMOTE_HOSTNAME})."
  else
    display "Unable to connect to ${REMOTE_IP} (${REMOTE_HOSTNAME}). If you are using the option --pwd \"PASSWORD\", consider enclosing special characters in single quotes, e.g., --pwd '\$!'."
    
    log "err" "exit_password_expired_or_wrong: Unable to connect due to password issues for user '${USER}' on ${REMOTE_IP} (${REMOTE_HOSTNAME})."
  fi

  echo -e "\n\n <==== \n\n"

  # Exit the script 
  exit 0

}


# This function interrupts the current script execution and requires code troubleshooting.
exit_due_to_code_issue() {

  # Notify the TAC engineer about the internal code issue and provide guidance on where to check for details
  exit_and_escalate_to_TAC_engineer "Internal issue detected in the code. Please inspect /var/log/message with root access."

}

#==============================#
# FUNCTIONS - INPUT AND OUTPUT #
#==============================#

# This function displays a message in a framed box.
#
# Arguments:
#   MESSAGE: The message to be displayed inside the framed box.
#
display() {
  # Check if exactly one argument (the message) is provided.
  if [ $# -eq 1 ] ; then
    
    # Message
    local MESSAGE="$1"

    # Construct the frame string based on the calculated length.
    local FRAME_BORDER="--"

    # Add a dash to the frame string for each character in the MESSAGE.
    for CPT in $(seq 0 $(echo "${MESSAGE}" | wc -c)) ; do
      FRAME_BORDER="$FRAME_BORDER""-"
    done

    # Display the MESSAGE within the frame.
    echo ""
    echo " ${FRAME_BORDER}"
    echo " | ${MESSAGE} |"
    echo " ${FRAME_BORDER}"
    echo ""

    # Clean up local variables
    unset MESSAGE FRAME_BORDER CPT   

  fi
}

# This function displays a message in the same line.
#
# Arguments:
#   $1 (MESSAGE) - The message to be printed on the same line.
display_same_line(){
  
  # Check if exactly one argument (the message) is provided.
  if [ $# -eq 1 ] ; then
      
      local MESSAGE="$1"
  
      local CLEAN_LINE=""
      
      # Construct a clean line with spaces of the same length as the message.
      for CPT in $(seq 0 $(echo "${MESSAGE}" | wc -c)) ; do
        CLEAN_LINE=$CLEAN_LINE" "
      done
  
      # Overwrite the current line with spaces.
      echo -ne "${CLEAN_LINE}\r"

      # Display the new message.
      printf "${MESSAGE}"

      # Unset the local variables to free up resources.
      unset MESSAGE CLEAN_LINE CPT   
  
  fi
}

# This function prompts the user to wait for a specified duration.
#
# Arguments:
#   MESSAGE: Message to be displayed above the countdown timer.
#   DURATION: The duration in formats like "1d", "1h", "2m", "3s" representing days, hours, minutes, and seconds respectively.
#
waiting_timer() {
  # Ensure that two arguments have been passed to the function
  if [ $# -eq 2 ] ; then
    local MESSAGE="$1"
    local DURATION="$2"
    local TIMER=0

    # Convert the DURATION to seconds
    local NUMBER
    local REGEX_TIME="([0-9]+)([dhms])"  # Regular expression to match duration formats

    # Parse the DURATION input and convert it to seconds
    while [[ $DURATION =~ $REGEX_TIME ]] ; do
      NUMBER=${BASH_REMATCH[1]}
      # Based on the matched unit (d, h, m, or s), multiply the number with its equivalent in seconds
      case ${BASH_REMATCH[2]} in
        d)  let "TIMER += ${NUMBER} * 86400" ;;  # days to seconds
        h)  let "TIMER += ${NUMBER} * 3600" ;;   # hours to seconds
        m)  let "TIMER += ${NUMBER} * 60" ;;     # minutes to seconds
        s)  let "TIMER += ${NUMBER}" ;;          # seconds
      esac
      # Remove the processed part of the DURATION string for the next iteration
      DURATION=${DURATION#*${BASH_REMATCH[0]}}
    done

    # If TIMER remains 0, it means DURATION wasn't converted to seconds successfully
    if [ $TIMER -eq 0 ] ; then
      log "err" "waiting_timer: Failed to convert DURATION '${DURATION}' to seconds."
      exit_due_to_code_issue
    fi

    # Display the provided message to the user
    display "${MESSAGE}"
    log "info" "waiting_timer: Started with MESSAGE: '${MESSAGE}' and TIMER: '${TIMER}' seconds."

    # Display the countdown timer, decreasing every second
    for (( CPT=${TIMER} ; CPT>=0; CPT-- )); do
      # Calculate hours, minutes, and seconds for the countdown
      local HOURS=$((CPT / 3600))
      local MINUTES=$(( (CPT % 3600) / 60 ))
      local SECONDS=$((CPT % 60))

      # Display the countdown in the format hours:minutes:seconds
      echo -ne "                                          \r"  # Clear the line for updating the countdown
      printf "  Time Remaining: %02dh:%02dm:%02ds\r" $HOURS $MINUTES $SECONDS
      sleep 1
    done
    echo ""
    log "info" "waiting_timer: Finished for MESSAGE: '${MESSAGE}' after TIMER: '${TIMER}' seconds."

    # Clean up local variables
    unset MESSAGE DURATION TIMER NUMBER REGEX_TIME CPT HOURS MINUTES SECONDS

  else
    log "err" "waiting_timer: Function called with incorrect number of arguments."
    exit_due_to_code_issue
  fi
}


# Prompts the user with a message and waits for a 'yes' or 'no' response.
# Arguments:
#   MESSAGE: The message to be displayed to the user.
prompt_for_yes_no() {

  # Ensure a message has been passed to the function
  if [ $# -eq 1 ] ; then

    local MESSAGE="$1"
    
    # Reset the BOOLEAN variable
    BOOLEAN=""

    # For clarity add a newline before the message.
    echo ""

    # Log the initiation of the user prompt
    log "info" "prompt_for_yes_no: Prompting user with message: '${MESSAGE}'."

    # Continuously prompt the user until a valid response ('y' or 'n') is received
    while ! [ "${BOOLEAN}" == "y" ] && ! [ "${BOOLEAN}" == "n" ] ; do
      read -p "${MESSAGE} (y/n): " BOOLEAN
    done

    # Log the user's response
    log "info" "prompt_for_yes_no: User responded with: '${BOOLEAN}'."

    # Clean up local variables
    unset MESSAGE    

  else
    # Log an error if an incorrect number of arguments were passed
    log "err" "prompt_for_yes_no: Incorrect usage. Expected one argument, received $#."
    exit_due_to_code_issue
  fi
}

# Prompts the user for input until the input matches the given regex pattern.
# Arguments:
#   PROMPT: The message to be displayed to the user.
#   REGEX: The regex pattern that the input data should match.
prompt_until_match_regex() {

  # Ensure the right number of arguments have been passed to the function
  if [ $# -eq 2 ] ; then

    # Initialize the READ_VALUE variable
    READ_VALUE=""
    
    local PROMPT="$1"
    local REGEX="$2"

    # Log the initiation of the user prompt
    log "info" "prompt_until_match_regex: Prompting user with message: '${PROMPT}', expecting input to match regex: '${REGEX}'."

    # For clarity add a newline before the message.
    echo ""


    # Continuously prompt the user until the input matches the provided regex
    while [ $(echo "${READ_VALUE}" | egrep "${REGEX}" | wc -l) -eq 0 ] ; do
      read -p "${PROMPT}" READ_VALUE
    done

    # Log the user's input
    log "info" "prompt_until_match_regex: User provided valid input: '${READ_VALUE}'."

    # Clean up local variables
    unset PROMPT REGEX    

  else
    # Log an error if an incorrect number of arguments were passed
    log "err" "prompt_until_match_regex: Incorrect usage. Expected two arguments (PROMPT and REGEX), received $#."
    exit_due_to_code_issue
  fi
}

# Prompts the user for input until the input matches a given regex pattern. If the user provides no input, a default value is used.
# Arguments:
#   PROMPT: The message to be displayed to the user.
#   REGEX: The regex pattern the input data should match.
#   DEFAULT_VALUE: The default value to be used if the user provides no input.
prompt_until_match_or_default() {

  # Ensure the correct number of arguments have been passed to the function
  if [ $# -eq 3 ] ; then

    # Initialize the READ_VALUE variable
    READ_VALUE=""
    
    local PROMPT="$1"
    local REGEX="$2"
    local DEFAULT_VALUE="$3"

    # Log the initiation of the user prompt
    log "info" "prompt_until_match_or_default: Prompting user with message: '${PROMPT}', expecting input to match regex: '${REGEX}', with default value: '${DEFAULT_VALUE}'."

    # For clarity add a newline before the message.
    echo ""

    # Continuously prompt the user until the input matches the provided regex or uses the default value if no input is provided
    while [[ ! "${READ_VALUE}" =~ ${REGEX} ]] ; do
      read -p "${PROMPT}" READ_VALUE

      # Use the default value if the user provides no input
      if [ -z "${READ_VALUE}" ] ; then
        READ_VALUE="${DEFAULT_VALUE}"
      fi
    done

    # Log the user's input or the default value used
    log "info" "prompt_until_match_or_default: Value set to: '${READ_VALUE}'."

    # Clean up local variables
    unset PROMPT REGEX DEFAULT_VALUE    

  else
    # Log an error if an incorrect number of arguments were passed
    log "err" "prompt_until_match_or_default: Incorrect usage. Expected three arguments (PROMPT, REGEX, and DEFAULT_VALUE), received $#."
    exit_due_to_code_issue
  fi
}

# Prompts the user to select entries from a range of numbers (menu-style).
# Arguments:
#   PROMPT: The prompt message to be displayed to the user.
#   MIN: The minimum selectable number in the range.
#   MAX: The maximum selectable number in the range.
prompt_select_from_range() {

  # Ensure that three arguments have been passed to the function
  if [ $# -eq 3 ] ; then
    local PROMPT="$1"
    local MIN="$2"
    local MAX="$3"

    log "info" "prompt_select_from_range: Started with PROMPT: '${PROMPT}', MIN: '${MIN}', and MAX: '${MAX}'."

    # Ensure MIN is not greater than MAX
    if [ "${MIN}" -gt "${MAX}" ] ; then
      local TMP=${MIN}
      MIN=${MAX}
      MAX=${TMP}
    fi

    # For clarity add a newline before the message.
    echo ""

    local END="false"

    while [ "${END}" == "false" ] ; do
      # Prompt the user to provide input in a specific format, or default to "0"
      prompt_until_match_or_default "${PROMPT}" "^ *( *[0-9]+ *, *| *[0-9]+-[0-9]+ *, *)*([0-9]+|[0-9]+-[0-9]+) *$" "0"

      # Convert any specified ranges (e.g., 5-8) into a sequence of numbers (e.g., 5 6 7 8)
      for SEQUENCE_NUMBER in $(echo "${READ_VALUE}" | egrep -o "[0-9]+-[0-9]+"); do
        READ_VALUE=$(echo "${READ_VALUE}" | sed -e "s#${SEQUENCE_NUMBER}#$(seq $(echo "${SEQUENCE_NUMBER}" | awk -F '-' '{print $1}') $(echo "${SEQUENCE_NUMBER}" | awk -F '-' '{print $2}') | tr '\n' ' ')#g")
      done

      # Sort the numbers and ensure uniqueness
      READ_VALUE=$(echo "${READ_VALUE}" | tr ',' ' ' | sed -e "s#  *# #g" | tr ' ' '\n' | sort -n | uniq | tr '\n' ' ' | sed -e "s#^ *##g" -e "s# *\$##g")

      # Check if the provided values are within the expected range
      if [ "$(echo "${READ_VALUE}" | egrep -o "^[0-9]+")" -ge ${MIN} ] && [ "$(echo "${READ_VALUE}" | egrep -o "[0-9]+$")" -le ${MAX} ] ; then
        END="true"
      fi
    done

    log "info" "prompt_select_from_range: User's input is within the expected range."

    # Clean up local variables
    unset PROMPT MIN MAX END SEQUENCE_NUMBER    

  else
    log "err" "prompt_select_from_range: Incorrect number of arguments. Expected 3, received $#."
    exit_due_to_code_issue
  fi
}

#==========================#
# VARIABLES - RETURN VALUE #
#==========================#

# Stores the result of any boolean function.
BOOLEAN=""

# Stores the result of any other function.
READ_VALUE=""

# By default, redirect stdout to /dev/null to suppress output.
OUTPUT=" > /dev/null"

#=======================#
# VARIABLE - LEVEL MODE #
#=======================#

# Indicates if TAC (Technical Assistance Center) user mode is active.
TAC_USER="false"

#========================#
# VARIABLES - LOCAL NODE #
#========================#

# Hostname of the local node.
LOCAL_HOSTNAME=""

# Defines the type of the local device - can be controller, leaf, spine, or unknown.
LOCAL_NODE_TYPE=""

# Identifier for the local node.
LOCAL_NODE_ID=""

# Identifier for the local pod.
LOCAL_POD_ID=""

# IP address used for VTEP (VXLAN Tunnel Endpoint) on the local node.
LOCAL_IP=""

# Software version/release on the local node.
LOCAl_SOFTWARE_RELEASE=""

#=========================#
# VARIABLES - REMOTE NODE #
#=========================#

# Hostname of the remote node.
REMOTE_HOSTNAME=""

# Defines the type of the remote device - can be controller, leaf, spine, or unknown.
REMOTE_NODE_TYPE=""

# Identifier for the remote node.
REMOTE_NODE_ID=""

# Identifier for the remote pod.
REMOTE_POD_ID=""

# IP address used for VTEP on the remote node.
REMOTE_IP=""

# Software version/release on the remote node.
REMOTE_SOFTWARE_RELEASE=""

#=================#
# VARIABLES - SSH #
#=================#

# Constructed command for SSH to the remote node. 
# Will be appended with specific commands as needed.
SSH_REMOTE_COMMAND=""

# Username for SSH.
USER=""

# Password associated with the above username.
PASSWORD=""

# Root user's password.
ROOT_PASSWORD=""

#=========================#
# FUNCTIONS - CREDENTIALS #
#=========================#

# Prompt and ask the user for credentials, ensuring that they are provided.
prompt_for_user_credentials() {

  log "info" "prompt_for_user_credentials: Starting to gather user credentials."

  # Check if either the USER or PASSWORD variables are empty
  if [ -z "${USER}" ] || [ -z "${PASSWORD}" ] ; then

    # If the USER variable is empty, prompt the user for it
    if [ -z "${USER}" ] ; then
      prompt_until_match_or_default "Please enter the user name (default: admin) : " "..*" "admin"
      USER=${READ_VALUE}
    fi

    # If the PASSWORD variable is empty, prompt the user for it
    if [ -z "${PASSWORD}" ] ; then
      read -s -p  "Please enter the password : " PASSWORD
      echo ""
      # For security reasons, do not log the actual password
      log "info" "prompt_for_user_credentials: User provided a password for the username: \"${USER}\"."
    fi

  else
    # Both USER and PASSWORD are already set, so log this information
    log "info" "prompt_for_user_credentials: USER and PASSWORD are already set. No need for further input."
  fi

}

# Prompt and ask the user for TAC credentials when required.
prompt_for_tac_credentials() {

  log "info" "prompt_for_tac_credentials: Checking if TAC credentials are required."

  # If ROOT_PASSWORD is not set and TAC_USER is true, then prompt for the credentials
  if [ -z "${ROOT_PASSWORD}" ] && [ "${TAC_USER}" == "true" ] ; then

    # If ROOT_PASSWORD is not yet set, prompt the user for it
    if [ -z "${ROOT_PASSWORD}" ] ; then
      
      # generate a new token for the TAC user.
      local TOKEN=$(acidiag dbgtoken)

      read -p "Please enter the root password with the TOKEN ${TOKEN} : " ROOT_PASSWORD
      echo ""

      # For security reasons, do not log the actual password but record that it was provided
      log "info" "prompt_for_tac_credentials: User provided a root password for TAC with the associated TOKEN: '${TOKEN}'."

      # Clean up local variables
      unset TOKEN
    fi

  else
    log "info" "prompt_for_tac_credentials: ROOT_PASSWORD is already set or TAC_USER is not active. No need for further input."
  fi

}

# Validates TAC user credentials.
validate_tac_credentials() {

    log "info" "validate_tac_credentials: Verifying TAC user credentials."

    # Check if the root password is provided or not. If not, read it.
    if [ -z "${ROOT_PASSWORD}" ] ; then
        prompt_for_tac_credentials
    fi

    # Temporarily set the SSH command to connect to localhost using the provided root password.
    local REMOTE_IP="127.0.0.1"
    local SSH_TMP_COMMAND="sshpass -p ${ROOT_PASSWORD} ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o StrictHostKeyChecking=no root@${REMOTE_IP}"
    local TEST_RESULT

    # Test the validity of the root password using a simple SSH command to localhost.
    TEST_RESULT=$(${SSH_TMP_COMMAND} "echo 'SSH Test Success'" 2>/dev/null)

    if [ "$TEST_RESULT" != "SSH Test Success" ] ; then
        log "err" "validate_tac_credentials: Invalid or expired root password."
        exit_password_expired_or_wrong
    fi

    # Clear temporary variables used for testing.
    unset SSH_TMP_COMMAND
    unset TEST_RESULT

    log "info" "validate_tac_credentials: TAC user credentials validated successfully."
}

#====================================#
# FUNCTIONS - GATHERING NODE DETAILS #
#====================================#

# Determine the type of ACI node (e.g., leaf, spine, controller) on which the script is running and set
# relevant global variables.
gather_local_node_details() {
  
  log "info" "gather_local_node_details: Starting to identify local node details."

  local HOST=$(hostname)

  # Retrieve node information using 'acidiag fnvread'.
  local NODE_INFO=$(acidiag fnvread | grep " ${HOST} ")

  # If NODE_INFO has content, it indicates we're on a leaf or spine node.
  if ! [ -z "${NODE_INFO}" ] ; then
    LOCAL_HOSTNAME=${HOST}
    LOCAL_NODE_TYPE=$(echo "${NODE_INFO}" | awk '{print $6}')
    LOCAL_NODE_ID=$(echo "${NODE_INFO}" | awk '{print $1}')
    LOCAL_POD_ID=$(echo "${NODE_INFO}" | awk '{print $2}')
    LOCAL_IP=$(echo "${NODE_INFO}" | awk '{print $5}' | cut -d '/' -f 1)
    LOCAl_SOFTWARE_RELEASE=$(acidiag version)
  else
    # If no node information is found, we might be on a controller node.
    # Check if the current node is a controller node.
    local NODE_ATTRIBUTES=$(moquery -c fabricNode -x "query-target-filter=eq(fabricNode.name,\"${HOST}\")" -o json | jq '.imdata[].fabricNode.attributes' 2> /dev/null )
    if [ -n "${NODE_ATTRIBUTES}" ] ; then
      LOCAL_HOSTNAME=${HOST}
      LOCAL_NODE_TYPE=$(echo "${NODE_ATTRIBUTES}" | jq -r '.role')      
      LOCAL_NODE_ID=$(echo "${NODE_ATTRIBUTES}" | jq -r '.id')
      LOCAL_POD_ID=$(echo "${NODE_ATTRIBUTES}" | jq -r '.dn' | egrep -o "pod-[0-9]+" | cut -d '-' -f 2)
      LOCAL_IP=$(echo "${NODE_ATTRIBUTES}" | jq -r '.address')
      LOCAl_SOFTWARE_RELEASE=$(acidiag version)
    else
      # If it's neither a leaf, spine, nor controller node, set type to 'unknown'.
      LOCAL_NODE_TYPE="unknown"
    fi

  fi

  # Log the consolidated attributes of the local node.
  log "info" "gather_local_node_details: Local Node Details: Hostname=${LOCAL_HOSTNAME}, Type=${LOCAL_NODE_TYPE}, Node ID=${LOCAL_NODE_ID}, Pod ID=${LOCAL_POD_ID}, IP=${LOCAL_IP}, Software Release=${LOCAl_SOFTWARE_RELEASE}"

  # Clean up local variables
  unset NODE_INFO HOST NODE_ATTRIBUTES
}

# This function gathers details about the remote node.
# relevant global variables.
gather_remote_node_details() {
  log "info" "gather_remote_node_details: Starting to identify remote node details."

  # Check if local node details are available, if not fetch them.
  if [ -z "${LOCAL_NODE_TYPE}" ] ; then
    log "info" "gather_remote_node_details: Fetched local node details as LOCAL_NODE_TYPE was not set."
    gather_local_node_details
  fi

  # If the REMOTE_NODE_ID isn't provided, exit with an error.
  if [ -z "${REMOTE_NODE_ID}" ] ; then
    log "err" "gather_remote_node_details: Remote Node ID not set."
    exit_due_to_code_issue
  fi

  # Initialize local variable to store remote node info.
  local REMOTE_NODE_INFO=""

  # If local node is a leaf or spine, determine the remote node's details with acidiag fnvread or acidiag avread.
  if [[ "${LOCAL_NODE_TYPE}" == "leaf" ]] || [[ "${LOCAL_NODE_TYPE}" == "spine" ]] ; then
    
    REMOTE_NODE_INFO=$(acidiag fnvread | egrep "^ *${REMOTE_NODE_ID} ")

    # If we find matching details, it's either a leaf or spine.
    if [ -n "${REMOTE_NODE_INFO}" ] ; then
      REMOTE_HOSTNAME=$(echo "${REMOTE_NODE_INFO}" | awk '{print $3}')
      REMOTE_NODE_TYPE=$(echo "${REMOTE_NODE_INFO}" | awk '{print $6}')
      REMOTE_POD_ID=$(echo "${REMOTE_NODE_INFO}" | awk '{print $2}')
      REMOTE_IP=$(echo "${REMOTE_NODE_INFO}" | awk '{print $5}' | cut -d '/' -f 1)
      REMOTE_SOFTWARE_RELEASE="unknown"
    else
      # If not a leaf or spine, it's potentially a controller.
      REMOTE_HOSTNAME="unknown hostname"
      REMOTE_NODE_INFO=$(acidiag avread | egrep  "appliance +id=${REMOTE_NODE_ID} ")

      REMOTE_NODE_TYPE="controller"
      REMOTE_POD_ID=$(echo "${REMOTE_NODE_INFO}" | egrep -o "podId=[^ ]+" | awk -F '=' '{print $2}')
      REMOTE_IP=$(echo "${REMOTE_NODE_INFO}" | tr ' ' '\n' | egrep -m 1 "address=[^ ]+" | cut -d '=' -f 2)
      REMOTE_SOFTWARE_RELEASE="unknown"
    fi
  elif [[ "${LOCAL_NODE_TYPE}" == "controller" ]] ; then
    # If local node is a controller, use MO queries to fetch remote node details.
    REMOTE_NODE_INFO=$(moquery -c fabricNode -x "query-target-filter=eq(fabricNode.id,\"${REMOTE_NODE_ID}\")" -o json | jq '.imdata[].fabricNode' | tr '\n' ' ')

    REMOTE_HOSTNAME=$(echo "${REMOTE_NODE_INFO}" | jq -r '.attributes.name')
    REMOTE_NODE_TYPE=$(echo "${REMOTE_NODE_INFO}" | jq -r '.attributes.role')
    REMOTE_POD_ID=$(echo "${REMOTE_NODE_INFO}" | jq -r '.attributes.dn' | egrep -o "pod-[0-9]+" | cut -d '-' -f 2)
    REMOTE_IP=$(echo "${REMOTE_NODE_INFO}" | jq -r '.attributes.address')
    REMOTE_SOFTWARE_RELEASE=$(echo "${REMOTE_NODE_INFO}" | jq -r '.attributes.version' | sed -e "s#(\([^)][^)]*\))#.\1#g")
  fi

  # Log the gathered remote node details.
  log "info" "gather_remote_node_details: Remote Node Details: Hostname=${REMOTE_HOSTNAME}, Type=${REMOTE_NODE_TYPE}, Node ID=${REMOTE_NODE_ID}, Pod ID=${REMOTE_POD_ID}, IP=${REMOTE_IP}, Software Release=${REMOTE_SOFTWARE_RELEASE}"

  # Cleanup local variable.
  unset REMOTE_NODE_INFO
}

# This function reset details about the remote node.
# relevant global variables.
reset_remote_node_details() {

  log "info" "reset_remote_node_details: Starting to identify remote node details."

  # Hostname of the remote node.
  REMOTE_HOSTNAME=""

  # Defines the type of the remote device - can be controller, leaf, spine, or unknown.
  REMOTE_NODE_TYPE=""

  # Identifier for the remote node.
  REMOTE_NODE_ID=""

  # Identifier for the remote pod.
  REMOTE_POD_ID=""

  # IP address used for VTEP on the remote node.
  REMOTE_IP=""

  # Software version/release on the remote node.
  REMOTE_SOFTWARE_RELEASE=""

}


#=================#
# FUNCTIONS - SSH #
#=================#

# Sets up the SSH command for remote connections based on the local node type and user mode.
# relevant global variables.
configure_remote_ssh() {
  
  # Verify if LOCAL_NODE_TYPE is already set. If not, fetch the details.
  if [ -z "${LOCAL_NODE_TYPE}" ] ; then
    log "info" "configure_remote_ssh: Fetched local node details as LOCAL_NODE_TYPE was not set."
    gather_local_node_details
  fi

  # The command ssh vrf overlay-1 specification is currently not available for leaf/spine.
  # Hence, we only configure SSH for controllers.
  if [ "${LOCAL_NODE_TYPE}" == "controller" ] ; then

    # If REMOTE_NODE_ID is provided, proceed with SSH configuration.
    if [ -n "${REMOTE_NODE_ID}" ] ; then

      # Retrieve remote node details.
      gather_remote_node_details

      # TAC mode SSH configuration.
      if [ "${TAC_USER}" == "true" ] ; then

        # Check if the root password is set. If not, prompt for TAC credentials.
        if [ -z "${ROOT_PASSWORD}" ] ; then
          log "info" "configure_remote_ssh: Prompted for TAC credentials as ROOT_PASSWORD was not set."
          prompt_for_tac_credentials
          
        fi

        # Configure SSH with the root password.
        SSH_REMOTE_COMMAND="sshpass -p ${ROOT_PASSWORD} ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o StrictHostKeyChecking=no root@${REMOTE_IP} "
        log "info" "configure_remote_ssh: SSH command configured in TAC mode for remote IP: ${REMOTE_IP}"

      # User mode SSH configuration.
      else

        # If either USER or PASSWORD is unset, prompt the user for credentials.
        if [ -z "${USER}" ] || [ -z "${PASSWORD}" ] ; then
          prompt_for_user_credentials
          log "info" "configure_remote_ssh: Prompted for user credentials as they were not set."
        fi

        # Configure SSH with the provided user credentials.
        SSH_REMOTE_COMMAND="sshpass -p ${PASSWORD} ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o StrictHostKeyChecking=no ${USER}@${REMOTE_IP} "
        log "info" "configure_remote_ssh: SSH command configured in user mode for remote IP: ${REMOTE_IP}"

      fi

    else
      log "err" "configure_remote_ssh: REMOTE_NODE_ID is not set."
      exit_due_to_code_issue
    fi

  else
    log "err" "configure_remote_ssh: Local node type is unkown/leaf/spine. Currently it is not supported."
    exit_due_to_code_issue
  fi

}

# Verifies the connectivity of the remote SSH session.
check_remote_ssh_alive() {
  # Check if the SSH_REMOTE_COMMAND is defined.
  if [ -n "${SSH_REMOTE_COMMAND}" ] ; then

    # Execute a simple echo command remotely to test the SSH connectivity.
    local SSH_TEST_RESULT=$(${SSH_REMOTE_COMMAND}"echo Connectivity test" 2> /dev/null)

    # Check the result of the SSH test command.
    if [ -n "${SSH_TEST_RESULT}" ] ; then
      BOOLEAN="true"
      log "info" "check_remote_ssh_alive: SSH session is active."
    else
      log "warning" "check_remote_ssh_alive: SSH session is not active second try in 10s."

      sleep 2s

      SSH_TEST_RESULT=$(${SSH_REMOTE_COMMAND}"echo Connectivity test" 2> /dev/null)
      if [ -n "${SSH_TEST_RESULT}" ] ; then
        BOOLEAN="true"
        log "info" "check_remote_ssh_alive: SSH session is active."
      else
        BOOLEAN="false"
        log "err" "check_remote_ssh_alive: SSH session is not active."
      fi

    fi

    unset SSH_TEST_RESULT

  else
    log "err" "check_remote_ssh_alive: SSH_REMOTE_COMMAND is not set. Can't check connectivity."
    exit_due_to_code_issue
  fi
}

# Sends a command to the remote SSH session.
# Arguments:
#   COMMAND: The command to be executed remotely.
send_remote_command() {

  # Ensure SSH configuration exists or set it up if required.
  if [ -z "${SSH_REMOTE_COMMAND}" ] && [ -n "${REMOTE_NODE_ID}" ] ; then
    configure_remote_ssh
  fi

  # Proceed if the SSH_REMOTE_COMMAND is configured.
  if [ -n "${SSH_REMOTE_COMMAND}" ] ; then
    local COMMAND="$1"

    # Verify if the remote session is still active.
    check_remote_ssh_alive

    if [ "${BOOLEAN}" == "true" ] ; then

      # Execute the remote command and store its result.
      READ_VALUE=$(${SSH_REMOTE_COMMAND}"${COMMAND}" 2> /dev/null)

      log "info" "send_remote_command: Successfully executed remote command: ${COMMAND}."
    else
      # Log and handle an expired or wrong password scenario.
      log "err" "send_remote_command: Remote SSH session is inactive for the command: ${COMMAND}. Password might be expired or incorrect."
      exit_password_expired_or_wrong
    fi

    # Clean up the local variable.
    unset COMMAND

  else
    log "err" "send_remote_command: SSH_REMOTE_COMMAND is not set. Unable to send remote command."
    exit_due_to_code_issue
  fi

}

#=====================#
# FUNCTIONS - Moquery #
#=====================#

# Retrieves the Distinguished Names (DNs) for a specific fault.
# Arguments:
#   FAULT_CODE: The code of the fault for which the DNs are to be fetched.
moquery_dn_fault() {

  # Check if the argument count is 1.
  if [ "$#" -ne "1" ] ; then
    log "err" "moquery_dn_fault: Invalid number of arguments provided. Expected 1 but got $#."
    exit_due_to_code_issue
  fi

  local FAULT_CODE="$1"
  local FAULT_COUNT=""

  # Fetch the count of the given fault code.
  FAULT_COUNT=$(moquery -c faultInst -x "query-target-filter=and(eq(faultInst.code,\"${FAULT_CODE}\"),eq(faultInst.lc,\"raised\"))" -x "rsp-subtree-include=count" \
  | egrep "^count" | egrep -o "[0-9]+$" | sed -e "s#\"##g")

  if [ "${FAULT_COUNT}" -gt 0 ] ; then
    # If fault exists, fetch its Distinguished Names (DNs).
    READ_VALUE=$(moquery -c faultInst -x "query-target-filter=and(eq(faultInst.code,\"${FAULT_CODE}\"),eq(faultInst.lc,\"raised\"))" | egrep "^dn" \
    | sed -e "s#^dn  *:  *##g" -e "s#\"##g" -e "s#  *# #g" -e "s#^ *##g" -e "s# *\$##g" | tr '\n' ' ' )
    log "info" "moquery_dn_fault: Successfully fetched DNs for fault code: ${FAULT_CODE} | count: ${FAULT_COUNT}."
  else
    # If no fault exists, set an empty value.
    READ_VALUE=""
    log "info" "moquery_dn_fault: No fault found for code: ${FAULT_CODE}."
  fi

  # Clean up the local variables.
  unset FAULT_CODE FAULT_COUNT
}

# Retrieves the Distinguished Names (DNs) for multiple faults.
# Arguments:
#   FAULT_CODES: A string containing multiple fault codes separated by spaces for which the DNs are to be fetched.
moquery_dn_faults() {

  # Check if the argument count is 1.
  if [ "$#" -ne "1" ] ; then
    log "err" "moquery_dn_faults: Invalid number of arguments provided. Expected 1 but got $#."
    exit_due_to_code_issue
  fi

  local FAULT_CODES="$1"
  local STORE_DNS=""

  # Logging the function completion.
  log "info" "moquery_dn_faults: Fetched DNs for fault codes: ${FAULT_CODES}."

  # Loop over each fault code and retrieve its DNs.
  for FAULT_CODE in $(echo "${FAULT_CODES}"); do
    moquery_dn_fault "${FAULT_CODE}"
    
    if ! [ -z "${READ_VALUE}" ] ; then
      STORE_DNS="${STORE_DNS} ${READ_VALUE}"
    fi
  done

  # Trim leading and trailing spaces.
  READ_VALUE=$(echo "${STORE_DNS}" | sed -e "s#^ *##g" -e "s# *\$##g")

  # Clean up the local variables.
  unset FAULT_CODES STORE_DNS FAULT_CODE
}

# Extracts the node ID from the given Distinguished Name (DN).
# Arguments:
#   DN: A string containing the Distinguished Name to be parsed.
# relevant global variable: REMOTE_NODE_ID.
extract_node_id_from_dn() {

  # Check if the argument count is 1.
  if [ "$#" -ne "1" ] ; then
    log "err" "extract_node_id_from_dn: Invalid number of arguments provided. Expected 1 but got $#."
    exit_due_to_code_issue
  fi

  local DN="$1"

  # Extract node id from the DN if it exists.
  if [ $(echo "${DN}" | egrep -o "/node-[0-9]+" | wc -l) -gt 0 ] ; then
    REMOTE_NODE_ID=$(echo "${DN}" | egrep -m 1 -o "/node-[0-9]+" | awk -F '-' '{print $2}')
    log "info" "extract_node_id_from_dn: Extracted node ID ${REMOTE_NODE_ID} from DN: ${DN}."
  else
    log "warn" "extract_node_id_from_dn: No node ID found in DN: ${DN}."
    exit_due_to_code_issue
  fi

  # Clean up the local variables.
  unset DN
  
}

# Checks if the fault with the given Distinguished Name (DN) has its status set to "raised".
# Arguments:
#   DN: The Distinguished Name of the fault.
is_fault_status_raised() {

  # Check if the argument count is 1.
  if [ "$#" -ne "1" ] ; then
    log "err" "is_fault_status_raised: Invalid number of arguments provided. Expected 1 but got $#."
    exit_due_to_code_issue
  fi

  local DN="$1"

  # Extract fault status using moquery and parse using jq.
  local FAULT_STATUS=$(moquery --dn "${DN}" -o json | jq -r '.imdata[].faultInst.attributes.lc')
  
  # Determine the boolean result based on the fault status.
  if [ "${FAULT_STATUS}" == "raised" ] ; then
    BOOLEAN="true"
    log "info" "is_fault_status_raised: The fault with DN ${DN} has its status set to raised."
  else
    BOOLEAN="false"
    log "info" "is_fault_status_raised: The fault with DN ${DN} does not have its status set to raised."
  fi

  # Clean up local variables.
  unset DN
  unset FAULT_STATUS

}

#=============================#
# FUNCTIONS - SOFWARE RELEASE #
#=============================#

# Compares two software release versions and checks if one is newer, older, or the same as the other.
# Arguments:
#   SOFTWARE_RELEASE_1: The first software release version to be compared.
#   SOFTWARE_RELEASE_2: The second software release version to be compared.
#
# Returns:
# - SOFTWARE_RELEASE_1 == SOFTWARE_RELEASE_2: 0
# - SOFTWARE_RELEASE_1 > SOFTWARE_RELEASE_2: 1
# - SOFTWARE_RELEASE_1 < SOFTWARE_RELEASE_2: -1
compare_software_versions() {

  # Ensure that exactly two arguments are provided.
  if [ "$#" -ne "2" ] ; then
    log "err" "compare_software_versions: Incorrect number of arguments. Expected 2, received $#."
    exit_due_to_code_issue
    return
  fi

  local SOFTWARE_VERSION_1=$(echo "$1" | sed -e "s#^ *##g" -e "s# *\$##g" -e "s#(\([^)][^)]*\))#.\1#g")
  local SOFTWARE_VERSION_2=$(echo "$2" | sed -e "s#^ *##g" -e "s# *\$##g" -e "s#(\([^)][^)]*\))#.\1#g")

  log "info" "compare_software_versions: Comparing versions ${SOFTWARE_VERSION_1} and ${SOFTWARE_VERSION_2}."

  # Check if both versions are the same.
  if [ "${SOFTWARE_VERSION_1}" == "${SOFTWARE_VERSION_2}" ] ; then
    READ_VALUE="0"
    log "info" "compare_software_versions: The software versions are identical."
  else
    # Determine which version is newer.
    local HIGHEST_VERSION=$(echo -e "${SOFTWARE_VERSION_1}\n${SOFTWARE_VERSION_2}" | sort -r -V | head -n 1)

    if [ "${HIGHEST_VERSION}" == "${SOFTWARE_VERSION_1}" ] ; then
      READ_VALUE="1"
      log "info" "compare_software_versions: Version ${SOFTWARE_VERSION_1} is newer than ${SOFTWARE_VERSION_2}."
    else
      READ_VALUE="-1"
      log "info" "compare_software_versions: Version ${SOFTWARE_VERSION_2} is newer than ${SOFTWARE_VERSION_1}."
    fi
  fi

  # Cleanup local variables to free up memory.
  unset SOFTWARE_VERSION_1
  unset SOFTWARE_VERSION_2
  unset HIGHEST_VERSION
}


#===================================================================================================================================================================#

#=======================#
# FUNCTIONS - ARGUMENTS #
#=======================#

# Displays help menu for the script aci-exceeded-storage-allocation.
menu_help() {
  
  # Function to display the title in a clear and consistent format.
  display "aci-exceeded-storage-allocation"
  
  # Describe the purpose and usage of the script.
  cat <<EOL
Usage:
  Check faults associated with exceeded storage (F1527, F1528, and F1529) and determine the associated mount point and filesystems.

Options:
  -u, --user        Define the user.
  -p, --pwd         Define the user's password.
  -r, --root-pwd    Define the root password.
  -t, --tac         Flag for TAC usage.
  -h, --help        Show this help message.

Examples:
  ./aci-exceeded-storage-allocation

  ./aci-exceeded-storage-allocation --user "{{USER}}" --pwd '{{PASSWORD}}'

  ./aci-exceeded-storage-allocation --tac --root-pwd "MEQCIAP+JMXdMqOPUkrkavwhgFFl/6KrZEO6snWtirFiiy9vAiB6ubkkb3lT+wA8YlmwzXLeNz5didzH3Vu8lQrp8OMVUw=="
EOL
}

 # Parses the command line arguments.
parse_args() {
  
  # Use getopt to parse the provided arguments.
  local OPTIONS
  OPTIONS=$(getopt -l "user:,pwd:,root-pwd:,tac,help" -o "u:p:r:th" -a -- "$@")
  
  # Ensure no error occurred while parsing.
  if [ $? -ne 0 ] ; then
    log "err" "parse_args: Error in the options, see --help for more information."
    exit 0
  fi

  # Evaluate parsed options and set corresponding variables.
  eval set -- "$OPTIONS"
  
  while true; do
    case "${1}" in
      -u|--user)
        USER="${2}"
        shift
        ;;
      -p|--pwd)
        PASSWORD="${2}"
        shift
        ;;
      -r|--root-pwd)
        ROOT_PASSWORD="${2}"
        shift
        ;;
      -t|--tac)
        TAC_USER="true"
        ;;
      -h|--help)
        menu_help
        exit 1
        ;;
      --)
        shift
        break
        ;;
      *)
        # Should not occur.
        log "err" "parse_args: Unknown option encountered."
        exit_due_to_code_issue
        ;;
    esac
    shift
  done
}

#================================================================================================================================================================#

################################################     
# MAIN PROGRAM - Fault: F1527, F1528 and F1529 #
################################################


##############################################
# FUNCTIONS - MAIN PROGRAM - TREAT DEFECT(S) #
##############################################

# Defect(s) : CSCwe09535
# ---------------------- 
# Directory(ies): /var/tmp/oci*
# Directory(ies): /data2/third-party/containers/tmp/oci*
# Reference(s): https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe09535
STORE_DEFECT_CSCwe09535_CPT=0
STORE_DEFECT_CSCwe09535=()
CSCwe09535() {


  # Local variable for the passed directory path
  local PATH_MOUNT="$1"

  # Log the initiation of the process
  log "info" "Starting the process for the /techsupport path."

  # Validate that the correct number of arguments are provided
  if [ "$#" -ne 1 ] ; then
    log "err" "Invalid number of arguments provided. Expected 2, received $#."
    exit_due_to_code_issue
  fi

  # Ensure this function is run by a TAC user on a controller with an appropriate software version.
  if [ "${TAC_USER}" == "true" ] && [ "${REMOTE_NODE_TYPE}" == "controller" ] ; then

    # Display the defect being handled.
    display "Checking the defect: CSCwe09535"
    log "info" "CSCwe09535: Checking the defect: CSCwe09535"  

    # Helper function to process the defect on one specific directory.
    # Arguments:
    #   TARGET_DIR: The target directory to check for the defect.
    process_defect_on_directory() {
      local TARGET_DIR="$1"  # The target directory to inspect for the defect.
      local TARGET_COUNT=0  # Count of defect occurrences in the target directory.

      log "info" "process_defect_on_directory: Checking defect in directory ${TARGET_DIR}."

      # Check for presence of the problematic directories.
      send_remote_command "ls -d ${TARGET_DIR} 2> /dev/null | egrep \"oci[0-9]+\" | wc -l"
      TARGET_COUNT=$(( ${TARGET_COUNT} + ${READ_VALUE} ))
      
      echo -e "\nChecking directory(ies): ${TARGET_DIR} \n"
      echo -e "\n ==> \"${TARGET_COUNT}\" directory(ies) detected.\n"

      # If problematic directories found, delete them and re-check.
      if [ "${TARGET_COUNT}" -gt 0 ] ; then

        display "CSCwe09535 Hits"

        display "To fix the defect you need to performs the following steps during a maintenance windows:"

        display "1. connect as root user on \"${REMOTE_HOSTNAME}\"."

        display "2. ls -d ${TARGET_DIR} 2> /dev/null | egrep \"oci[0-9]+\" | xargs -I {} rm -rf {} "

        display "3. reboot the contoller \"${REMOTE_HOSTNAME}\"."

      else
        display "CSCwe09535 No Hits"
      fi

      # Store results about the defect.
      if [ "${TARGET_COUNT}" -gt 0 ] ; then
        log "info" "process_defect_on_directory: Defect CSCwe09535 detected in directory ${TARGET_DIR}."
        STORE_DEFECT_CSCwe09535[${STORE_DEFECT_CSCwe09535_CPT}]="${REMOTE_NODE_ID}:CSCwe09535:hit"
      else
        log "info" "process_defect_on_directory: No defect detected in directory ${TARGET_DIR}."
        STORE_DEFECT_CSCwe09535[${STORE_DEFECT_CSCwe09535_CPT}]="${REMOTE_NODE_ID}:CSCwe09535:no hit"
      fi
      STORE_DEFECT_CSCwe09535_CPT=$((STORE_DEFECT_CSCwe09535_CPT+1))
      
      # Clear local variables.
      unset TARGET_DIR
      unset TARGET_COUNT
    }
  
    # Check if the defect has been tested.
    local CSCwe09535_CPT
    local CSCwe09535_TESTED="false"

    for CSCwe09535_CPT in $(seq 1 ${STORE_DEFECT_CSCwe09535_CPT}) ; do
      if [ $(echo "STORE_DEFECT_CSCwe09535[${CSCwe09535_CPT}]" | egrep -i "^${REMOTE_NODE_ID}:CSCwe09535:" | wc -l) -eq 1 ] ; then
        CSCwe09535_TESTED="true"
      fi
    done

    if [ "${CSCwe09535_TESTED}" == "false" ] ; then

      compare_software_versions "${REMOTE_SOFTWARE_RELEASE}" "6.0.2h"
      if [ "${READ_VALUE}" -lt 0 ] ; then

        # Check for the defect on the /var/tmp/oci* directory.
        if [ "${PATH_MOUNT}" == "/" ] ; then 
          process_defect_on_directory "/var/tmp/oci*"
        fi

        # Check for the defect on the /data2/third-party/containers/tmp/oci* directory.
        if [ "${PATH_MOUNT}" == "/data2" ] ; then 
          process_defect_on_directory "/data2/third-party/containers/tmp/oci*"
        fi

      else
        log "info" "CSCwe09535: Software ${REMOTE_SOFTWARE_RELEASE} not affected by defect."
      fi

    else
      log "info" "CSCwe09535: ${REMOTE_NODE_ID}:CSCwe09535:already tested."
    fi

    # Clear the local variables.
    unset CSCwe09535_CPT CSCwe09535_TESTED

  else
    log "info" "CSCwe09535: Not processing - either not a TAC user or not a controller."
  fi

  # Clear the local variables.
  unset PATH_MOUNT
}


# Defect(s) : CSCvt98738
# ---------------------- 
# File(s): vsvc_ifc_{{DME_SERVICE}}.bin.log.{{ROTATION_NUMBER}} didn't been removed after compression.
# Reference(s): https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt98738
STORE_DEFECT_CSCvt98738_CPT=0
STORE_DEFECT_CSCvt98738=()
CSCvt98738(){

  # User/Root access is required to check the defect.
  if [ "${TAC_USER}" == "true" ] && [ "${REMOTE_NODE_TYPE}" == "controller" ] ; then

    # Display the defect being handled.
    display "Checking the defect: CSCvt98738" 
    log "info" "CSCvt98738: Checking the defect: CSCvt98738" 

    process_defect_on_directory() {
      local TARGET_DIR="$1" 
      local TARGET_COUNT=0
      local TARGET_FILE
      local TARGET_FILES
      local ONE_HOURS_TO_SECONDS=$(( 1 * 60 * 10 ))
      local DELETED_FILES

      # Retrieve all log files that have an associated .gz (compressed) file.
      send_remote_command "ls ${TARGET_DIR} | egrep \"\.gz\$\" | egrep -o \"^.*\.log\" | sort | uniq"
      LOG_FILES=${READ_VALUE}

      # Retrieve all log file rotations that haven't started compression yet and take the modify timestamp in seconds.      
      send_remote_command "ls ${TARGET_DIR} | egrep \"$(echo "${LOG_FILES}" | sed -e "s#^\(.*\)\$#\1.[0-9]+\$#g" | tr "\n" "|" | sed -e "s#|\$##g")\" \
      | xargs -n 1 -I {} bash -c 'echo \"{} \$(date --date \"\$(stat ${TARGET_DIR}{} | grep \"Modify\" | sed -e \"s#Modify: ##g\" -e \"s#\\..*\\\$##g\" | tr \" \" \"T\")\" +%s)\"'"
      TARGET_FILES=$READ_VALUE
  
      for LOG_FILE in $(echo "${LOG_FILES}") ; do

        # Retrieve the modification timestamp for the current log file.
        send_remote_command "date --date \"\$(stat ${TARGET_DIR}${LOG_FILE} | grep \"Modify\" | sed -e \"s#Modify: ##g\" -e \"s#\\..*\\\$##g\" | tr \" \" \"T\")\" +%s"
        local LOG_FILE_TIMESTAMP_MODIFY=${READ_VALUE}

        # Iterate through associated rotated versions of the log file.
        for TARGET_FILE in $(echo "${TARGET_FILES}" | egrep -o "${LOG_FILE}\.[0-9]+") ; do

          # Retrieve the modification timestamp for each rotated version.
          local TARGET_TIMESTAMP_MODIFY=$(echo "${TARGET_FILES}" | egrep -o "${TARGET_FILE} [0-9]+" | awk '{print $2}')

          # If a valid timestamp exists for the rotated version, proceed with the comparison.
          if [ -n "${TARGET_TIMESTAMP_MODIFY}" ] ; then

            # Compute the time difference between the original and its rotated version.
            local DIFFERENCE_FILE_TIMESTAMP=$(( ${LOG_FILE_TIMESTAMP_MODIFY}  - ${TARGET_TIMESTAMP_MODIFY}))

            # If the time difference is greater than one hour, log the potential deletion.
            if [ "${DIFFERENCE_FILE_TIMESTAMP}" -gt "${ONE_HOURS_TO_SECONDS}" ] ; then
              
              # Store the file in the list of files to be deleted.
              DELETE_FILES="${DELETE_FILES} ${TARGET_DIR}${TARGET_FILE}"

              # Increment the count of files to be deleted.              
              TARGET_COUNT=$(( ${TARGET_COUNT} + 1 ))

              log "info" "CSCvt98738: File deleted: ${TARGET_FILE}"
              display "CSCvt98738: File deleted: ${TARGET_FILE}"

            else
              
              log "info" "CSCvt98738: File correct: ${TARGET_FILE}"
              display "CSCvt98738: File correct: ${TARGET_FILE}"

            fi
          fi

          # Clean up local variables for efficiency.
          unset TARGET_TIMESTAMP_MODIFY DIFFERENCE_FILE_TIMESTAMP
        done

        # Clean up the log file's timestamp variable.
        unset LOG_FILE_TIMESTAMP_MODIFY

      done

      # Release variables containing log file information.
      unset LOG_FILES TARGET_FILES LOG_FILE

      # Record the results of the defect check.
      if [ "${TARGET_COUNT}" -gt 0 ] ; then

        # Delete the files.
        DELETE_FILES=$(echo "${DELETE_FILES}" | sed -e "s#^  *##g")

        send_remote_command "rm -f ${DELETE_FILES} 2> /dev/null"

        # Test the files have been deleted
        send_remote_command "ls ${DELETE_FILES} 2> /dev/null | wc -l"
        if [ "${READ_VALUE}" -gt 0 ] ; then
          log "err" "CSCvt98738: Files remained: \"${READ_VALUE}\""
          display "CSCvt98738 Hits and not fixed"

        else

          log "info" "CSCvt98738: Files remained: \"${READ_VALUE}\""
          display "CSCvt98738 Hits and fixed"

        fi

        STORE_DEFECT_CSCvt98738[${STORE_DEFECT_CSCvt98738_CPT}]="${REMOTE_NODE_ID}:CSCvt98738:hit"

        BOOLEAN_SLEEP="true"
      else

        display "CSCvt98738 No Hits"

        STORE_DEFECT_CSCvt98738[${STORE_DEFECT_CSCvt98738_CPT}]="${REMOTE_NODE_ID}:CSCvt98738:no hit"
      fi

      # Increment the defect check counter.
      STORE_DEFECT_CSCvt98738_CPT=$((STORE_DEFECT_CSCvt98738_CPT+1))  

    }

    local CSCvt98738_CPT
    local CSCvt98738_TESTED="false"

    for CSCvt98738_CPT in $(seq 1 ${STORE_DEFECT_CSCvt98738_CPT}) ; do
      if [ $(echo "STORE_DEFECT_CSCvt98738[${CSCvt98738_CPT}]" | egrep -i "^${REMOTE_NODE_ID}:CSCvt98738:" | wc -l) -eq 1 ] ; then
        CSCvt98738_TESTED="true"
      fi
    done

    if [ "${CSCvt98738_TESTED}" == "false" ] ; then
      compare_software_versions "${REMOTE_SOFTWARE_RELEASE}" "5.2.3e"
      if [ "${READ_VALUE}" -lt 0 ] ; then

        # Search the folder with the svc_if_{{DME}}.log
        send_remote_command "find /data/ /var -type f 2> /dev/null | grep -E \"svc_ifc_[a-zA-Z.]+\.log\$\" | sed -e \"s#[^/][^/]*\\\$##g\" | grep -v  -E \"log.lastupgrade|/data/admin/log/\" | sort | uniq"
        local DIRECTORIES=${READ_VALUE}
        for DIRECTORY in $(echo "${DIRECTORIES}") ; do
          process_defect_on_directory "${DIRECTORY}"
        done
        unset DIRECTORIES DIRECTORY
      else
        log "info" "CSCvt98738: Software ${REMOTE_SOFTWARE_RELEASE} not affected by defect."
      fi
    else
      log "info" "CSCvt98738: ${REMOTE_NODE_ID}:CSCvt98738:already tested."
    fi

    # Clear the local variables.
    unset CSCvt98738_CPT CSCvt98738_TESTED

  else
    log "info" "CSCvt98738: Not processing - either not a TAC user or not a controller."
  fi      
}


# Defect(s) : CSCvn13119
# ---------------------- 
# File(s): /MegaSAS.log
# Reference(s): https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn13119
STORE_DEFECT_CSCvn13119_CPT=0
STORE_DEFECT_CSCvn13119=()
CSCvn13119() {

  # Root access is required to check this defect.
  if [ "${TAC_USER}" == "true" ] && [ "${REMOTE_NODE_TYPE}" == "controller" ] ; then

    # Display the defect being handled.
    display "Checking the defect: CSCvn13119"
    log "info" "CSCvn13119: Checking the defect: CSCvn13119"

    process_defect_on_directory() {
      local TARGET_DIR="$1" 
      local TARGET_COUNT=0
      local TARGET_SIZE=""

      # Maximum MegaSAS files
      local MAXIMUM_SIZE=256000

      # Retrieve all MegaSAS files.
      
      send_remote_command "du -sc ${TARGET_DIR}MegaSAS.log* | tail -n 1 | awk '{print \$1}'"
      TARGET_SIZE=${READ_VALUE}

      # Convert the size to the appropriate unit.
      bytes_converter "${TARGET_SIZE} KB" 
      local SIZE=${READ_VALUE}

      # If the total size of the MegaSAS files exceeds the maximum, delete the oldest ones.
      if [ "${TARGET_SIZE}" -gt "${MAXIMUM_SIZE}" ] ; then

          log "info" "CSCvn13119: MegaSAS files size ${SIZE} exceeds the maximum limit. Preparing for deletion."
          
          TARGET_COUNT=$(( ${TARGET_COUNT} + 1 ))

          # Remove tar file
          send_remote_command "ls -t ${TARGET_DIR}MegaSAS.log* | egrep \"\\.gz\$\" | xargs -I {} rm -f {}"
          
          # Clear the file without deleting
          send_remote_command "echo \"\" > ${TARGET_DIR}MegaSAS.log"

          display "MegaSAS files size is exceeded: ${SIZE} - the files have been cleared."

      else
          log "info" "CSCvn13119: MegaSAS files size is ${SIZE}, which is within acceptable limits. No action needed."

          display "MegaSAS files size is not exceeded: ${SIZE}"

      fi

      # Clear local variable.
      unset SIZE

      # Record the results of the defect check.
      if [ "${TARGET_COUNT}" -gt 0 ] ; then
        display "CSCvn13119 Hits and fixed"

        STORE_DEFECT_CSCvn13119[${STORE_DEFECT_CSCvn13119_CPT}]="${REMOTE_NODE_ID}:CSCvn13119:hit"

        BOOLEAN_SLEEP="true"
      else
        display "CSCvn13119 No Hits"

        STORE_DEFECT_CSCvn13119[${STORE_DEFECT_CSCvn13119_CPT}]="${REMOTE_NODE_ID}:CSCvn13119:no hit"
      fi

      # Increment the defect check counter.
      STORE_DEFECT_CSCvn13119_CPT=$((STORE_DEFECT_CSCvn13119_CPT+1))  

      # Clear local variables.
      unset TARGET_DIR TARGET_COUNT MAXIMUM_SIZE TARGET_SIZE
    }

    local CSCvn13119_CPT
    local CSCvn13119_TESTED="false"

    for CSCvn13119_CPT in $(seq 1 ${STORE_DEFECT_CSCvn13119_CPT}); do
      if [ $(echo "STORE_DEFECT_CSCvn13119[${CSCvn13119_CPT}]" | egrep -i "^${REMOTE_NODE_ID}:CSCvn13119:" | wc -l) -eq 1 ] ; then
        CSCvn13119_TESTED="true"
      fi
    done

    if [ "${CSCvn13119_TESTED}" == "false" ]; then
      compare_software_versions "${REMOTE_SOFTWARE_RELEASE}" "4.2.1i"
      if [ "${READ_VALUE}" -lt 0 ] ; then
        process_defect_on_directory "/"
      else
        log "info" "CSCvn13119: Software ${REMOTE_SOFTWARE_RELEASE} not affected by defect."
      fi
    else
      log "info" "CSCvn13119: ${REMOTE_NODE_ID}:CSCvn13119:already tested."
    fi
    
  else
    log "info" "CSCvn13119: Not processing - either not a TAC user or not a controller."
  fi

  # Clear the local variables.
  unset CSCvn13119_CPT CSCvn13119_TESTED

}


#############################################
# FUNCTIONS - MAIN PROGRAM - TREAT FAULT(S) #
#############################################

# Used to allow the controller time to clear the fault
BOOLEAN_SLEEP="false"

# Handle the action of displaying and optionally deleting the largest files.
# The function allows users to view a list of the largest files and then provides
# an option to delete specific ones from the displayed list.
# 
# Args:
#   $1 (OPTIONS): User's operation choice, expected to be "a" for this function.
#   $2 (PATH_MOUNT): Directory from which the largest files will be fetched and potentially deleted.
#   $3 (DN): Distinguished Name for the fault. Used for logging purposes.
handle_largest_files_option() {
  local OPTIONS="$1"
  local PATH_MOUNT="$2"
  local DN="$3"
  local SPACE_DELIMITER="_______________________-_______________________"

  log "info" "handle_largest_files_option: Entered the function."

  # Validate the selected option to ensure it's the right function for the task.
  if [ "${OPTIONS}" != "a" ] ; then
    log "err" "handle_largest_files_option: Incorrect option provided. Expected 'a', received ${OPTIONS}."
    exit_due_to_code_issue
  fi

  # Prompt the user to specify the number of largest files they'd like to see.
  prompt_until_match_or_default "How many of the largest files would you like to see ? (default 20): " "^[0-9]+$" "20"
  local COUNTER_FILE=${READ_VALUE}

  # Execute a command remotely to identify and rank the largest files from the given directory.
  # The files are then processed and displayed to the user.
  send_remote_command "find ${PATH_MOUNT} -type f | xargs -n 1 -I {} du {} | sort -n | tail -n ${COUNTER_FILE} | sort -rn | sed -e \"s#^[0-9][0-9]* *##g\" | xargs -I {} -n 1 du -h {} | sed -e \"s#\t#${SPACE_DELIMITER}#g\"" 
  local BIGGER_FILES=${READ_VALUE}

  # Display the ranked list of files to the user.
  display "The ${COUNTER_FILE} largest files:"

  local CPT=0
  local FILES=()
  # Process each line from the list, extracting relevant file details.
  for LINE in $(echo "${BIGGER_FILES}"); do
    local FILE=$(echo "$LINE" | sed -e "s#${SPACE_DELIMITER}# #g")
    CPT=$((CPT+1))
    FILES[${CPT}]=$(echo "${FILE}" | awk '{print $2}')
    echo -e "${CPT})\t${FILE// / ==> }"
  done

  # If any files were displayed, prompt the user if they'd like to delete any.
  if [ "${CPT}" -gt 0 ] ; then
    prompt_for_yes_no "Would you like to delete some of these files?"
    if [ "${BOOLEAN}" == "y" ] ; then
      # Request user to specify which files they want to delete.
      prompt_select_from_range "Specify the files to delete (e.g., 2,3-5): " "1" "${CPT}"
      local DELETE_FILES=${READ_VALUE}
      
      # For each file selected for deletion, seek user confirmation and then delete.
      for DELETE_FILE in $(echo "${DELETE_FILES}"); do
        if [ "${DELETE_FILE}" -gt 0 ] && [ "${DELETE_FILE}" -le "${COUNTER_FILE}" ] ; then
          prompt_for_yes_no "Please confirm the deletion of file: ${FILES[${DELETE_FILE}]}"
          if [ "${BOOLEAN}" == "y" ] ; then
            send_remote_command "rm -f ${FILES[${DELETE_FILE}]}"

            # Test if the file has been deleted
            send_remote_command "ls ${FILES[${DELETE_FILE}]} 2> /dev/null | wc -l"
            if [ "${READ_VALUE}" -gt 0 ] ; then
              
              log "err" "handle_largest_files_option: File ${FILES[${DELETE_FILE}]} has not been deleted."
              display "File ${FILES[${DELETE_FILE}]} has not been deleted."
            
            else

              BOOLEAN_SLEEP="true"
              log "info" "handle_largest_files_option:File ${FILES[${DELETE_FILE}]} has been deleted."
              display "File ${FILES[${DELETE_FILE}]} has been deleted."
              
              # Note the fault and the corresponding deleted file.
              RECORD_FILES[${RECORD_FILES_CPT}]="${DN}:${FILES[${DELETE_FILE}]}"
              RECORD_FILES_CPT=$((RECORD_FILES_CPT+1))            

            fi

          fi
        fi
      done
    fi
  fi

  # Clean up local variables.
  unset COUNTER_FILE BIGGER_FILES CPT FILES DELETE_FILES SPACE_DELIMITER
}


# Handle displaying and optionally deleting the oldest files from a directory.
# The function allows users to view a list of oldest files and then provides
# an option to delete specific ones from the displayed list.
#
# Args:
#   $1 (OPTIONS): User's operation choice (should be "b" for this function).
#   $2 (PATH_MOUNT): Directory where files are to be checked.
#   $3 (DN): Distinguished Name for the fault (used for logging).
handle_oldest_files_option() {
  local OPTIONS="$1"
  local PATH_MOUNT="$2"
  local DN="$3"
  local SPACE_DELIMITER="_______________________-_______________________"

  # Confirm that the user has selected the correct option.
  if [ "${OPTIONS}" != "b" ] ; then
    log "err" "handle_oldest_files_option: Incorrect option provided. Expected 'a', received ${OPTIONS}."
    exit_due_to_code_issue
  fi

  log "info" "handle_oldest_files_option: Preparing to view and potentially delete oldest files."

  # Prompt the user to specify the number of oldest files they'd like to see.
  prompt_until_match_or_default "How many of the oldest files would you like to display ? (default 20): " "^[0-9]+$" "20"
  local COUNTER_FILE=${READ_VALUE}

  # Use the find command to retrieve and sort files by age.
  # The files are then processed and displayed to the user.
  send_remote_command "find ${PATH_MOUNT} -type f -printf '%T+ %p\n' | sort -n | head -n ${COUNTER_FILE} | sed -e \"s#  *#${SPACE_DELIMITER}#g\""
  local OLDER_FILES=${READ_VALUE}

  display "The ${COUNTER_FILE} oldest files in the directory ${PATH_MOUNT}:"
  echo ""

  local CPT=0
  local FILES=()

  # Extract the older files
  local FILE_SIZE=$(echo "$OLDER_FILES" | awk -F"${SPACE_DELIMITER}" '{print $2}' | tr '\n' ' ')
  
  # Execute a remote command to determine the human-readable size of the older files.
  send_remote_command "du -h ${FILE_SIZE} | awk '{print \$1}'"  
  FILE_SIZE=$READ_VALUE

  # Process each line from the older files list.
  for LINE in $(echo "${OLDER_FILES}"); do
    # Extract the file's timestamp and convert it to a readable format.
    local DATE=$(echo "$LINE" | awk -F"${SPACE_DELIMITER}" '{print $1}' | tr "+" "T" | xargs -I {} date --date {} +"%Yy-%mm-%dd %Hh:%Mmin")
    # Extract the file path.
    local FILE=$(echo "$LINE" | awk -F"${SPACE_DELIMITER}" '{print $2}')
    CPT=$((CPT+1))
    FILES[${CPT}]="${FILE}"

    echo -e "${CPT})\t $(echo "${FILE_SIZE}" | sed -n "${CPT},${CPT}p")\t-\t${DATE}\t\t===>\t${FILE}"
  done

  unset FILE_SIZE

  # If any old files were found, offer the option to delete some of them.
  if [ "${CPT}" -gt 0 ] ; then
    prompt_for_yes_no "Would you like to delete some of these files?"
    if [ "${BOOLEAN}" == "y" ] ; then
      # Ask user to specify which files they want to delete.
      prompt_select_from_range "Specify the files to delete (e.g., 2,3-5): " "1" "${CPT}"
      local DELETE_FILES=${READ_VALUE}
      for DELETE_FILE in $(echo "${DELETE_FILES}"); do
        if [ "${DELETE_FILE}" -gt 0 ] && [ "${DELETE_FILE}" -le "${COUNTER_FILE}" ] ; then
          # Seek confirmation before actually deleting the file.
          prompt_for_yes_no "Please confirm the deletion of file: ${FILES[${DELETE_FILE}]}"
          if [ "${BOOLEAN}" == "y" ] ; then
            # Execute the file deletion.
            send_remote_command "rm -f ${FILES[${DELETE_FILE}]}"

            # Test if the file has been deleted
            send_remote_command "ls ${FILES[${DELETE_FILE}]} 2> /dev/null | wc -l"
            if [ "${READ_VALUE}" -gt 0 ] ; then
              
              log "err" "handle_oldest_files_option: File ${FILES[${DELETE_FILE}]} has not been deleted."
              display "File ${FILES[${DELETE_FILE}]} has not been deleted."
            
            else

              BOOLEAN_SLEEP="true"
              log "info" "handle_oldest_files_option:File ${FILES[${DELETE_FILE}]} has been deleted."
              display "File ${FILES[${DELETE_FILE}]} has been deleted."
              
              # Note the fault and the corresponding deleted file.
              RECORD_FILES[${RECORD_FILES_CPT}]="${DN}:${FILES[${DELETE_FILE}]}"
              RECORD_FILES_CPT=$((RECORD_FILES_CPT+1))            

            fi
          fi
        fi
      done
    fi
  fi

  # Clean up local variables.
  unset OPTIONS PATH_MOUNT DN COUNTER_FILE OLDER_FILES CPT FILES DATE FILE DELETE_FILES DELETE_FILE SPACE_DELIMITER
}

# Handle displaying and optionally deleting the newest files from a directory.
# This function allows users to view a list of the newest files and then provides
# an option to delete specific ones from the displayed list.
#
# Args:
#   $1 (OPTIONS): User's operation choice (should be "c" for this function).
#   $2 (PATH_MOUNT): Directory where files are to be checked.
#   $3 (DN): Distinguished Name for the fault (used for logging).
handle_newest_files_option() {
  local OPTIONS="$1"
  local PATH_MOUNT="$2"
  local DN="$3"
  local SPACE_DELIMITER="_______________________-_______________________"

  log "info" "handle_newest_files_option: Entered."

  # Validate that the user has selected the appropriate option.
  if [ "${OPTIONS}" != "c" ] ; then
    log "err" "handle_newest_files_option: Incorrect option provided. Exiting function."
    exit_due_to_code_issue
  fi

  # Prompt user to specify the number of newest files they'd like to see.
  prompt_until_match_or_default "How many file(s) would you like to see ? (default 20): " "^[0-9]+$" "20"
  local COUNTER_FILE=${READ_VALUE}

  # Use the find command to retrieve and sort files by age in descending order.
  # The newest files are then processed and displayed to the user.
  send_remote_command "find ${PATH_MOUNT} -type f -printf '%T+ %p\n' | sort -rn | head -n \"${COUNTER_FILE}\" | sed -e \"s#  *#${SPACE_DELIMITER}#g\" "
  local NEWER_FILES=${READ_VALUE}

  display "The ${COUNTER_FILE} newest files in the directory ${PATH_MOUNT}:"

  local CPT=0
  local FILES=()

  # Extract the older files
  local FILE_SIZE=$(echo "$NEWER_FILES" | awk -F"${SPACE_DELIMITER}" '{print $2}' | tr '\n' ' ')
  
  # Execute a remote command to determine the human-readable size of the older files.
  send_remote_command "du -h ${FILE_SIZE} | awk '{print \$1}'"  
  FILE_SIZE=$READ_VALUE

  # Process each file in the list.
  for LINE in $(echo "${NEWER_FILES}"); do
    # Extract the file's timestamp and format it for readability.
    local DATE=$(echo "$LINE" | sed -e "s#${SPACE_DELIMITER}# #g" | awk '{print $1}' | tr "+" "T" | xargs -n 1 -I {} date --date {} +"%Yy-%mm-%dd %Hh:%Mmin")
    # Extract the file path.
    local FILE=$(echo "$LINE" | sed -e "s#${SPACE_DELIMITER}# #g" | awk '{print $2}')
    CPT=$((CPT+1))
    FILES[${CPT}]="${FILE}"

    # Display the file's timestamp and path to the user with the file size.
    echo -e "${CPT})\t $(echo "${FILE_SIZE}" | sed -n "${CPT},${CPT}p")\t-\t${DATE}\t\t===>\t${FILE}"
    
  done
  unset FILE_SIZE

  # If any files were found, provide the option to delete some.
  if [ "${CPT}" -gt 0 ] ; then
    prompt_for_yes_no "Would you like to delete some of these files?"
    if [ "${BOOLEAN}" == "y" ] ; then
      # Prompt the user to specify which files they'd like to delete.
      prompt_select_from_range "Specify the files to delete (e.g., 2,3-5): " "1" "${CPT}"
      local DELETE_FILES=${READ_VALUE}

      # For each selected file, seek user confirmation and then delete it.
      for DELETE_FILE in $(echo "${DELETE_FILES}"); do
        if [ "${DELETE_FILE}" -gt 0 ] && [ "${DELETE_FILE}" -le "${COUNTER_FILE}" ] ; then
          prompt_for_yes_no "Please confirm the deletion of file: ${FILES[${DELETE_FILE}]}"
          if [ "${BOOLEAN}" == "y" ] ; then
            send_remote_command "rm -f ${FILES[${DELETE_FILE}]}"

            # Test if the file has been deleted
            send_remote_command "ls ${FILES[${DELETE_FILE}]} 2> /dev/null | wc -l"
            if [ "${READ_VALUE}" -gt 0 ] ; then
              
              log "err" "handle_newest_files_option: File ${FILES[${DELETE_FILE}]} has not been deleted."
              display "File ${FILES[${DELETE_FILE}]} has not been deleted."
            
            else

              BOOLEAN_SLEEP="true"
              log "info" "handle_newest_files_option:File ${FILES[${DELETE_FILE}]} has been deleted."
              display "File ${FILES[${DELETE_FILE}]} has been deleted."
              
              # Note the fault and the corresponding deleted file.
              RECORD_FILES[${RECORD_FILES_CPT}]="${DN}:${FILES[${DELETE_FILE}]}"
              RECORD_FILES_CPT=$((RECORD_FILES_CPT+1))
            fi    
          fi
        fi
      done
    fi
  fi

  # Clean up local variables.
  unset OPTIONS PATH_MOUNT DN COUNTER_FILE NEWER_FILES CPT FILES DATE FILE DELETE_FILES DELETE_FILE SPACE_DELIMITER
}


# handle_firmware_path()
# This function handles operations related to the /firmware path on an ACI device.
# It retrieves the uploaded images from the controller,
# and performs a series of operations like logging, deletion of certain releases, etc.
#
# Arguments:
#   1) PATH_MOUNT: Specifies which directory path is being worked on, e.g., "/firmware".
#   2) REMOTE_SOFTWARE_RELEASE: The software release version that you want to exclude from the list of images.
#
# Global Variables Used:
#   RECORD_FILES: An array that tracks any faults that are detected.
#   RECORD_FILES_CPT: A counter to manage where to insert data in the RECORD_FILES array.
#
handle_firmware_path() {

  # Local variables to capture passed arguments
  local PATH_MOUNT="$1"

  # Log the start of the process
  log "info" "handle_firmware_path: Starting the process for the /firmware path."

  # Ensure the correct number of arguments is passed
  if [ "$#" -ne 1 ] ; then
    log "err" "handle_firmware_path: Invalid number of arguments provided. Expected 1, received $#."
    exit_due_to_code_issue
  fi

  # Define the minimum required number of firmware images
  local MINIMUM_FIRMWARE=4

  # Handle the /firmware path
  if [ "${PATH_MOUNT}" == "/firmware" ] ; then
    log "info" "handle_firmware_path: Working with /firmware path."

    # Fetch the list of software images uploaded on the controller
    local LIST_IMAGES=$(icurl -k "https://127.0.0.1/api/class/firmwareFirmware.json" --silent \
                    | jq '.imdata[].firmwareFirmware.attributes | select( .isoname | match("aci-apic-dk|aci-n9000-dk9")).dn' \
                    | sed "s#\"##g" | grep -v "${REMOTE_SOFTWARE_RELEASE}")

    # Check for insufficient uploaded firmware images and escalate if necessary
    if [ $(echo "${LIST_IMAGES}" | wc -l) -lt "${MINIMUM_FIRMWARE}" ] ; then
      log "warn" "handle_firmware_path: Fewer than \"${MINIMUM_FIRMWARE}\" images uploaded."
      exit_and_escalate_to_TAC_engineer "/firmware requires manual inspection. Fault found with fewer than \"${MINIMUM_FIRMWARE}\" uploaded images."
    else
      # Parse details of uploaded software releases
      log "info" "handle_firmware_path: Parsing software release details."
      local LIST_RELEASES=$(echo "${LIST_IMAGES}" | sed 's#\(n9000[^0-9][^0-9]*\)[0-9]#\1#g' \
                    | egrep -o "[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z]" | sort -n -r | uniq)

      # Display the list of available software releases
      display "Available software releases:"
      local CPT_FIRMWARE=0
      local SOFTWARE_RELEASES=()

      # Loop through each release and display it
      for LINE in ${LIST_RELEASES} ; do
        CPT_FIRMWARE=$(( ${CPT_FIRMWARE} +1 ))
        SOFTWARE_RELEASES[${CPT_FIRMWARE}]="${LINE}"
        echo "${CPT_FIRMWARE}) ${LINE}"
      done

      # Check for user input to delete specific software releases
      if [ "${CPT_FIRMWARE}" -gt 0 ] ; then
        log "info" "handle_firmware_path: Prompting user for releases deletion."
        echo ""
        prompt_for_yes_no "Would you like to delete specific releases?"

        if [ "${BOOLEAN}" == "y" ] ; then
          echo ""
          prompt_select_from_range "Select the releases to be deleted (e.g., 2,3-5): " "1" "${CPT_FIRMWARE}"
          local DELETE_RELEASES=${READ_VALUE}

          # Process deletion for each selected release
          for DELETE_RELEASE in $(echo "${DELETE_RELEASES}") ; do

            if [ "${DELETE_RELEASE}" -ge 1 ] && [ "${DELETE_RELEASE}" -le "${CPT_FIRMWARE}" ] ; then
              log "info" "handle_firmware_path: Confirming deletion for release: ${SOFTWARE_RELEASES[${DELETE_RELEASE}]}."
              echo ""
              prompt_for_yes_no "Please confirm the deletion of release: ${SOFTWARE_RELEASES[${DELETE_RELEASE}]}"
              
              # Find matching images for deletion and process deletion
              if [ "${BOOLEAN}" == "y" ] ; then
                local DELETE_IMAGES=$(echo "${LIST_IMAGES}" | egrep "${SOFTWARE_RELEASES[${DELETE_RELEASE}]}")
                for DELETE_IMAGE in ${DELETE_IMAGES} ; do
                  log "info" "handle_firmware_path: Sending deletion request for ${DELETE_IMAGE}."

                  local HTTP_RESPONSE=$(icurl -k -g -H "Content-Type: application/xml" -H "Accept: application/xml" -X POST \
                                "https://127.0.0.1/api/mo/${DELETE_IMAGE}.xml" --data "<firmwareFirmware deleteIt=\"yes\"/>" \
                                --silent --dump-header - --output /dev/null | egrep -o "^HTTP.*")
                  
                  # Flag deletion for force a sleep timer to allow the controller to clear the fault
                  BOOLEAN_SLEEP="true"

                  # Verify successful image deletion
                  if [ "$(echo "${HTTP_RESPONSE}" | egrep -i "200 OK" | wc -l )" -gt 0 ] ; then
                    log "info" "handle_firmware_path: Successfully deleted ${DELETE_IMAGE}. HTTP Response: ${HTTP_RESPONSE}"
                    display "API: https://127.0.0.1/api/mo/${DELETE_IMAGE}.xml | HTTP Response: ${HTTP_RESPONSE}"
                  else
                    log "err" "handle_firmware_path: Failed to delete ${DELETE_IMAGE}. HTTP Response: ${HTTP_RESPONSE}."
                    exit_and_escalate_to_TAC_engineer "handle_firmware_path: Failed to delete ${DELETE_IMAGE}. HTTP Response: ${HTTP_RESPONSE}."
                  fi

                  # Update the global records for deleted files
                  RECORD_FILES[${RECORD_FILES_CPT}]="${DN}:${FILES[${DELETE_RELEASE}]}"
                  RECORD_FILES_CPT=$((RECORD_FILES_CPT+1))

                done

                # Clean up local variables
                unset DELETE_IMAGE DELETE_IMAGES

              fi
            fi
          done

          # Clean up local variables
          unset DELETE_RELEASE DELETE_RELEASES
        fi
      fi

      # Clean up local variables
      unset CPT_FIRMWARE SOFTWARE_RELEASES LIST_RELEASES

    fi

    # Clean up local variables
    unset LIST_IMAGES

  fi

  # Clean up local variables
  unset MINIMUM_FIRMWARE PATH_MOUNT

}

# handle_techsupport_path()
# This function manages operations related to the /techsupport path on an ACI device.
# It fetches the uploaded tech support files from the controller, evaluates their count, 
# and prompts the user for possible deletions as required.
#
# Arguments:
#   1) PATH_MOUNT: Specifies the directory path to work on, for instance, "/techsupport".
#
# Global Variables Utilized:
#   RECORD_FILES: An array maintaining a record of detected issues.
#   RECORD_FILES_CPT: A counter for handling insertion points in the RECORD_FILES array.

handle_techsupport_path() {
  
  # Local variable for the passed directory path
  local PATH_MOUNT="$1"
  local FAULT="$2"
  local SPACE_DELIMITER="_______________________-_______________________"
  local TAB_DELIMITER="=======================-========================"

  # Log the initiation of the process
  log "info" "Starting the process for the /techsupport path."

  # Validate that the correct number of arguments are provided
  if [ "$#" -ne 2 ] ; then
    log "err" "Invalid number of arguments provided. Expected 2, received $#."
    exit_due_to_code_issue
  fi

  # Define the threshold for minimum required tech support files
  local MINIMUM_TECHSUPPORT=9

  # Operations specific to /techsupport path
  if [ "${PATH_MOUNT}" == "/techsupport" ] ; then
    log "info" "Working on the /techsupport path."

    # Retrieve the list of tech support files present on the controller
    local LIST_TECHSUPPORTS=$(icurl -k "https://127.0.0.1/api/class/dbgexpTechSupStatus.json" --silent \
                    | jq '.imdata[].dbgexpTechSupStatus.attributes | select( .dataType | match("techSupport")) | select( .exportedToController | match("yes")).dn' \
                    | sed "s#\"##g")

    # Alert if there are fewer than the threshold tech support files
    if [ $(echo "${LIST_TECHSUPPORTS}" | wc -l) -lt "${MINIMUM_TECHSUPPORT}" ] ; then
      log "warn" "Detected fewer than 6 techsupport files."
      exit_and_escalate_to_TAC_engineer "/techsupport needs manual inspection due to fewer than 9 tech support files."
    else
      # Extract and sort timestamps of the tech support files
      local LIST_TIMESTAMP=$(echo "${LIST_TECHSUPPORTS}" | sed -e "s#^expcont/expstatus-tsod-\([^/][^/]*\)/inst-\([^.][^.]*\)\..*#\1${SPACE_DELIMITER}==>${SPACE_DELIMITER}\2#g" | sort | uniq)

      # Display the sorted tech support files
      display "Tech support available(s) for the deletion(s):"
      local TECHSUPPORT_COUNT=0
      local TECHSUPPORT_ENTRIES=()

      for LINE in ${LIST_TIMESTAMP} ; do
        TECHSUPPORT_COUNT=$(( ${TECHSUPPORT_COUNT} +1 ))
        TECHSUPPORT_ENTRIES[${TECHSUPPORT_COUNT}]=$(echo "${LINE}" | sed -e "s#${SPACE_DELIMITER}# #g" -e "s#${TAB_DELIMITER}#\t#g")
        echo "${TECHSUPPORT_COUNT}) ${TECHSUPPORT_ENTRIES[${TECHSUPPORT_COUNT}]}"
      done

      # Seek user input for potential deletions of tech support files
      if [ "${TECHSUPPORT_COUNT}" -gt 0 ] ; then
        log "info" "Prompting user for tech support file deletions."
        prompt_for_yes_no "Would you like to delete any of the tech support files?"

        if [ "${BOOLEAN}" == "y" ] ; then
          prompt_select_from_range "Select the files to be deleted (e.g., 2,3-5): " "1" "${TECHSUPPORT_COUNT}"
          local DELETE_SELECTIONS=${READ_VALUE}

          for DELETE_INDEX in $(echo "${DELETE_SELECTIONS}") ; do
            log "info" "Confirming deletion for tech support: ${TECHSUPPORT_ENTRIES[${DELETE_INDEX}]}."
            prompt_for_yes_no "Please confirm the deletion of tech support: ${TECHSUPPORT_ENTRIES[${DELETE_INDEX}]}"
              
            if [ "${BOOLEAN}" == "y" ] ; then
                # Extract the files corresponding to the chosen index for deletion
                local FILES_TO_DELETE=$(echo "${LIST_TECHSUPPORTS}" | egrep "$(echo "${TECHSUPPORT_ENTRIES[${DELETE_INDEX}]}" | egrep -o "[^ ]+$")")

                for FILE_TO_DELETE in ${FILES_TO_DELETE} ; do
                    log "info" "Sending request to delete ${FILE_TO_DELETE}."

                    # Sending a deletion request for the tech support file
                    local HTTP_RESPONSE=$(icurl -k -g -H "Content-Type: application/xml" -H "Accept: application/xml" -X POST \
                        "https://127.0.0.1/api/mo/${FILE_TO_DELETE}.xml" --data "<dbgexpTechSupStatus status=\"deleted\"/>" \
                        --silent --dump-header - --output /dev/null | egrep -o "^HTTP.*")

                    # Flag deletion for force a sleep timer to allow the controller to clear the fault
                    BOOLEAN_SLEEP="true"   

                    # Verify if the tech support file was successfully deleted
                    if [ "$(echo "${HTTP_RESPONSE}" | egrep -i "200 OK" | wc -l )" -gt 0 ] ; then
                        log "info" "Successfully deleted ${FILE_TO_DELETE}. HTTP Response: ${HTTP_RESPONSE}"
                        display "API: https://127.0.0.1/api/mo/${FILE_TO_DELETE}.xml | HTTP Response: ${HTTP_RESPONSE}"

                     
                    else
                        log "err" "Failed to delete ${FILE_TO_DELETE}. HTTP Response: ${HTTP_RESPONSE}."
                        exit_and_escalate_to_TAC_engineer "Failed to delete ${FILE_TO_DELETE}. HTTP Response: ${HTTP_RESPONSE}."
                    fi

                    # Update the global records for deleted files
                    RECORD_FILES[${RECORD_FILES_CPT}]="${FAULT}:${FILE_TO_DELETE}"
                    RECORD_FILES_CPT=$((RECORD_FILES_CPT+1))
                done

                # Cleanup local variables related to deletion
                unset FILES_TO_DELETE FILE_TO_DELETE HTTP_RESPONSE
            fi

          done

          # Local variable cleanup for deletion operations
          unset DELETE_INDEX DELETE_SELECTIONS
        fi
      fi

      # Local variable cleanup for tech support file handling
      unset TECHSUPPORT_COUNT TECHSUPPORT_ENTRIES LIST_TIMESTAMP
    fi

    # Cleanup primary tech support list variable
    unset LIST_TECHSUPPORTS
  fi

  # Cleanup of general variables
  unset PATH_MOUNT FAULT MINIMUM_TECHSUPPORT
}

# handle_coredump_path()
# This function manages operations related to the /techsupport path on an ACI device.
# It fetches the uploaded core dumps from the controller, evaluates their count, 
# and prompts the user for possible deletions as required.
#
# Arguments:
#   1) PATH_MOUNT: Specifies the directory path to work on, for instance, "/techsupport".
#
# Global Variables Utilized:
#   RECORD_FILES: An array maintaining a record of detected issues.
#   RECORD_FILES_CPT: A counter for handling insertion points in the RECORD_FILES array.

handle_coredump_path() {
  
  # Local variable for the passed directory path
  local PATH_MOUNT="$1"
  local FAULT="$2"
  
  # Delimiters used for processing core dump data
  local SPACE_DELIMITER="_______________________-_______________________"
  local TAB_DELIMITER="=======================-========================"
  
  # Start logging the process
  log "info" "Starting the process for the /techsupport path."

  # Ensure correct argument count
  if [ "$#" -ne 2 ] ; then
    log "err" "Invalid number of arguments provided. Expected 2, received $#."
    exit_due_to_code_issue
  fi

  # Threshold for minimum number of core dumps
  local MINIMUM_COREDUMPS=0

  # Proceed only if the provided path is /techsupport
  if [ "${PATH_MOUNT}" == "/techsupport" ] ; then
    log "info" "Working on the /techsupport path."

    # Fetch the list of core dumps present on the controller
    local LIST_COREDUMPS=$(icurl -k "https://127.0.0.1/api/class/dbgexpCoreStatus.json" --silent \
                    | jq '.imdata[].dbgexpCoreStatus.attributes | select( .dataType | match("core")) | select( .exportedToController | match("yes")).dn' \
                    | sed "s#\"##g")

    # Process and list the available core dumps with their timestamps
    local LIST_TIMESTAMP=$(echo "${LIST_COREDUMPS}" \
    | sed -e "s#^expcont/expstatus-coreexp-\([^/][^/]*\)/inst-\([^.][^.]*\)[^/][^/]*/corenode-\([0-9][0-9]*\)#\1${SPACE_DELIMITER}===>${SPACE_DELIMITER}\2${SPACE_DELIMITER}===>${SPACE_DELIMITER}node-\3#g" \
    | sort | uniq)

    # Display the available core dumps
    display "Core dumps available(s) for the deletion(s):"
    local COREDUMP_COUNT=0
    local COREDUMP_ENTRIES=()

    for LINE in ${LIST_TIMESTAMP} ; do
      COREDUMP_COUNT=$(( ${COREDUMP_COUNT} + 1 ))
      COREDUMP_ENTRIES[${COREDUMP_COUNT}]=$(echo "${LINE}" | sed -e "s#${SPACE_DELIMITER}# #g" -e "s#${TAB_DELIMITER}#\t#g")
      echo "${COREDUMP_COUNT}) ${COREDUMP_ENTRIES[${COREDUMP_COUNT}]}"
    done

    # If any core dumps are available, prompt user for possible deletions
    if [ "${COREDUMP_COUNT}" -gt 0 ] ; then
      log "info" "Prompting user for core dump deletions."
      prompt_for_yes_no "Would you like to delete any of the core dumps?"

      if [ "${BOOLEAN}" == "y" ] ; then
        prompt_select_from_range "Select the files to be deleted (e.g., 2,3-5): " "1" "${COREDUMP_COUNT}"
        local DELETE_SELECTIONS=${READ_VALUE}

        # Process deletions for each user-selected core dump
        for DELETE_INDEX in $(echo "${DELETE_SELECTIONS}") ; do
          log "info" "Confirming deletion for core dump: ${COREDUMP_ENTRIES[${DELETE_INDEX}]}."
          prompt_for_yes_no "Please confirm the deletion of core dump: ${COREDUMP_ENTRIES[${DELETE_INDEX}]}"
            
          if [ "${BOOLEAN}" == "y" ] ; then
              # Extract files for deletion based on user confirmation
              local FILES_TO_DELETE=$(echo "${LIST_COREDUMPS}" | \
              egrep "$(echo "${COREDUMP_ENTRIES[${DELETE_INDEX}]}" | egrep -o "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}")" | \
              egrep "$(echo "${COREDUMP_ENTRIES[${DELETE_INDEX}]}" | egrep -o "node-[0-9]+]")"
              )

              # Process deletion for each file
              for FILE_TO_DELETE in ${FILES_TO_DELETE} ; do
                  log "info" "Sending request to delete ${FILE_TO_DELETE}."

                  # Initiate core dump deletion on the controller
                  local HTTP_RESPONSE=$(icurl -k -g -H "Content-Type: application/xml" -H "Accept: application/xml" -X POST \
                      "https://127.0.0.1/api/mo/${FILE_TO_DELETE}.xml" --data "<dbgexpCoreStatus status=\"deleted\"/>" \
                      --silent --dump-header - --output /dev/null | egrep -o "^HTTP.*")

                  # Flag deletion for force a sleep timer to allow the controller to clear the fault
                  BOOLEAN_SLEEP="true" 

                  # Verify the deletion status
                  if [ "$(echo "${HTTP_RESPONSE}" | egrep -i "200 OK" | wc -l )" -gt 0 ] ; then
                      log "info" "Successfully deleted ${FILE_TO_DELETE}. HTTP Response: ${HTTP_RESPONSE}"
                      display "API: https://127.0.0.1/api/mo/${FILE_TO_DELETE}.xml | HTTP Response: ${HTTP_RESPONSE}"
                  else
                      log "err" "Failed to delete ${FILE_TO_DELETE}. HTTP Response: ${HTTP_RESPONSE}."
                      exit_and_escalate_to_TAC_engineer "Failed to delete ${FILE_TO_DELETE}. HTTP Response: ${HTTP_RESPONSE}."
                  fi

                  # Update records of deleted files
                  RECORD_FILES[${RECORD_FILES_CPT}]="${FAULT}:${FILE_TO_DELETE}"
                  RECORD_FILES_CPT=$((RECORD_FILES_CPT+1))
              done
          fi
        done
      fi
    fi

  fi
  
  # Clean up used variables
  unset PATH_MOUNT FAULT MINIMUM_COREDUMPS
}


# Handles and resolves issues related to a specific fault based on its DN.
# Arguments:
#   DN: The Distinguished Name (DN) of the fault to address.
treat_fault() {
  if [ "$#" -eq "1" ] ; then
    local SPACE_DELIMITER="_______________________-_______________________"

    local DN="$1"
    BOOLEAN_SLEEP=0

    # Check if the fault is still present.
    is_fault_status_raised "${DN}"
    if [ "${BOOLEAN}" == "true" ] ; then

      # Display the fault being handled.
      display "Fault: ${DN}"

      # Extract node ID from DN.
      extract_node_id_from_dn "${DN}"

      # Configure SSH.
      configure_remote_ssh

      log "info" "treat_fault: Handling fault with DN: ${DN}. Software Release: ${REMOTE_SOFTWARE_RELEASE}"

      # Parse DN to retrieve mount details.
      local DEV_MOUNT=$(echo "${DN}" | egrep -o "\-f-\[[^]]+]" | sed -e "s#-f-\[\([^]][^]]*\)]#\1#g")
      local PATH_MOUNT=$(echo "${DN}" | egrep -o "p-\[[^]]+]" | sed -e "s#p-\[\([^]][^]]*\)]#\1#g")

      # Address specific defects.
      if [ "${PATH_MOUNT}" == "/" ] || [ "${PATH_MOUNT}" == "/data2" ]   ; then
        CSCwe09535 "${PATH_MOUNT}"
      fi

      if [ "${PATH_MOUNT}" == "/data/log" ] ; then
        CSCvt98738
      fi

      if [ "${PATH_MOUNT}" == "/" ] ; then
        CSCvn13119
      fi
      
      # Determine the executor of the script.
      if [ "${TAC_USER}" != true ] ; then
        log "info" "treat_fault: Operating in USER MODE."

        # Check repositories using REST API: Techsupport, Firmware, Cores
        if [ "${PATH_MOUNT}" == "/firmware" ] ; then

          display "Directory usage for ${PATH_MOUNT}"
          send_remote_command "df -h ${PATH_MOUNT}"
          echo "${READ_VALUE}"

          display "Firmware checks"

          # Handle the firmware checks and possible deletions based on the given path.
          handle_firmware_path "${PATH_MOUNT}" 

        elif [ "${PATH_MOUNT}" == "/techsupport" ] ; then

          display "Directory usage for /data/techsupport"
          send_remote_command "df -h /data/techsupport"
          echo "${READ_VALUE}"

          display "Techsupport checks"

          # Handle the tech support checks and possible deletions based on the given path
          handle_techsupport_path "${PATH_MOUNT}" "${DN}"

          display "Core dump checks"

          # Handle the core dump checks and possible deletions based on the given path
          handle_coredump_path "${PATH_MOUNT}" "${DN}"

        fi

      else

        # Logging the mode of operation.
        log "info" "treat_fault: Operating in TAC MODE."

        display "Directory usage for ${PATH_MOUNT}"
        send_remote_command "df -h ${PATH_MOUNT}"
        echo "${READ_VALUE}"

        local FILE_COUNT
        local OPTIONS

        # Continuously prompt the user until they choose to exit.
        while ! [ "${OPTIONS}" == "e" ] ; do

          # Fetching the count of files in the specified path.
          send_remote_command "find ${PATH_MOUNT} -type f 2> /dev/null | wc -l"
          FILE_COUNT=$(echo "${READ_VALUE} - 1" | bc)

          # Logging the number of files detected.
          log "info" "treat_fault: Detected ${FILE_COUNT} files in ${PATH_MOUNT}."

          # Displaying the count of files in the directory.
          display "Number of files in ${PATH_MOUNT}"
          echo -e "\n ==> In \"${PATH_MOUNT}\": ${FILE_COUNT} files detected.\n"

          # Presenting deletion options to the user.
          echo -e "\nYou can choose from the following file deletion options:\n"
          echo "   a) Delete the largest files."
          echo "   b) Delete the oldest files."
          echo "   c) Delete the newest files."
          echo "   d) Manually select files for deletion."
          echo "   e) Exit."
          echo ""

          # Prompting the user for their preferred deletion criteria.
          prompt_until_match_regex "Which deletion option do you prefer (a,b,c,d,e)? " "^[a-eA-E]$"
          OPTIONS=${READ_VALUE}

          # Switch-like construct to determine which operation to perform based on the user's choice.
          case "${OPTIONS}" in
            a)
              # Option 'a': Handle the largest files.
              # The function will fetch, display, and offer an option to delete the largest files in the given directory.
              handle_largest_files_option "a" "${PATH_MOUNT}" "${DN}"
              ;;
            b)
              # Option 'b': Handle the oldest files.
              # This function will retrieve, show, and provide an option to delete the oldest files in the given directory.
              handle_oldest_files_option "b" "${PATH_MOUNT}" "${DN}"
              ;;
            c)
              # Option 'c': Handle the newest files.
              # The function will gather, display, and propose an option to delete the newest files in the specified directory.
              handle_newest_files_option "c" "${PATH_MOUNT}" "${DN}"
              ;;
            d)
              # Option 'd': Handle the remote SSH.
              ${SSH_REMOTE_COMMAND}
              BOOLEAN_SLEEP="true"
              ;;
            e)
              # Option 'e': Exit.
              log "info" "treat_fault: Exit DN: ${DN}"
              ;;
            *)
              # Logs an error indicating an unsupported option has been provided.
              log "err" "treat_fault: Invalid option ${OPTIONS} provided."
              ;;
          esac

        done

      fi

    else

      # Log that the fault has been cleared.
      log "info" "treat_fault: Fault ${DN} has been cleared."
    
    fi

    if [ "${BOOLEAN_SLEEP}" == "true" ] ; then

      # sleep 90 seconds
      waiting_timer "The fault ${DN} has been treated, waiting 2m30s seconds before checking the next fault(s)." "2m30s"
      
    fi

  fi

}

############################
# FUNCTIONS - MAIN PROGRAM #
############################

# Process storage faults on a controller.
main(){
  log "info" "main: Starting fault processing."

  # Ensure the current node is a controller.
  if [ "${LOCAL_NODE_TYPE}" != "controller" ] ; then
    log "err" "main: Script execution limited to controllers only."
    display "This script is exclusive for controllers."
    return
  fi

  # Initialize storage for removed files and define fault codes to monitor.
  RECORD_FILES=()
  RECORD_FILES_CPT=0
  FAULTS="F1527 F1528 F1529"
  HIT_FAULT="false"  # Flag to detect faults.

  log "info" "main: Retrieving Distinguished Names for faults: ${FAULTS}"
  
  display "loading faults F1527, F1528 and F1529"

  moquery_dn_faults "${FAULTS}"
  DNS="${READ_VALUE}"

  # Check for the presence of faults.
  if [ -z "${DNS}" ] ; then
    log "info" "main: No faults detected for codes: ${FAULTS}"
    echo -e "\nNo faults were detected. Please respond to Sherlock Holmes at <noreply@cisco.com> with the following information:\n"
    display "Sherlock, the faults F1527, F1528, and F1529 were not detected."
    echo -e "\nThank you.\n----------\n\n"
  else
    log "info" "main: $(echo "${DNS}" | tr ' ' '\n' | wc -l) detected faults for code: ${FAULTS}"

    # Display faults according to their fault codes.
    local FAULT
    for FAULT in $(echo "${FAULTS}") ; do 
      display "${FAULT}: $(echo "${DNS}" | tr ' ' '\n' | egrep "${FAULT}$" | wc -l) fault(s) detected."
    done
    unset FAULT

    HIT_FAULT="true"
    for DN in $(echo "${DNS}"); do
      treat_fault "${DN}"
    done
  fi

  # If faults were initially detected, check if they've been fixed.
  if [ "${HIT_FAULT}" == "true" ] ; then
    log "info" "main: Verifying if detected faults have been fixed."
    moquery_dn_faults "${FAULTS}"
    DNS="${READ_VALUE}"

    if [ -z "${DNS}" ] ; then

      # Display separation lines and spaces for clarity
      echo -e "\n\n ====> \n\n"

      log "info" "main: All faults have been fixed."
      echo -e "\nAll the faults have been cleared. Please respond to Sherlock Holmes at <noreply@cisco.com> with the following information:\n"
      display "Sherlock, the faults F1527, F1528, and F1529 have been cleared."
      
      # Detail files removed due to faults.
      while [ "${RECORD_FILES_CPT}" -gt 0 ] ; do
        RECORD_FILES_CPT=$((RECORD_FILES_CPT - 1))
        DN=$(echo "${RECORD_FILES[${RECORD_FILES_CPT}]}" | awk -F ':' '{print $1}')
        FILE=$(echo "${RECORD_FILES[${RECORD_FILES_CPT}]}" | awk -F ':' '{print $2}')
        display "Fault: ${DN} - File removed: ${FILE}"
      done
      
      # Detail detected defects.

      while [ "${STORE_DEFECT_CSCwe09535_CPT}" -gt 0 ] ; do
        STORE_DEFECT_CSCwe09535_CPT=$((STORE_DEFECT_CSCwe09535_CPT - 1))
        DEFECT_NODE=$(echo "${STORE_DEFECT_CSCwe09535[${STORE_DEFECT_CSCwe09535_CPT}]}" | awk -F ':' '{print $1}')
        DEFECT_NAME=$(echo "${STORE_DEFECT_CSCwe09535[${STORE_DEFECT_CSCwe09535_CPT}]}" | awk -F ':' '{print $2}')
        DEFECT_STATUS=$(echo "${STORE_DEFECT_CSCwe09535[${STORE_DEFECT_CSCwe09535_CPT}]}"| awk -F ':' '{print $3}')
        display "Defect: ${DEFECT_NAME} - Node ID: ${DEFECT_NODE} - Status: ${DEFECT_STATUS}"
      done

      while [ "${STORE_DEFECT_CSCvt98738_CPT}" -gt 0 ] ; do
        STORE_DEFECT_CSCvt98738_CPT=$((STORE_DEFECT_CSCvt98738_CPT - 1))
        DEFECT_NODE=$(echo "${STORE_DEFECT_CSCvt98738[${STORE_DEFECT_CSCvt98738_CPT}]}" | awk -F ':' '{print $1}')
        DEFECT_NAME=$(echo "${STORE_DEFECT_CSCvt98738[${STORE_DEFECT_CSCvt98738_CPT}]}" | awk -F ':' '{print $2}')
        DEFECT_STATUS=$(echo "${STORE_DEFECT_CSCvt98738[${STORE_DEFECT_CSCvt98738_CPT}]}"| awk -F ':' '{print $3}')
        display "Defect: ${DEFECT_NAME} - Node ID: ${DEFECT_NODE} - Status: ${DEFECT_STATUS}"
      done

      while [ "${STORE_DEFECT_CSCvn13119_CPT}" -gt 0 ] ; do
        STORE_DEFECT_CSCvn13119_CPT=$((STORE_DEFECT_CSCvn13119_CPT - 1))
        DEFECT_NODE=$(echo "${STORE_DEFECT_CSCvn13119[${STORE_DEFECT_CSCvn13119_CPT}]}" | awk -F ':' '{print $1}')
        DEFECT_NAME=$(echo "${STORE_DEFECT_CSCvn13119[${STORE_DEFECT_CSCvn13119_CPT}]}" | awk -F ':' '{print $2}')
        DEFECT_STATUS=$(echo "${STORE_DEFECT_CSCvn13119[${STORE_DEFECT_CSCvn13119_CPT}]}"| awk -F ':' '{print $3}')
        display "Defect: ${DEFECT_NAME} - Node ID: ${DEFECT_NODE} - Status: ${DEFECT_STATUS}"
      done

      echo -e "\nThank you.\n----------"

      echo -e "\n\n <==== \n\n"

    # The defect CSCwe09535 needs a maintenance window to be fixed.
    elif [ "${STORE_DEFECT_CSCwe09535_CPT}" -gt 0 ] ; then 

      # Display separation lines and spaces for clarity
      echo -e "\n\n ====> \n\n"

      log "info" "main: a maintaince windows is required for the defect CSCwe09535 to clear the fault \"${DNS}\"."
      echo -e "\nA maintenance windows is required. Please respond to Sherlock Holmes at <noreply@cisco.com> with the following information:\n"
      display "Sherlock, we hit the defect CSCwe09535 meaning a maitenance windows with the TAC engineer is required to clear the fault(s) below."


      for DN in $(echo "${DNS}") ; do
        display "Fault: ${DN}"
      done

      echo -e "\nThank you.\n----------"

      echo -e "\n\n <==== \n\n"


    else
      log "err" "main: Remaining unaddressed faults detected."
      exit_and_escalate_to_TAC_engineer "The faults ${DNS} are still remaining."
    fi
  fi
}

# Invoke the function to parse arguments.
parse_args "$@"

# If the user is from TAC, validate their credentials.
if [ "${TAC_USER}" == "true" ] ; then
    echo ""
    validate_tac_credentials
fi

# Display the script's header.
display "Sherlock Campaign - Exceeded Data Storage Issue"

display "Loading node configuration"

# Gathering local node details.
gather_local_node_details

# Main
main

exit 0