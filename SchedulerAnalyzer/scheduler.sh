#!/bin/bash

# -e: if the command fails, exit
# -u: unset var are considered error and exit 
# -f: No filename expension
# -o pipefile: return error on pipe error
set -uf -o pipefail

scriptName="schedulerAnalyzer"

verbose=0
tempfile="/dev/null"

localApicDn="null"
localApicName="null"
localApicId=-1
localApicVersion="null"
apicClusterSize=0
apicContainerRuntime="null"
apicIdArray=()
cri="null"
apicPwd=""
debugToken=$(acidiag dbgtoken)
rootPassword=""
rootPasswordRequired=false

schedulerStatus=""
hit_scheduler_down=false
hit_CSCwa45126=false
hit_CSCvw05302=false
hit_certmismatch=false
hit_F3254=false
attempt_fix=false
check_certs=false

log(){

    local line=""
    local ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S')

    if [ "$#" -gt 0 ] ; then
        if [ "$#" -gt 1 ] ; then

            case $1 in
                "err")
                    # bold red
                    echo -e "\033[1;\033[31m${2}\033[0m"
                ;;
                "alert")
                    # bold yellow
                    echo -e "\033[1;\033[33m${2}\033[0m"
                ;;
                "info")
                    # bold blue
                    echo -e "\033[1;\033[34m${2}\033[0m"
                ;;
                "success")
                    # bold green
                    echo -e "\033[1;\033[32m${2}\033[0m"
                ;;         
                "trace")
                    if (( $verbose >= 1 )) ; then  echo -e "${2}" ; fi
                ;;
                "debug")
                    if (( $verbose > 1 )) ; then echo -e "${2}" ; fi
                ;;
                *)
                    echo -e "$2"
                ;;
            esac
        else
            echo -e "$1"
        fi

  
    fi

}

title(){ log "\n\e[1;44;1;30m $1 \e[0m\n" ; }
subtitle(){ log "→ $1"; }
err(){ log "err" "[x] $1" | pr -to2 ; }
info(){ log "info" "[i] $1" | pr -to2; }
alert(){ log "alert" "[!] $1" | pr -to2 ; }
success(){ log "success" "[√] $1" | pr -to2 ; }
trace(){ log "trace" "$1"; }
debug(){ log "debug" "$1"; }
cmd(){ log "debug" "---\ncmd: $1\n$(eval $1)"; }

generate_tsbundle(){
    # Generate tar archive with the scheduler logs
    # $1 is APIC id 
    
    local filename
    filename="/data/techsupport/Scheduler-$(date +'%F-%T').tgz"

    set +f

    echo "" > /tmp/scheduler_output.log

    echo "---" >> /tmp/scheduler_output.log
    echo "show controller" >> /tmp/scheduler_output.log
    show controller >> /tmp/scheduler_output.log
    
    echo "---" >> /tmp/scheduler_output.log
    echo "acidiag scheduler statusx" >> /tmp/scheduler_output.log
    acidiag scheduler statusx >> /tmp/scheduler_output.log
    
    echo "---" >> /tmp/scheduler_output.log
    echo "ps -eaf | grep logmon" >> /tmp/scheduler_output.log
    ps -eaf | grep logmon >> /tmp/scheduler_output.log
    
    echo "---" >> /tmp/scheduler_output.log
    echo "dmesg | grep forked" >> /tmp/scheduler_output.log
    dmesg | grep forked >> /tmp/scheduler_output.log
    
    echo "---" >> /tmp/scheduler_output.log
    echo "df -h /var/log/dme/log/" >> /tmp/scheduler_output.log
    df -h /var/log/dme/log/ >> /tmp/scheduler_output.log
    
    echo "---" >> /tmp/scheduler_output.log
    echo "stat /var/log/dme/log/av_state.json -c %s" >> /tmp/scheduler_output.log
    stat /var/log/dme/log/av_state.json -c %s >> /tmp/scheduler_output.log

    for apicId in "${apicIdArray[@]}"
    do
        echo "---" >> /tmp/scheduler_output.log
        echo "cat /aci/system/controllers/node-$apicId/processes/summary" >> /tmp/scheduler_output.log
        cat "/aci/system/controllers/node-$apicId/processes/summary" >> /tmp/scheduler_output.log
    done 
 
    tar -cvzf "$filename"  --absolute-names \
        /var/log/dme/log/insieme_fwhdr* \
        /var/log/dme/log/scheduler* \
        /var/log/dme/log/kron* \
        /var/log/dme/log/gen_cert* \
        /var/log/dme/log/scaleout_app_* \
        /var/log/dme/log/nomad* \
        /var/log/dme/log/consul* \
        /var/log/dme/log/kafka* \
        /tmp/scheduler_output.log

    set -f

    rm /tmp/scheduler_output.log
    
    info "A tar.gz archive has been generated under $filename"
}

ask_for_password(){

    # $1 is apicId
    # $2 is username

    local retry=1
    local ret=1

    if [ -z "$apicPwd" ]; then

        info "APIC $1 $2's password is required to continue" 
        read -r -p "  Do you wish to continue? [y/N] " response

        case "$response" in
            [yY][eE][sS]|[yY]) 
            ;;
            *)
                return 1
            ;;
        esac

        # ssh will ret 0 if success 
        while [[ "$ret" -gt 0 && "$retry" -le 3 ]]; do

            read -rsp "  Enter APIC $1's password for $2 (attempt $retry/3): " apicPwd
            sshpass -p "$apicPwd" ssh -F /dev/null -l "$2" "apic$1" -o ConnectTimeout=1 true &>/dev/null
            ret=$?

            trace "SSH password test result: $ret, retry: $retry"

            retry=$((retry+1))
        done

        if [[ "$ret" -gt 0 ]]; then
            return 1
        fi

        # echo -e "${Z}${Z}"
    fi

    return 0

}

ask_for_rootpassword(){

    local retry=1
    local ret=1

    if [ -z "$rootPassword" ]; then

        info "Root password is required to continue (provided by TAC)" 
        read -r -p "  Do you wish to continue? [y/N] " response
        case "$response" in
            [yY][eE][sS]|[yY]) 
            ;;
            *)
                return 1
            ;;
        esac

        # ssh will ret 0 if success 
        while [[ "$ret" -gt 0 && "$retry" -le 3 ]]; do

            info "Root access required, debug token: $debugToken" 
            read -rsp "  Enter root password (attempt $retry/3): " rootPassword

            sshpass -p "$rootPassword" ssh -F /dev/null -l root 0 -o ConnectTimeout=1 true &>/dev/null
            ret=$?

            trace "SSH root password test reslt: $ret, retry: $retry"

            retry=$((retry+1))
        done

        if [[ "$ret" -gt 0 ]]; then
            trace "No successful root password provided, aborting "
            return 1
        fi

    fi

    return 0
}


gather_facts(){

    # Gather facts about local APIC, cluster size etc ...

    local fabricNode
    local infraCont
    local infraContDn

    subtitle "Gathering facts"

    debug "$(cat /data/data_admin/sam_exported.config)"

    localApicId=$(grep -oP "^controllerID\s+=\s+\K(\d+)" /data/data_admin/sam_exported.config)
    trace "localApicId: $localApicId"

    fabricNode=$(icurl -s "http://localhost:7777/api/uni/class/fabricNode.xml?query-target-filter=eq(fabricNode.id, \"$localApicId\")" | xmllint --xpath '/imdata/fabricNode' - )
    if [ $? -gt 0 ]; then
        err "Invalid node id $localApicId"
        exit 1
    fi

    debug "fabricNode: $fabricNode"

    localApicDn=$(xmllint --xpath 'string(/fabricNode/@dn)' - <<< $fabricNode)
    trace "localApicDn: $localApicDn"

    infraCont=$(icurl -s "http://localhost:7777/api/uni/mo/$localApicDn.xml?query-target=subtree&target-subtree-class=infraCont" | xmllint --xpath '/imdata/infraCont' -)
    if [ $? -gt 0 ]; then
        err "No infraCont MO found for dn $localApicDn"
        exit 1
    fi

    debug "infraCont: $infraCont"

    localApicName=$(xmllint --xpath 'string(/fabricNode/@name)' - <<< $fabricNode)
    trace "localApicName: $localApicName"

    localApicVersion=$(xmllint --xpath 'string(/fabricNode/@version)' - <<< $fabricNode)
    trace "localApicVersion: $localApicVersion"

    apicClusterSize=$(xmllint --xpath 'string(/infraCont/@size)' - <<< $infraCont)
    trace "apicClusterSize: $apicClusterSize"
    
    infraContDn=$(xmllint --xpath 'string(/infraCont/@dn)' - <<< $infraCont)
    trace "infraContDn: $infraContDn"

    infraWiNode="$(icurl -s "http://localhost:7777/api/uni/mo/$infraContDn.xml?query-target=subtree&target-subtree-class=infraWiNode&order-by=infraWiNode.id|asc")"
    debug "infraWiNode: $infraWiNode"

    # How many APIC do we have in the cluster, as seen by local APIC
    infraWiNodeCount=$(xmllint --xpath 'count(/imdata/infraWiNode)' - <<< $infraWiNode)
    trace "infraWiNodeCount: $infraWiNodeCount"

    # Gather the APIC Ids in the cluster
    infraWiNodeIds=($localApicId)
    for ((i=1; i<=infraWiNodeCount; i++)); do
        id=$(xmllint --xpath "number(/imdata/infraWiNode[$i]/@id)" - <<< $infraWiNode)
        if [ ! $localApicId -eq $id ]; then
            infraWiNodeIds+=($id)
        fi 
    done

    trace "infraWiNodeIds: ${infraWiNodeIds[*]}"
    
    # if [ $? -gt 0 ]; then
    #     err "No infraWiNode MO found for dn $localApicDn"
    #     exit 1
    # fi

    # Map the infraWiNode ids to an array


    # If apicIdArray is not populated we populate it from the infraWiNode
    if [ -z "${apicIdArray[@]+"${apicIdArray[@]}"}" ]; then
        apicIdArray=("${infraWiNodeIds[@]}")
    # else 
    # TODO: if user already provided a apicId, we must verify it exists in the cluster
    fi

    trace "apicIdArray: ${apicIdArray[*]}"

    # Checking CRI
    if command -v docker &> /dev/null; then
        cri="docker"
    elif command -v podman &> /dev/null; then
        cri="podman"
    else
        cri="null"
        err "Unrecognized container runtime, aborting"
        exit 1
    fi

    trace "cri: $cri"

}

check_cluster_health(){

    # Check if the cluster is healhty and all APICs are available
    # $1: apicId
    # $2: apicDn

    local unhealthyApicsCount
    local unhealthyApics

    subtitle "Verifying cluster health"

    # Grab the count of APIC marked with heath != fully-fit or operSt != available
    unhealthyApicsCount=$(icurl -s "http://localhost:7777/api/uni/mo/$2.xml?query-target=subtree&target-subtree-class=infraWiNode&query-target-filter=or(ne(infraWiNode.health, \"fully-fit\"),ne(infraWiNode.operSt,\"available\"))&rsp-subtree-include=count" | xmllint --xpath 'number(/imdata/moCount/@count)' -)
    trace "unhealthyApicsCount: $unhealthyApicsCount" 

    if [[ $unhealthyApicsCount -gt 0 ]]; then     
        err "Cluster is not healthy, please ensure the cluster is fully-fit and all APICs are available before executing this script"
        exit 1
    fi 

    success "Cluster health is healthy (fully-fit and available)" 
}


check_F3254(){

    # Look for F3254 fault
    # $1: apicId
    # $2: apicDn

    if [[ "$cri" != "podman" ]]; then
        trace "F3254 verification is only performed for podman runtime, current CRI $cri"
        return 0
    fi

    subtitle "Verifying existence of fault F3254"

    faultInstCount="$(icurl -s 'http://localhost:7777/api/node/class/faultInst.xml?query-target-filter=eq(faultInst.code,"F3254")&rsp-subtree-include=count' | xmllint --xpath 'number(/imdata/moCount/@count)' -)"
    trace "faultCount: $faultInstCount"

    # Grab the App name, look into kron.log for "image not known"

    if (( faultInstCount > 0 )); then
        # TODO ... add logs verification logic
        hit_F3254=true
        alert "$faultInstCount fault(s) F3254 identified" 

        # if $attempt_fix ; then
        #     fix_F3254
        # fi

    else
        success "No fault F3254 found" 
    fi
}

fix_F3254(){
    # $1 is apic Id
    local loadinit="null"

    # Need to locate APIC leader for this App

    subtitle "Attempting to fix F3254"

    ask_for_rootpassword
    if (( $? )); then
        log "Aborting F3254 fix"
        return 0
    fi

    # Valid starting  ACI 4.2(3j)
    if (( "$localApicId" == "$1" )); then
        loadinit="$(sshpass -p $rootPassword ssh -tq -l root 0 '/opt/cisco/system-env/bin/python /mgmt/support/insieme/kron/kron_helper.py --loadinit')"
    else
        loadinit="$(sshpass -p $rootPassword ssh -tq -l root apic$1 '/opt/cisco/system-env/bin/python /mgmt/support/insieme/kron/kron_helper.py --loadinit')"
    fi
    
    trace "loadinit: $loadinit"
}

check_scheduler_status(){

    # Check if scheduler status is up on all APICs 
    # If we have >0 False, we have a problem with one service
    # $1: apicId 
    # $2: apicDn

    local apicSchedulerStatus

    if [ "$#" -eq 0 ]; then
        err "check_scheduler_status: Missing apicId args"
        exit 1
    fi

    subtitle "Verifying scheduler status for APIC $1"

    # Example:
    # bdsol-aci13-apic1# acidiag scheduler statusx
    # Scheduler status extended: [DCNnK]
    #  [ False]   Apic-01        [   X ]
    #  [ True ]   Apic-02        [     ]
    #  [ True ]   Apic-03        [     ]
    

    # Note: keep the double quotes around the var, otherwise the CR is trimmed
    debug "$schedulerStatus"
    apicSchedulerStatus="$(echo "$schedulerStatus" | grep -i "apic-0$1" | grep -i 'false')"

    trace "apicSchedulerStatus: $apicSchedulerStatus"
    
    if [ ! -z "$apicSchedulerStatus" ]; then
        err "Scheduler issue detected for one or more services" 
        err "$apicSchedulerStatus" 
        return 1
    else
        success "Scheduler is up" 
        return 0
    fi

    return 0

}

check_CSCwa45126(){

    # Checking orphaned nomad logmon processes >0
    # $1 : apicId
    # $2 : apicDn
 
    # Example:
    # --------
    # APIC1# ps -eaf | grep logmon | egrep "1  0"   
    # root       912     1  0 00:20 ?        00:00:53 /usr/bin/nomad logmon
    # root      4400     1  0 Dec08 ?        00:01:52 /usr/bin/nomad logmon
    # root     16235     1  0 00:16 ?        00:01:01 /usr/bin/nomad logmon

    local apicLogmonProcess
    local oprhanLogmonProcessNumber
    local forkRejected

    if [ "$#" -eq 0 ]; then
        err "check_CSCwa45126: Missing apicId args"
        exit 1
    fi

    subtitle "Verifying orphaned nomad logmon process"


    if (( "$localApicId" == "$1" )); then
        apicLogmonProcess="$(ps -eaf | grep logmon | grep -v grep)"
    else
        apicLogmonProcess="$(sshpass -p $apicPwd ssh -tq -l $(whoami) apic$1 \"ps -eaf | grep logmon | grep -v grep\")"
    fi

    debug "apicLogmonProcess: $apicLogmonProcess"

    oprhanLogmonProcessNumber="$(echo \"$apicLogmonProcess\" | grep -q '1  0' -c)"
    trace "oprhanLogmonProcessNumber: $oprhanLogmonProcessNumber"

    if (( oprhanLogmonProcessNumber > 0)); then
        alert "$oprhanLogmonProcessNumber oprhan(s) found" 

        # Checking fork limitation for infra_addons.slice match >0
        # Example:
        # APIC1# dmesg | egrep "fork rejected by pids controller"
        # [264812.514204] cgroup: fork rejected by pids controller in /ifc.slice/ifc-infra_addons.slice/scheduler_converge.service

        log "Looking for rejected fork for infra_addons slice" 

        if (( "$localApicId" == "$1" )); then
            forkRejected="$(dmesg | grep 'fork rejected by pids controller' -c)"
        else
            forkRejected="$(sshpass -p $apicPwd ssh -tq -l $(whoami) apic$1  \"dmesg | grep 'fork rejected by pids controller' -c\")"
        fi 

        trace "forkRejected: $forkRejected"

        if (( forkRejected > 0 )); then
            hit_CSCwa45126=1

            alert "Fork rejected logs found for infra_addons" 

            if $attempt_fix ; then 
                fix_CSCwa45126 $1
            else
                alert "Suggested next steps:\n1 - reboot APIC $1 using \`acidiag reboot\` command\n or \n2 - manually remove the orphaned process using the --fix-me args" 
            fi 

            return 1
        else
            success "No fork rejected logs found" 
            return 0
        fi
    else
        success "No orphaned nomad logmon process"
        return 0
    fi 
}

fix_CSCwa45126(){

    ask_for_rootpassword
    if (( $? )); then
        log "No/incorrect root password provided. Aborting"
        return 0
    fi

    if (( "$localApicId" == "$1" )); then
        info "Removing orphaned processes"
        sshpass -p $rootPassword ssh -tq -l root 0 "kill -9 $(ps -ef | grep '/usr/bin/nomad logmon' | grep -v grep | awk  '{print \$\2}')"
        info "Restarting nomad_client"
        sshpass -p $rootPassword ssh -tq -l root 0 "systemctl restart nomad_client"

    else
        info "Removing orphaned processes"
        sshpass -p $rootPassword ssh -tq -l root apic$1 "kill -9 $(ps -ef | grep '/usr/bin/nomad logmon' | grep -v grep | awk  '{print \$\2}')"
        info "Restarting nomad_client"
        sshpass -p $rootPassword ssh -tq -l root apic$1 "systemctl restart nomad_client"
    fi

}

check_CSCvw05302(){

    # Checking orphaned process
    # $1 is apicId
    # $2 is apicDn

    local orphanedProcess

    subtitle "Verifying scheduler processes with invalid PID"

    # Example:
    # --------
    # apic-1# cat /aci/system/controllers/node-1/processes/summary     
    # process-id  process-name       state              
    # ----------  -----------------  -------------------
    # 0           consul             interruptible-sleep
    # 0           nomad              interruptible-sleep
    # 0           kron               interruptible-sleep
    # 0           nomad_client       interruptible-sleep

    debug "$(cat "/aci/system/controllers/node-$1/processes/summary")"
    
    consulPid="$(grep -oP "process-id\s+:\s+\K(\d+)" "/aci/system/controllers/node-$1/processes/consul/summary")"
    trace "consulPid: $consulPid"

    nomadPid="$(grep -oP "process-id\s+:\s+\K(\d+)" "/aci/system/controllers/node-$1/processes/nomad/summary")"
    trace "nomadPid: $nomadPid"

    nomadClientPid="$(grep -oP "process-id\s+:\s+\K(\d+)" "/aci/system/controllers/node-$1/processes/nomad_client/summary")"
    trace "nomadClientPid: $nomadClientPid"

    kronPid="$(grep -oP "process-id\s+:\s+\K(\d+)" "/aci/system/controllers/node-$1/processes/kron/summary")"
    trace "kronPid: $kronPid"


    # If scheduler PIDs are all 0
    if [[ "$consulPid" -eq 0 ]] && [[ "$nomadPid" -eq 0 ]] && [[ "$nomadClientPid" -eq 0 ]] && [[ "$kronPid" -eq 0 ]]; then
        alert "Process with pid 0 found" 

        hit_CSCvw05302=1

        if $attempt_fix ; then
            fix_CSCvw05302 "$apicId"
        else
            info "No --fix-me options provided, however this issue do not require root password to get fixed"
            read -r -p "  Do you wish to run the fix? [y/N] " response
            case "$response" in
                [yY][eE][sS]|[yY]) 
                    fix_CSCvw05302
                    ;;
                *)
                    return 1
                ;;
                esac
        fi 

        return 1
    else
        "success" "Scheduler processes are up" 
        return 0
    fi

}

fix_CSCvw05302(){

    # Fix SCvw05302 by cleaning up and enable the scheduler
    
    subtitle "Trying to fix scheduler issue"

    info "The script will restart the scheduler using the below commands:\n\
    - acidiag scheduler cleanup force\n\
    - acidiag scheduler enable" 
 
    info "This action is not disruptive" 

    read -r -p "  Do you wish to continue? [y/N] " response
    case "$response" in
    [yY][eE][sS]|[yY]) 
        ;;
    *)
        info "Fix aborted, bye" 
        return 1
    ;;
    esac

    log "Cleaning up the scheduler" | pr -to2
    acidiag scheduler cleanup force

    log "Enabling back the scheduler" | pr -to2
    acidiag scheduler enable

    success "Done. Wait 60m and confirm if the fault F1419 is gone or in cleared state\n    If not, please contact Cisco TAC for further assistance" 
    exit 0
}

check_av_json_empty(){

    # Check if av_state.json file is empty and the /var/log/dme/log disk usage
    # $1 apicId
    # $2 apicDn 

    local avStateSize
    local dmeLogUsage

    subtitle "Verifying state files and disk usage"

    if (( "$localApicId" == "$1" )); then
        avStateSize="$(stat /var/log/dme/log/av_state.json -c %s)"
        trace "avStateSize: $avStateSize"

        dmeLogUsage=$(df /var/log/dme/log | grep -oP "\K\d+(?=%)")
        trace "dmeLogUsage: $dmeLogUsage"
    else
        avStateSize="$(sshpass -p $apicPwd ssh -tq -l $(whoami) apic$1 'stat /var/log/dme/log/av_state.json -c %s')"
        trace "avStateSize: $avStateSize"

        dmeLogUsage="$(sshpass -p $apicPwd ssh -tq -l $(whoami) apic$1 'df /var/log/dme/log | grep -oP "\K\d+(?=%)"')"
        trace "dmeLogUsage: $dmeLogUsage"
    fi



    # Use string maniplulation to remove trailing \r from ssh output
    if [[ "${avStateSize%%[[:cntrl:]]}" -eq 0 ]]; then
        err "The file /var/log/dme/log/av_state.json is empty, this will prevents the scheduler to function properly"
    else
        success "av_state.json file is populated"
    fi

    if [[ "${dmeLogUsage%%[[:cntrl:]]}" -gt 95 ]]; then
        err "/var/log/dme/log partition usage is high ($dmeLogUsage%)"

    else
        success "/var/log/dme/log partition usage is lower than 95%"
    fi

    return 0
}

check_apic_ca(){

    # Check if apic crt and key md5 sum do match
    # $1 apicId
    # $2 apicDn 

    local apicCrtmd5="null-crt"
    local apickeymd5="null-key"

    if [ "$#" -eq 0 ]; then
        err "check_CSCwa45126: Missing apicId args"
        exit 1
    fi

    subtitle "Verifying APIC certificates."

    ask_for_rootpassword
    if (( $? )); then
        info "Skipped APIC certificate verifications" 
        return 0
    fi

    if (( "$localApicId" == "$1" )); then
        apicCrtmd5="$(sshpass -p $rootPassword ssh -tq -l root 0 'openssl x509 -noout -modulus -in /securedata/apicca/apicca.crt | openssl md5')"
        apickeymd5="$(sshpass -p $rootPassword ssh -tq -l root 0 'openssl rsa -noout -modulus -in /securedata/apicca/apicca.key | openssl md5')"
    else
        apicCrtmd5="$(sshpass -p $rootPassword ssh -tq -l root apic$1 'openssl x509 -noout -modulus -in /securedata/apicca/apicca.crt | openssl md5')"
        apickeymd5="$(sshpass -p $rootPassword ssh -tq -l root apic$1 'openssl rsa -noout -modulus -in /securedata/apicca/apicca.key | openssl md5')"
    fi
    
    # Required if trailing CR found in the output
    apicCrtmd5=$(grep -oP ".*=\s+\K(.*)" <<< $apicCrtmd5)
    apickeymd5=$(grep -oP ".*=\s+\K(.*)" <<< $apickeymd5)

    trace "apicCrtmd5: $apicCrtmd5"
    trace "apickeymd5: $apickeymd5"

    if [[ "$apicCrtmd5" == "$apickeymd5" ]]; then
        success "APIC certificate do matches" 
        return 0
    else
        err "Mismatching APIC certificate, please raise a TAC case to have this issue addressed" 
        return 1
    fi

}



main(){

    # Check if the script is running on APIC (acidiag platform == IFC)
    title "Running APIC scheduler analyzer"
    gather_facts
    info "Running on $localApicName (apic id: $localApicId, cluster of $apicClusterSize, version $localApicVersion)" 
    check_cluster_health "$localApicId" "$localApicDn"
    
    if $rootPasswordRequired ; then
        subtitle "Root password"
        ask_for_rootpassword
        if (( $? )); then
            log "No/incorrect root password provided. Aborting"
            exit 1
        fi
    fi

    schedulerStatus="$(acidiag scheduler statusx)"
    debug "$schedulerStatus"
    
    if ! $check_certs ; then
        check_F3254
    fi

    trace "APIC id in cluster: $apicIdArray"

    for apicId in "${apicIdArray[@]}"
    do
        if [ ! -d "/aci/system/controllers/node-$apicId"  ]; then
            err "Unknown APIC id $apicId"
            exit 1
        fi

        title "Running verification on APIC $apicId"

        local apicDn

        apicDn=$(icurl -s "http://localhost:7777/api/uni/class/fabricNode.xml?query-target-filter=eq(fabricNode.id, \"$apicId\")" | xmllint --xpath 'string(/imdata/fabricNode/@dn)' - )
        trace "apicDn: $apicDn"

        # If --check-certs is given, only check certs 
        if $check_certs ; then 
            check_apic_ca "$apicId"
            trace "check_apic_ca: $?"
        else 

            check_scheduler_status "$apicId" "$apicDn"
            trace "check_scheduler_status: $?"


            if (( "$localApicId" != "$apicId" )); then
                ask_for_password "$apicId" "$(whoami)"
                if (( $? )); then
                    info "Skipped verifications for APIC $apicId" 
                    continue
                fi
            fi

            check_CSCwa45126 "$apicId"
            trace "check_CSCwa45126: $?"

            check_CSCvw05302 "$apicId"
            trace "check_CSCvw05302: $?"

            check_av_json_empty "$apicId"
            trace "check_av_json_empty: $?"

        fi 

        unset apicDn
    done

}

usage(){
    echo "APIC scheduler analyzer"
    echo ""
    echo "usage: ./scheduler [-h] [-v] [--apic ID] [--apic-pwd PWD] [--root-pwd PWD] [--fix-me] [--check-certs] | [--generate-ts]"
    echo ""
    echo "optional arguments:"
    echo "  --apic {APIC-ID}  : run the verification on the provided APIC id (default is all)"
    echo "  --apic-pwd        : APIC password (used if verification are performed on remote APICs)"
    echo "  --root-pwd        : root password (provided by TAC)"
    echo "  --check-certs     : run the certificiation verification (requires root password)"
    echo "  --fix-me          : attempts to run an fix when a verification fails"
    echo "  --generate-ts     : generate a tar.gz archives containing the scheduler logs for TAC "
    echo ""
    echo "  -v, --verbose     : show traces"
    echo "  -h, --help        : show this help message"
    echo ""
    echo "examples:"
    echo "  ./scheduler : run the scheduler for all APICs"
    echo "  ./scheduler --apic 2 : run the scheduler for APIC 2 only"
    echo "  ./scheduler --apic 2 --root-pwd 1234 --fix-me : run the scheduler for APIC 2 and attemps fix"
    echo "  ./scheduler --generate-ts : generate the techsupport bundle"

}


if [[ -v APIC_PWD ]]; then
    apicPwd="$APIC_PWD"
fi

if [[ -v APIC_ROOT_PWD ]]; then
    rootPassword="$APIC_ROOT_PWD"
fi

# Grab given named args 
while [ "$#" -gt 0 ]; do
    case "$1" in
        --apic)
            # Allow only 1 digits or 'all'
            if ! [[ "$2" =~ ^[0-9]+$ ]] ; then
                if [[ "$2" != "all" ]]; then
                    err "--apic args must be a single APIC id"
                    exit 1
                fi
            else
                apicIdArray=($2)
            fi
  
            shift 2
        ;;

        --apic-pwd)
            apicPwd="$2"
            shift 2

            if [ -z ${APIC_PWD} ]; then
                trace "--apic-pwd args provided and APIC_PWD var found in the env variables, using --apic-pwd instead "
            fi

        ;;

        --root-pwd)
            rootPassword="$2"
            shift 2

            if [ -z ${APIC_ROOT_PWD} ]; then
                trace "--root-pwd args provided and APIC_ROOT_PWD var found in the env variables, using --root-pwd instead "
            fi
        ;;

        --check-certs)
            check_certs=true
            shift 1
        ;;
        --fix|--fix-me)
            attempt_fix=true
            shift 1
        ;;
        -v|--verbose)
            verbose=1
            shift 1
        ;;

        --debug)
            # set -o xtrace
            verbose=2
            shift 1
        ;;

        --generate-ts)
            gather_facts
            generate_tsbundle
            exit
        ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
        ;;
    esac
done

if [ "$check_certs" = true ] || [ "$attempt_fix" = true ]; then
    rootPasswordRequired=true
fi

main