#!/bin/bash

#TODO, need to fix handling of remote teps where it isn't a ptep or vpc tep.
#Test scenarios with hot standby links, mac-pinning
#Test where peer-link is down but local legs are up
#Need to save all objects for debugging
function log() {
    ts=$(date '+%Y-%m-%dT%H:%M:%S')
    echo "$ts $1"
}

function progress_checker(){
  ep_progress=$1; ep_count=$2
  if [[ $ep_progress == $ep_count ]]; then
    echo -ne "Completion Check: $ep_progress/$ep_count\n"
  else
    echo -ne "Completion Check: $ep_progress/$ep_count\r"
  fi
}

#Need to make sure there aren't more than 100k l3 or l2 ep's in the vnid supplied. I think supporting pagination would be bad for this script since ep info could change between page collections.
function _check_ep_count(){
  vnid=$1
  object=$2
  param='&rsp-subtree-include=count'
  if [[ $object == "epmIpEp" ]]; then
    obj_count=$(icurl -g 'http://127.0.0.1:7777/api//class/'$object'.json?query-target-filter=wcard('$object'.dn,"ctx-\[vxlan-'$vnid'\]")'$param 2>/dev/null)
    #obj_count=$(icurl -g 'http://127.0.0.1:7777/api//class/'$object'.json?query-target-filter=wcard('$object'.dn,"")'$param 2>/dev/null)
  elif [[ $object == "epmMacEp" ]]; then
    obj_count=$(icurl -g 'http://127.0.0.1:7777/api//class/'$object'.json?query-target-filter=wcard('$object'.dn,"bd-\[vxlan-'$vnid'\]")'$param 2>/dev/null)
  fi
  obj_count=$(jq -r '.imdata[].moCount.attributes.count' <<< $obj_count)
  if [[ $obj_count > 100000 ]]; then
    log "Warning, more than 100k $object objects! This script won't work well with that, exiting."
    exit 1
  else
    log "Collecting $obj_count relevant endpoint objects within the specified vnid"
  fi
}

###
###Build dictionaries to contain tep and role information
###
function _get_tep_info() {
  ep_count=$(echo "$OVERLAY_IF_IP" | grep -c "\"addr\"")
  log "Processing $ep_count overlay teps."
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  IFS=$'\n'
  for line in $(echo "$OVERLAY_IF_IP"); do
    if [[ $line == *"\"dn\""* ]]; then
      type=""; addr=""
      node=${line#*node-}
      node="node-"${node%%/*}
    elif [[ $line == *"\"mode\""* ]]; then
      type=${line#*\"mode\": \"}
      type=${type%%\"*}
    elif [[ $line == *"\"addr\""* ]]; then
      let ep_progress++; progress_checker "$ep_progress" "$ep_count"
      addr=${line#*\"addr\": \"}
      addr=${addr%%/*}
      if [[ -n "${ip_node_dic[$addr]}" ]]; then
        ip_node_dic[$addr]+=" $node"
      else
        if [[ $type == "vpc" ]]; then
          ip_node_dic[$addr]="VPC_NODES $node"
        elif [[ $type == "ptep" ]]; then
          ip_node_dic[$addr]="PTEP_NODE $node"
        else
          ip_node_dic[$addr]="$node"
        fi
      fi
      ip_type_dic[$addr]="$type"
    fi
  done
  unset IFS
}

###
###Build dictionaries to contain vpc information. Basically what members/ifs are down and also map vpc ifs to port-channels
###Needed to later determine if the expected tep is vtep or ptep
###
function _get_vpc_info() {
  vpc_pairs=$(echo "$VPC_DB_INFO" | egrep -o "protpaths\-[0-9]+\-[0-9]+" | sort | uniq | sed -e "s/protpaths/node/g")
  ep_count=$(echo "$VPC_DB_INFO" | grep -c "\"tDn\"")
  log "Processing $ep_count down vpc interfaces."
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  IFS=$'\n'
  for line in $(echo "$VPC_DB_INFO"); do
    if [[ $line == *"\"fabricPathDn\""* ]]; then
      ifid=""; localState=""; remoteState=""; node=""; pcif=""
      node_pair=$(echo $line | egrep -o "protpaths\-[0-9]+\-[0-9]+" | sed -e "s/protpaths/node/g")
    elif [[ $line == *"\"id\""* ]]; then
      ifid=${line#*\"id\": \"}
      ifid=${ifid%%\"*}
    elif [[ $line == *"\"localOperSt\""* ]]; then
      localState=${line#*\"localOperSt\": \"}
      localState=${localState%%\"*}
    elif [[ $line == *"\"remoteOperSt\""* ]]; then
      remoteState=${line#*\"remoteOperSt\": \"}
      remoteState=${remoteState%%\"*}
    elif [[ $line == *"\"tDn\""* ]]; then
      let ep_progress++; progress_checker "$ep_progress" "$ep_count"
      node=$(echo $line | egrep -o "node\-[0-9]+" | egrep -o "[0-9]+")
      pcif=$(echo $line | egrep -o "aggr\-\[po[0-9]+\]" | egrep -o "po[0-9]+")
      vpc_mapping_dic['node-'$node'_'$pcif]="$ifid"
      if [[ $localState == "up" ]]; then
        if [[ $(echo "${vpc_dic["$node-pair"'_if-'"$ifid"]}" | wc -w) > 0 ]]; then
          vpc_dic["$node-pair"'_if-'"$ifid"]+=" node-$node"
        else
          vpc_dic["$node_pair"'_if-'"$ifid"]="node-$node"
        fi
      fi
    fi
  done
  unset IFS
}

###
###Build dictionaries to contain tunnel information for xr mapping
###
function _get_tunnel_info() {
  ep_count=$(grep -c "\"dn\"" <<< "$TUNNEL_DST_INFO")
  log "Processing $ep_count fabric tunnels"
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  IFS=$'\n'
  for line in $(echo "$TUNNEL_DST_INFO"); do
    if [[ $line == *"\"dest\""* ]]; then
      tun=""; node=""; type=""
      dest_tep="${line#*: \"}"  # Remove everything up to and including the string ': "'
      dest_tep="${dest_tep%%\"*}"  # Remove everything from and including the next quote
      dest_tep="${dest_tep%%/*}"  # Remove the subnet part, if present
    elif [[ $line == *"\"dn\""* ]]; then
      node=${line#*node-}
      node="node-"${node%%/*}
    elif [[ $line == *"\"id\""* ]]; then
      tun=${line#*\"id\": \"}
      tun=${tun%%\"*}
    elif [[ $line == *"\"type\""* ]]; then
      let ep_progress++; progress_checker "$ep_progress" "$ep_count"
      type=${line#*\"type\": \"}
      type=${type%%\"*}
      if ! [[ $type == *"mcast"* ]]; then
        key=$(echo "$node"'_'"$tun")
        tunnel_dest_dic[$key]="$dest_tep"
      fi
    fi
  done
  unset IFS
}

###
###Build dictionaries to contain l3 ep information
###
function _get_l3_ep_info() {
  ep_count=$(echo "$L3_EP_INFO" | grep -c "\"dn\"")
  log "Processing $ep_count ipv4 endpoints"
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  IFS=$'\n'
  for line in $(echo "$L3_EP_INFO"); do
    if [[ $line == *"\"addr\""* ]]; then
      node=""; nodeId="", iface=""; flags=""
      addr=${line#*\"addr\": \"}
      addr=${addr%%\"*}
    elif [[ $line == *"\"dn\""* ]]; then
      nodeId=${line#*node-}
      nodeId=${nodeId%%/*}
      node="node-$nodeId"
    elif [[ $line == *"\"flags\""* ]]; then
      flags=${line#*\"flags\": \"}
      flags=${flags%%\"*}
    elif [[ $line == *"\"ifId\""* ]]; then
      iface=${line#*\"ifId\": \"}
      iface=${iface%%\"*}
      ep_key=$(echo "$node"'_'"$addr")
      let ep_progress++; progress_checker "$ep_progress" "$ep_count"
      #fabric IP's, don't care about those
      if [[ $flags == *"svi"* ]] || [[ $flags == *"loopback"* ]] || [[ $flags == *"vtep"* ]] || [[ $flags == *"span"* ]]; then
        continue
      #local learns
      #skip check if remote leaf since dst tep is spine
      elif [[ " $REMOTE_LEAF_LIST " == *" $nodeId "* ]]; then 
        #log "skipping remote leaf $nodeId"; 
        continue
      elif [[ $flags == *"local,"* ]] || [[ $flags =~ .*local$ ]]; then
        if [[ -n "${l3_local_ep_dic[$addr]}" ]]; then
          l3_local_ep_dic[$addr]+=' '"$node"'_'"$iface"
        else
          l3_local_ep_dic[$addr]="$node"'_'"$iface"
        fi
      #process xr learns
      else
        value=$(echo "$node"'_'"$iface")
        tun_dst_node="${tunnel_dest_dic[$value]}"
        #If dst tep is msite ucast etep, skip
        if [[ " $DCI_UCAST_TEP_LIST " == *" $tun_dst_node "* ]]; then 
          #log "skipping etep $tun_dst_node"; 
          continue
        fi
        l3_xr_ep_dic[$ep_key]="$tun_dst_node"
      fi
      l3_ep_flags_dic[$ep_key]="$flags"
    fi
  done

  #Populate unique_l3_ep_dic with all l3 ep's in the fabric that are local or ptep/vpc tep learned
  for key in "${!l3_local_ep_dic[@]}"; do
    unique_l3_ep_dic+=("$key")
  done
  for xr_key in "${!l3_xr_ep_dic[@]}"; do
    #xr_key='node-103_192.168.254.101'
    dst_tep="${l3_xr_ep_dic[$xr_key]}"
    if [[ -n "$dst_tep" ]]; then
      tep_type="${ip_type_dic[$dst_tep]}"
      if [[ $tep_type == *"vpc"* ]] || [[ $tep_type == *"ptep"* ]]; then
        regex='([0-9]{1,3}\.){3}[0-9]{1,3}'
        if [[ $xr_key =~ $regex ]]; then ip=${BASH_REMATCH[0]}; fi
        unique_l3_ep_dic+=("$ip")
      fi
    fi
  done

  #Remove duplicates
  readarray -t unique_l3_ep_dic < <(printf '%s\0' "${unique_l3_ep_dic[@]}" | sort -zu | xargs -0n1)
  unset IFS
}

###
###Build dictionaries to contain l2 ep information
###
function _get_l2_ep_info() {
  ep_count=$(echo "$L2_EP_INFO" | grep -c "\"dn\"")
  log "Processing $ep_count L2 mac endpoints"
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  IFS=$'\n'
  for line in $(echo "$L2_EP_INFO"); do
    if [[ $line == *"\"addr\""* ]]; then
      node=""; nodeId="", iface=""; flags=""
      addr=${line#*\"addr\": \"}
      addr=${addr%%\"*}
    elif [[ $line == *"\"dn\""* ]]; then
      nodeId=${line#*node-}
      nodeId=${nodeId%%/*}
      node="node-$nodeId"
    elif [[ $line == *"\"flags\""* ]]; then
      flags=${line#*\"flags\": \"}
      flags=${flags%%\"*}
    elif [[ $line == *"\"ifId\""* ]]; then
      iface=${line#*\"ifId\": \"}
      iface=${iface%%\"*}
      ep_key=$(echo "$node"'_'"$addr")
      let ep_progress++; progress_checker "$ep_progress" "$ep_count"
      #fabric IP's, don't care about those
      if [[ $flags == *"svi"* ]] || [[ $flags == *"vtep"* ]] || [[ $flags == *"span"* ]]; then
        continue
      #local learns
      #skip check if remote leaf since dst tep is spine
      elif [[ " $REMOTE_LEAF_LIST " == *" $nodeId "* ]]; then 
        #log "skipping remote leaf $nodeId"; 
        continue
      elif [[ $flags == *"local,"* ]] || [[ $flags =~ .*local$ ]]; then
        if [[ -n "${l2_local_ep_dic[$addr]}" ]]; then
          l2_local_ep_dic[$addr]+=' '"$node"'_'"$iface"
        else
          l2_local_ep_dic[$addr]="$node"'_'"$iface"
        fi
      #process xr learns
      else
        value=$(echo "$node"'_'"$iface")
        tun_dst_node="${tunnel_dest_dic[$value]}"
        #If dst tep is msite ucast etep, skip
        if [[ " $DCI_UCAST_TEP_LIST " == *" $tun_dst_node "* ]]; then 
          #log "skipping etep $tun_dst_node"; 
          continue
        fi
        l2_xr_ep_dic[$ep_key]="$tun_dst_node"
      fi
      l2_ep_flags_dic[$ep_key]="$flags"
    fi
  done

  #Populate unique_l2_ep_dic with all l2 ep's in the fabric that are local or ptep/vpc tep learned within the supplied bd vnid
  for key in "${!l2_local_ep_dic[@]}"; do
    unique_l2_ep_dic+=("$key")
  done
  for xr_key in "${!l2_xr_ep_dic[@]}"; do
    #xr_key='node-102_00:50:56:A8:65:41'
    dst_tep="${l2_xr_ep_dic[$xr_key]}"
    if [[ -n "$dst_tep" ]]; then
      tep_type="${ip_type_dic[$dst_tep]}"
      if [[ $tep_type == *"vpc"* ]] || [[ $tep_type == *"ptep"* ]]; then
        regex='([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
        if [[ $xr_key =~ $regex ]]; then mac=${BASH_REMATCH[0]}; fi
        unique_l2_ep_dic+=("$mac")
      fi
    fi
  done

  #Remove duplicates
  readarray -t unique_l2_ep_dic < <(printf '%s\0' "${unique_l2_ep_dic[@]}" | sort -zu | xargs -0n1)
  unset IFS
}

###
###Build dictionaries to contain vtep information. This can't be done in the function that processes ep's (even though its stored in the same epmIpEp object) because that def uses tenant vnid filtering.
###
function _get_vtep_info() {
  ep_count=$(echo "$VTEP_INFO" | grep -c "\"dn\"")
  log "Processing $ep_count ipv4 VTEPs"
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  IFS=$'\n'
  for line in $(echo "$VTEP_INFO"); do
    if [[ $line == *"\"addr\""* ]]; then
      node=""; iface=""; flags=""
      addr=${line#*\"addr\": \"}
      addr=${addr%%\"*}
    elif [[ $line == *"\"dn\""* ]]; then
      node=${line#*node-}
      node="node-"${node%%/*}
    elif [[ $line == *"\"ifId\""* ]]; then
      iface=${line#*\"ifId\": \"}
      iface=${iface%%\"*}
      let ep_progress++; progress_checker "$ep_progress" "$ep_count"
      if [[ -n "${vtep_dic[$addr]}" ]]; then
        vtep_dic[$addr]+=' '"$node"'_'"$iface"
      else
        vtep_dic[$addr]="$node"'_'"$iface"
      fi
    fi
  done
}

###
###Check for stale l3 endpoints
###
#For a given vnid, need to build a list of all L3 EP's that are learned in the fabric that are local OR XR pointing to VPC TEP OR XR pointing to PTEP.
#This should catch scenarios where there is a stale xr learn regardless of if there is a local learn. It also filters out scenarios where the dst tep is proxy or inter-site.
function _check_l3_endpoints() {
  ep_count=${#unique_l3_ep_dic[@]}
  log "There are $ep_count relevant l3 endpoints to check."
  log "Determining expected TEPs for $ep_count ipv4 endpoints..."
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  #Iterate through unique learns to determine expected location.
  #If it is on a vpc is one side is down need to set expected tep to ptep. Need to be able to do this for eps that are locally vxlan learned (k8s, openstack, etc)
  for ep in ${unique_l3_ep_dic[@]}; do
    leg_down=false; regex=""; regex2=""
    let ep_progress++; progress_checker "$ep_progress" "$ep_count"
    #ep="172.16.1.4"
    #If ep is learned locally on 2 nodes it should be vpc attached. In this case need to check if either side of vpc is down in order to determine if the expected tep is vpc tep or ptep
    if [[ $(wc -w <<< ${l3_local_ep_dic[$ep]}) == 2 ]]; then
      expected_node_if=${l3_local_ep_dic[$ep]%% *}
      expected_node=${expected_node_if%_*}
      type=${l3_ep_flags_dic["$expected_node"_"$ep"]}
      if [[ $type == *"vpc-attached"* ]]; then
        #Set pcif in order to resolve vpc if
        if [[ $expected_node_if == *"tunnel"* ]]; then
          tun_if=${expected_node_if#*_}
          value=$(echo "$expected_node"'_'"$tun_if")
          tun_dst_tep=${tunnel_dest_dic[$value]}
          vtep_learn=${vtep_dic[$tun_dst_tep]}
          for element in $vtep_learn; do
            if [[ $element == "$expected_node"_* ]]; then
                pcif="po"${element##*po}
                break
            fi
          done
        else
          pcif="po"${expected_node_if##*po}
        fi
        vpcif=${vpc_mapping_dic[$expected_node'_'$pcif]}
        if ! [ -z "$vpcif" ]; then
          node=${expected_node##*node-}
          for pair in $vpc_pairs; do
            if echo "$pair" | grep -q "\<$node\>"; then node_pair=$pair; fi
          done
          if [[ $(echo "${vpc_dic["$node_pair"'_if-'"$vpcif"]}" | wc -w) < 2 ]]; then
            expected_node=$(echo "${vpc_dic["$node_pair"'_if-'"$vpcif"]}" | awk '{print $1}')
            regex="PTEP.*$expected_node"
            #If one side of vpc is down, ep fast convergence allows traffic destined to the vpc tep that arrives on the down side to get bounced to the active side. The bad scenario is if for some reason the dst tep is the ptep of the down side. Basically need to make sure that the dst tep is the vpc tep or the ptep of the up member.
            leg_down=true
            regex2="VPC.*$expected_node"
          else
            #Both sides of vpc are up so expected tep is vpc tep
            regex="VPC.*$expected_node"
          fi
        else
          #if we couldn't find the vpc if, that's means the query filtering on down members didn't catch it. Thus the vpc is up. Expected tep is vpc tep.
          regex="VPC.*$expected_node"
        fi
      else
        regex="PTEP.*$expected_node"
      fi
    elif [[ $(wc -w <<< ${l3_local_ep_dic[$ep]}) == 1 ]]; then
      expected_node_if=${l3_local_ep_dic[$ep]}
      expected_node=${expected_node_if%_*}
      type=${l3_ep_flags_dic["$expected_node"_"$ep"]}
      regex="PTEP.*$expected_node"
    else
      regex="nullnullnulllololololnonemptystring"
      l3ep_expected_tep[$ep]="not_fabric_local"
    fi
    for key in "${!ip_node_dic[@]}"; do
      if [[ ${ip_node_dic[$key]} =~ $regex ]]; then
        l3ep_expected_tep[$ep]="$key"
        if $leg_down; then
          for key2 in "${!ip_node_dic[@]}"; do
            if [[ ${ip_node_dic[$key2]} =~ $regex2 ]]; then
              l3ep_expected_tep[$ep]+=" $key2"
            fi
          done
        fi
        break
      fi
    done
  done
  ep_count=${#l3_xr_ep_dic[@]}
  log "Checking $ep_count remote ipv4 endpoints for incorrect learns"
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  for key in "${!l3_xr_ep_dic[@]}"; do
     exit_loop=false; expected_dst_nodes=""; expected_tep=""
    #key='node-101_10.3.3.50'
    let ep_progress++; progress_checker "$ep_progress" "$ep_count"
    node=${key%%_*}
    ep=${key##*_}
    #ep="192.168.102.25"
    if ! [[  ${l3_xr_ep_dic[$key]} == ${l3ep_expected_tep[$ep]} ]]; then
      #There could be more than one expected tep for scenario where ep is vpc attached but one leg is down. In this case could be ptep of active member or vpc tep. Need to check xr entry against both.
      if [[ $(wc -w <<< ${l3ep_expected_tep[$ep]}) == 2 ]]; then
        for tep in ${l3ep_expected_tep[$ep]}; do
          if [[  ${l3_xr_ep_dic[$key]} == $tep ]]; then
            exit_loop=true
            break
          fi
        done
        if ! $exit_loop; then
          expected_tep=$(echo "${l3ep_expected_tep[$ep]}" | sed 's/ / or /g')
          for expected_node_tep in ${l3ep_expected_tep[$ep]}; do
            IFS=' ' read -r -a array <<< "$(echo ${ip_node_dic[$expected_node_tep]})"
            if [[ ${array[0]} == *"VPC"* ]] || [[ ${array[0]} == *"PTEP"* ]]; then unset array[0]; array=("${array[@]}"); fi
            if [ -z "$expected_dst_nodes" ]; then
              expected_dst_nodes=$(IFS=','; echo "${array[*]}")
            else
              expected_dst_nodes+=" or "$(IFS=','; echo "${array[*]}")
            fi
          done
        fi
      else
        #Handle normal scenario where there's a single expected tep
        if [[ ${l3ep_expected_tep[$ep]} == "not_fabric_local" ]]; then
          expected_dst_nodes="not_fabric_local"
          expected_tep=${l3ep_expected_tep[$ep]}
        else
          IFS=' ' read -r -a array <<< "$(echo ${ip_node_dic[${l3ep_expected_tep[$ep]}]})"
          unset array[0]
          expected_dst_nodes=$(IFS=','; echo "${array[*]}")
          expected_tep=${l3ep_expected_tep[$ep]}
        fi
      fi
      if $exit_loop; then
        continue
      else
        IFS=' ' read -r -a array <<< "$(echo ${ip_node_dic[${l3_xr_ep_dic[$key]}]})"
        unset array[0]	
        real_dst_nodes=$(IFS=','; echo "${array[*]}")	
        log "WARNING! Found incorrect remote learn on $node for ep $ep"
        let BAD_LEARN_COUNT++
        echo -e "Endpoint: "$node"_"$ep"\n\tDestination TEP: ${l3_xr_ep_dic[$key]}\n\tDestination Node(s): $real_dst_nodes\n\tExpected TEP(s): $expected_tep\n\tExpected Node(s): $expected_dst_nodes\n" >> $LOG_DIR$BAD_LEARN_FILE
      fi
    fi
  done
}

###
###Check for stale l2 endpoints
###
#For a given vnid, need to build a list of all l2 EP's that are learned in the fabric that are local OR XR pointing to VPC TEP OR XR pointing to PTEP.
#This should catch scenarios where there is a stale xr learn regardless of if there is a local learn. It also filters out scenarios where the dst tep is proxy or inter-site.
function _check_l2_endpoints() {
  unset l2ep_expected_tep
  declare -A l2ep_expected_tep
  ep_count=${#unique_l2_ep_dic[@]}
  log "There are $ep_count relevant l2 endpoints to check."
  log "Determining expected TEPs for $ep_count l2 endpoints..."
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  #Iterate through unique learns to determine expected location.
  #If it is on a vpc is one side is down need to set expected tep to ptep. Need to be able to do this for eps that are locally vxlan learned (k8s, openstack, etc)
  for ep in ${unique_l2_ep_dic[@]}; do
    leg_down=false; regex=""; regex2=""
    let ep_progress++; progress_checker "$ep_progress" "$ep_count"
    #ep="00:50:56:A8:91:16"
    #If ep is learned locally on 2 nodes it should be vpc attached. In this case need to check if either side of vpc is down in order to determine if the expected tep is vpc tep or ptep
    if [[ $(wc -w <<< ${l2_local_ep_dic[$ep]}) == 2 ]]; then
      expected_node_if=${l2_local_ep_dic[$ep]%% *}
      expected_node=${expected_node_if%_*}
      type=${l2_ep_flags_dic["$expected_node"_"$ep"]}
      if [[ $type == *"vpc-attached"* ]]; then
        #Set pcif in order to resolve vpc if
        if [[ $expected_node_if == *"tunnel"* ]]; then
          tun_if=${expected_node_if#*_}
          value=$(echo "$expected_node"'_'"$tun_if")
          tun_dst_tep=${tunnel_dest_dic[$value]}
          vtep_learn=${vtep_dic[$tun_dst_tep]}
          for element in $vtep_learn; do
            if [[ $element == "$expected_node"_* ]]; then
                pcif="po"${element##*po}
                break
            fi
          done
        else
          pcif="po"${expected_node_if##*po}
        fi
        vpcif=${vpc_mapping_dic[$expected_node'_'$pcif]}
        if ! [ -z "$vpcif" ]; then
          node=${expected_node##*node-}
          for pair in $vpc_pairs; do
            if echo "$pair" | grep -q "\<$node\>"; then node_pair=$pair; fi
          done
          if [[ $(echo "${vpc_dic["$node_pair"'_if-'"$vpcif"]}" | wc -w) < 2 ]]; then
            expected_node=$(echo "${vpc_dic["$node_pair"'_if-'"$vpcif"]}" | awk '{print $1}')
            regex="PTEP.*$expected_node"
            #If one side of vpc is down, ep fast convergence allows traffic destined to the vpc tep that arrives on the down side to get bounced to the active side. The bad scenario is if for some reason the dst tep is the ptep of the down side. Basically need to make sure that the dst tep is the vpc tep or the ptep of the up member.
            leg_down=true
            regex2="VPC.*$expected_node"
          else
            #Both sides of vpc are up so expected tep is vpc tep
            regex="VPC.*$expected_node"
          fi
        else
          #if we couldn't find the vpc if, that's means the query filtering on down members didn't catch it. Thus the vpc is up. Expected tep is vpc tep.
          regex="VPC.*$expected_node"
        fi
      else
        regex="PTEP.*$expected_node"
      fi
    elif [[ $(wc -w <<< ${l2_local_ep_dic[$ep]}) == 1 ]]; then
      expected_node_if=${l2_local_ep_dic[$ep]}
      expected_node=${expected_node_if%_*}
      type=${l2_ep_flags_dic["$expected_node"_"$ep"]}
      regex="PTEP.*$expected_node"
    else
      regex="nullnullnulllololololnonemptystring"
      l2ep_expected_tep[$ep]="not_fabric_local"
    fi
    for key in "${!ip_node_dic[@]}"; do
      if [[ ${ip_node_dic[$key]} =~ $regex ]]; then
        l2ep_expected_tep[$ep]="$key"
        if $leg_down; then
          for key2 in "${!ip_node_dic[@]}"; do
            if [[ ${ip_node_dic[$key2]} =~ $regex2 ]]; then
              l2ep_expected_tep[$ep]+=" $key2"
            fi
          done
        fi
        break
      fi
    done
  done
  ep_count=${#l2_xr_ep_dic[@]}
  log "Checking $ep_count remote l2 endpoints for incorrect learns"
  ep_progress=0
  echo -ne "Completion Check: $ep_progress/$ep_count\r"
  for key in "${!l2_xr_ep_dic[@]}"; do
     exit_loop=false; expected_dst_nodes=""; expected_tep=""
    #key='node-102_00:50:56:A8:11:B5'
    let ep_progress++; progress_checker "$ep_progress" "$ep_count"
    node=${key%%_*}
    ep=${key##*_}
    #ep="192.168.102.25"
    if ! [[  ${l2_xr_ep_dic[$key]} == ${l2ep_expected_tep[$ep]} ]]; then
      #There could be more than one expected tep for scenario where ep is vpc attached but one leg is down. In this case could be ptep of active member or vpc tep. Need to check xr entry against both.
      if [[ $(wc -w <<< ${l2ep_expected_tep[$ep]}) == 2 ]]; then
        for tep in ${l2ep_expected_tep[$ep]}; do
          if [[  ${l2_xr_ep_dic[$key]} == $tep ]]; then
            exit_loop=true
            break
          fi
        done
        if ! $exit_loop; then
          expected_tep=$(echo "${l2ep_expected_tep[$ep]}" | sed 's/ / or /g')
          for expected_node_tep in ${l2ep_expected_tep[$ep]}; do
            IFS=' ' read -r -a array <<< "$(echo ${ip_node_dic[$expected_node_tep]})"
            if [[ ${array[0]} == *"VPC"* ]] || [[ ${array[0]} == *"PTEP"* ]]; then unset array[0]; array=("${array[@]}"); fi
            if [ -z "$expected_dst_nodes" ]; then
              expected_dst_nodes=$(IFS=','; echo "${array[*]}")
            else
              expected_dst_nodes+=" or "$(IFS=','; echo "${array[*]}")
            fi
          done
        fi
      else
        #Handle normal scenario where there's a single expected tep
        if [[ ${l2ep_expected_tep[$ep]} == "not_fabric_local" ]]; then
          expected_dst_nodes="not_fabric_local"
          expected_tep=${l2ep_expected_tep[$ep]}
        else
          IFS=' ' read -r -a array <<< "$(echo ${ip_node_dic[${l2ep_expected_tep[$ep]}]})"
          unset array[0]
          expected_dst_nodes=$(IFS=','; echo "${array[*]}")
          expected_tep=${l2ep_expected_tep[$ep]}
        fi
      fi
      if $exit_loop; then
        continue
      else
        IFS=' ' read -r -a array <<< "$(echo ${ip_node_dic[${l2_xr_ep_dic[$key]}]})"
        unset array[0]	
        real_dst_nodes=$(IFS=','; echo "${array[*]}")	
        log "WARNING! Found incorrect remote learn on $node for ep $ep"
        let BAD_LEARN_COUNT++
        echo -e "Endpoint: "$node"_"$ep"\n\tDestination TEP: ${l2_xr_ep_dic[$key]}\n\tDestination Node(s): $real_dst_nodes\n\tExpected TEP(s): $expected_tep\n\tExpected Node(s): $expected_dst_nodes\n" >> $LOG_DIR$BAD_LEARN_FILE
      fi
    fi
  done
}

#####HELP
function display_help() {
    echo -e \\n"Help documentation for $0"\\n
    echo "****************************************************************************************************"
    echo "This script automates detection of stale remote endpoint learns in an ACI fabric."
    echo ""
    echo "Supported Options:"
    echo "s:     Specifies scope for checking EPs. -s bd specifies to check MACs, -s vrf checks IPs."
    echo "v:    Specify the BD VNID (if -s bd was used) or VRF VNID (if -s vrf was used) to define the scope to check endpoints in."
    echo ""
    echo "Example Usage:"
    echo "      ./ep_checker.sh -s vrf -v 2916356 <--Check for incorrect remote IP endpoint learns in VRF vnid 2916356"
    echo "      ./ep_checker.sh -s bd -v 16056286 <--Check for incorrect remote mac endpoint learns in BD vnid 16056286"
    echo ""
    echo "All outputs are logged to /data/techsupport/stale_learn_checker"
    echo "****************************************************************************************************"
    exit 0
}

##################
#MAIN BODY BEGINS#
##################
if [[ "$1" == "--help" ]] || [[ "$1" == "--h" ]]; then
    display_help
    exit 0
fi

#####Take Args from Command
optspec="s:v:h"
while getopts "$optspec" optchar; do
  case $optchar in
    s)
        SCOPE=$OPTARG
        ;;
    v)
        VNID=$OPTARG
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

#Validate all the necessary arguments exist and only supported arg combinations are used
if [ -z ${VNID+x} ]; then
    log "VRF or BD VNID is required using the -v option. Check the -h/--h/--help for options"
    exit 1
fi

if [ -z ${SCOPE+x} ]; then
    log "Specify scope for checking ep's. -s vrf says to check IPs in the supplied vrf vnid; -s bd says to check MACs in the supplied BD vnid. Check the -h/--h/--help for options"
    exit 1
fi

if ! [[ $SCOPE == "vrf" ]] && ! [[ $SCOPE == "bd" ]]; then
    log "Specify -s vrf OR -s bd to indicate whether or not to check MACs or IPs in the associated VRF or BD."
    exit 1
fi

###DEFINE VARS, get API outputs
#Global Vars - do all api calls at the beginning so all data lines up...important for a fabric where things are moving/changing.
LOG_DIR="/data/techsupport/stale_learn_checker/"
BAD_LEARN_FILE="bad_learns"
BAD_LEARN_COUNT=0

#set up log dir and dump needed objects
GENERATE_NEW_DATA=true
if $GENERATE_NEW_DATA; then
  rm -rf "$LOG_DIR"
  mkdir -p "$LOG_DIR"
  if [[ $SCOPE == "vrf" ]]; then
    _check_ep_count "$VNID" "epmIpEp"
    icurl 'http://127.0.0.1:7777/api/class/epmIpEp.json?query-target-filter=wcard(epmIpEp.dn,"'$VNID'")' 2>/dev/null 1>> $LOG_DIR"l3_ep_info.json" &
  elif [[ $SCOPE == "bd" ]]; then
    _check_ep_count "$VNID" "epmMacEp"
    icurl 'http://127.0.0.1:7777/api/class/epmMacEp.json?query-target-filter=wcard(epmMacEp.dn,"'$VNID'")' 2>/dev/null 1>> $LOG_DIR"l2_ep_info.json" &
  fi
  icurl -g 'http://127.0.0.1:7777/api/node/class/ipv4If.json?query-target-filter=and(or(and(wcard(ipv4If.mode,"ptep"))and(wcard(ipv4If.mode,"vpc"))and(wcard(ipv4If.mode,"anycast")))and(wcard(ipv4If.dn,"dom-overlay-1/if-\[lo")))&rsp-subtree=children&rsp-subtree-class=ipv4Addr' 2>/dev/null  1>> $LOG_DIR"overlay_ips.json" &
  icurl 'http://127.0.0.1:7777/api/class/epmIpEp.json?query-target-filter=wcard(epmIpEp.flags,"vtep")' 2>/dev/null 1>> $LOG_DIR"vtep_info.json" &
  icurl 'http://127.0.0.1:7777/api/node/class/tunnelIf.json?query-target-filter=eq(tunnelIf.vrfName,"overlay-1")' 2>/dev/null 1>> $LOG_DIR"tunnel_dest_info.json" &
  icurl -g 'http://127.0.0.1:7777/api/node/class/vpcIf.json?query-target-filter=or(and(eq(vpcIf.localOperSt,"down"))and(eq(vpcIf.remoteOperSt,"down")))&rsp-subtree=children&rsp-subtree-class=vpcRsVpcConf' 2>/dev/null  1>> $LOG_DIR"vpc_db_info.json" &
  wait
  chmod -R 755 "$LOG_DIR"
fi

log "The following incorrect endpoint learns were found in $SCOPE vnid $VNID:" > $LOG_DIR$BAD_LEARN_FILE
echo "Note: In scenarios where an Endpoint is vpc_attached and one side of the vpc is down but that member is up, the extected TEP of the endpoint could be the VPC tep or the PTEP of the active leg." >> $LOG_DIR$BAD_LEARN_FILE

#Setup more global Vars from above mo's
REMOTE_LEAF_LIST=$(icurl 'http://127.0.0.1:7777/api/node/class/topSystem.json?query-target-filter=eq(topSystem.remoteNode,"yes")' 2>/dev/null | jq -r '.imdata[].topSystem.attributes.dn' | egrep -o "node\-[0-9]+" | egrep -o "[0-9]+" | tr '\n' ' ')
DCI_UCAST_TEP_LIST=$(icurl 'http://127.0.0.1:7777/api/node/class/dciAnycastExtn.json?query-target-filter=eq(dciAnycastExtn.is_ucast,"yes")' 2>/dev/null | jq -r '.imdata[].dciAnycastExtn.attributes.etep' | egrep -o "([0-9]+\.){3}[0-9]+" | sort | uniq | tr '\n' ' ')

#Get all overlay Interfaces
OVERLAY_IF_IP=$(cat $LOG_DIR"overlay_ips.json" | jq -r '.imdata'| egrep "dn|\"mode\"|\"addr\"")

#Get all l3 EPs
if [[ $SCOPE == "vrf" ]]; then
  L3_EP_INFO=$(cat $LOG_DIR"l3_ep_info.json" | jq -r '.imdata' | egrep "\"addr\"|\"dn\"|\"flags\"|\"ifId\"")
#Get all l2 EPs
elif [[ $SCOPE == "bd" ]]; then
  L2_EP_INFO=$(cat $LOG_DIR"l2_ep_info.json" | jq -r '.imdata' | egrep "\"addr\"|\"dn\"|\"flags\"|\"ifId\"")
fi
  
#Get all VTEPs. Used later for identying expected ptep for xr learns if one side of a vpc is down and the connected ep is local + vxlan (k8s, openstack, etc)
VTEP_INFO=$(cat $LOG_DIR"vtep_info.json" | jq -r '.imdata' | egrep "\"addr\"|\"dn\"|\"ifId\"")

#Get all tunnel destinations
TUNNEL_DST_INFO=$(cat $LOG_DIR"tunnel_dest_info.json" | jq -r '.imdata' | egrep "dn|\"id\"|\"dest\"|\"type\"")

#VPC info
VPC_DB_INFO=$(cat $LOG_DIR"vpc_db_info.json" | jq -r '.imdata' | egrep "\"id\"|\"localOperSt\"|\"remoteOperSt\"|\"fabricPathDn\"|\"tDn\"")

###Dictionary to contain tep to node mapping info
#Map tep to node(s) [ip] = [node(s)]
#Ex: 10.2.160.64[VPC_NODES  topology/pod-2/node-203 topology/pod-2/node-201]
unset ip_node_dic
declare -A ip_node_dic

###Dictionary to contain info about vpc member/legs that are down (used later determine if the expected tep for an EP is the PTEP or the VTEP)
#node-101-node-102_if10="node-101 node-102" <--this would indicate that for vpc if 10, both members are up
#node-101-node-102_if10="node-101" <--this would indicate that for vpc if 10, only node-101 side is up
unset vpc_dic
declare -A vpc_dic

###Dictionary to store mappings of port-channel id's to vpc id's.
#node-101_po6=if-##
unset vpc_mapping_dic
declare -A vpc_mapping_dic

#Save tep type [ip] = [type]
#Ex: 10.2.160.64[vpc]
unset ip_type_dic
declare -A ip_type_dic

###Dictionary to contain tunnel + dst tep info
#[node_if] = [dst_node or tep]
#Ex: topology/pod-1/node-102_tunnel7 , 10.0.216.65
unset tunnel_dest_dic
declare -A tunnel_dest_dic

###Dictionaries to contain ep mapping info
#Ep flags [node_ip] = [flags]
#Ex: topology/pod-2/node-201_192.168.254.101[ocal,vpc-attached]
unset l3_ep_flags_dic
declare -A l3_ep_flags_dic
unset l2_ep_flags_dic
declare -A l2_ep_flags_dic

#Local learns - [node_ip] = [interface]
#Ex: 192.168.254.101[topology/pod-2/node-201 topology/pod-2/node-203]
unset l3_local_ep_dic
declare -A l3_local_ep_dic
unset l2_local_ep_dic
declare -A l2_local_ep_dic

#XR learns - [node_ip] = [dst ip from tunnel]
#Ex: topology/pod-1/node-103_192.168.254.101 , 10.2.160.64
unset l3_xr_ep_dic
declare -A l3_xr_ep_dic
unset l2_xr_ep_dic
declare -A l2_xr_ep_dic

#vtep_db - [node_vtepip] = [dst ip from tunnel]
#Ex: topology/pod-1/node-103_192.168.254.101 , 10.2.160.64
unset vtep_dic
declare -A vtep_dic

#Indexed array of unique L3 Eps that are local, ptep, or vpc learned
#Ex: ("10.10.10.10" "10.10.10.11" "10.10.10.12")
unset unique_l3_ep_dic
declare -a unique_l3_ep_dic
unset unique_l2_ep_dic
declare -a unique_l2_ep_dic

#Expected TEP for each l3 ep - l3ep_expected_tep[ep] = tep
unset l3ep_expected_tep
declare -A l3ep_expected_tep
unset l2ep_expected_tep
declare -A l2ep_expected_tep

#Run the stuff!
log "Getting tep info..."
_get_tep_info
log "Checking for down VPC members and interfaces..."
_get_vpc_info  
log "Getting tunnel info from each node..."
_get_tunnel_info
log "Getting vtep info if applicable..."
_get_vtep_info
if [[ $SCOPE == "vrf" ]]; then
  _get_vtep_info
  log "Building database of ipv4 endpoint learns..."
  _get_l3_ep_info
  log "Checking for ipv4 endpoint incorrect learns.."
  _check_l3_endpoints
elif [[ $SCOPE == "bd" ]]; then
  log "Building database of ipv4 endpoint learns..."
  _get_l2_ep_info
  log "Checking for ipv4 endpoint incorrect learns.."
  _check_l2_endpoints
fi
log "Finished!"
if [[ $BAD_LEARN_COUNT > 0 ]]; then
  log "Found $BAD_LEARN_COUNT incorrect endpoint learns!"
  log "For a full list of bad learn information check: $LOG_DIR$BAD_LEARN_FILE"
else
  log "No incorrect endpoint learns were found!"
fi
log "All objects used by this checker are stored in: $LOG_DIR"
