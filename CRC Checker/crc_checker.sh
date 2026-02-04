#!/bin/bash
###########################################################################################################################
#author josephyo
#
#This script automates the collection of platform counters (normal, bv, and internal module) across all gen2+ aci switches
###########################################################################################################################

##################
#Define Functions#
##################
function log() {
    ts=$(date '+%Y-%m-%dT%H:%M:%S')
    echo "$ts" "$@"
}

#Define icurl as icurl binary is not available in root/ifc user context
if ! command -v icurl >/dev/null 2>&1; then
    icurl() {
        SESSION_FILE='/var/run/mgmt/shell-data/.webtoken.15374.txt'
        TOKEN=`cat ${SESSION_FILE}`
        curl --ipv4 -b "APIC-cookie=$TOKEN" "$@"
        echo
    }
fi

function global_conn_params() {
    myAddr=$(icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.name,"'"$HOSTNAME"'")' 2>/dev/null  | python3 -m json.tool | egrep  "\"address\"\:" | awk -F "\"" '{print $4}')
    username='apic#fallback\\admin'
	read -r -s -p "Enter admin Password: " pswd

    ssh_c='sshpass -p '$pswd' nohup ssh -f -o ServerAliveInterval=2 -o ServerAliveCountMax=1 -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -tq -b '$myAddr' '$username
}

function nodeExists () {
    local e match="$1"
    shift
    for e; do [[ "$e" == "$match" ]] && return 0; done
    return 1
}

#Determine what type of device the node is in order to build the correct commands.
function get_node_role() {
    node_dn=$(icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.id,"'"$node"'")' 2>/dev/null  | python -m json.tool | egrep  "\"dn\"\:" | awk -F "\"" '{print $4}')
    node_role=$(icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.id,"'"$node"'")' 2>/dev/null  | python -m json.tool | egrep  "\"role\"\:" | awk -F "\"" '{print $4}')

    if [[ $node_role == "spine" ]]; then
        if icurl 'http://localhost:7777/api/mo/'"$node_dn"'/ch.json' 2>/dev/null | python -m json.tool | egrep "model.*N9K-C95" 1>/dev/null; then
            node_role=mod_spine
            fm_list=$(icurl 'http://localhost:7777/api/mo/'"$node_dn"'/ch.json?rsp-subtree=children&rsp-subtree-class=eqptFCSlot&rsp-subtree-filter=eq(eqptFCSlot.operSt,"inserted")&rsp-subtree-include=required,no-scoped' 2>/dev/null | python -m json.tool | egrep  "\"physId\"\:" | awk -F "\"" '{print $4}' | sed -e 'H;${x;s/\n/ /g;s/^\s//;p;};d')
            lc_list=$(icurl 'http://localhost:7777/api/mo/'"$node_dn"'/ch.json?rsp-subtree=children&rsp-subtree-class=eqptLCSlot&rsp-subtree-filter=eq(eqptLCSlot.operSt,"inserted")&rsp-subtree-include=required,no-scoped' 2>/dev/null | python -m json.tool | egrep  "\"physId\"\:" | awk -F "\"" '{print $4}' | sed -e 'H;${x;s/\n/ /g;s/^\s//;p;};d')

        elif icurl 'http://localhost:7777/api/mo/'"$node_dn"'/ch.json' 2>/dev/null | python -m json.tool | egrep "model.*N9K-C93" 1>/dev/null; then
            node_role=fixed_spine

        else
            log "Node is a spine but couldn't determine if modular or fixed. Skipping node $node..."
        fi
    fi
}

#This function builds the commands to be passed through ssh to the leafs/spines.
#For modular spines we have to build a command (R_CMD)locally on the remote device that can then be passed through ssh
#from the sup to the module. This all has to be stored in variable CMD to pass to the remote spine.
#
#For fixed spines/leafs, there no need for R_CMD as it doesn't need to ssh to itself.
#
#This function also has to have customer syntax for each type of leaf/spine/module that supports bearValley because the
#PhyID and DevID is going to be different for each platform.
function build_remote_commands() {
CMD=""
#gen2_mod_spine
    if [[ $node_role == "mod_spine" ]]; then
        #Bear valley module
        if [[ $mod_model == N9K-X9736C-FX ]] ; then
            read -r -d '' CMD1 <<EOF
                mkdir -p /bootflash/admin;
                export HOME=/bootflash/admin;
                R_CMD='
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $clear_bv == yes ]] ; then
                    clear_bv=yes;
                    op=24;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                    op=22;
                fi;

                bv=(
                29 0 0
                30 0 1
                31 1 0
                32 1 1
                33 2 0
                34 2 1
                35 3 0
                36 3 1);

                n=29;
                i=0;
                p=1;
                d=2;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    /lc/isan/bin/vsh_lc -c "show platform internal counters port detail";
                    int_list=$(/lc/isan/bin/vsh_lc -c "show platform internal usd port info" | egrep -o "Int.{2}" | egrep -o "[0-9]+");
                    for int in $int_list; do
                        /lc/isan/bin/vsh_lc -c "show plat internal counters port internal $int";
                    done;

                    cat /dev/null > /var/tmp/logs/bv.log;
                fi;
                if [[ $clear_cnt == yes ]]; then
                    /lc/isan/bin/vsh_lc -c "clear platform internal counters port";
                    /lc/isan/bin/vsh_lc -c "clear platform internal counters port internal";
                fi;
                if [[ $clear_bv == yes ]] || [[ $dump_cnt == yes ]]; then
                    while [ $n -le 36 ]; do
                        echo "BV_PORT_${bv[$i]}_HOST_SIDE" >> /var/tmp/logs/bv.log;
                        /lc/isan/bin/vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 0 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        echo "BV_PORT_${bv[$i]}_LINE_SIDE" >> /var/tmp/logs/bv.log;
                        /lc/isan/bin/vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 1 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        n=$((n+1));
                        i=$((i+3));
                        p=$((p+3));
                        d=$((d+3));
                    done;
                fi;
                if [[ $dump_cnt == yes ]]; then
                    cat /var/tmp/logs/bv.log;
                fi;
                    ';
EOF
            CMD+='
            '
            CMD+="$CMD2"' sshpass -p root ssh -o StrictHostKeyChecking=no root@mod'$lc' "$R_CMD" '

        #Should match all gen 2 FM's
        elif [[ $mod_model =~ N9K-C95.*FM.* ]] ; then
            read -r -d '' CMD1 <<EOF
                mkdir -p /bootflash/admin;
                export HOME=/bootflash/admin;
                R_CMD='
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                fi;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    int_list=$(/lc/isan/bin/vsh_lc -c "show platform internal usd port info" | egrep -o "Int.{2}" | egrep -o "[0-9]+");
                    for int in $int_list; do
                        /lc/isan/bin/vsh_lc -c "show plat internal counters port internal $int";
                    done;
                fi;
                if [[ $clear_cnt == yes ]] ; then
                    /lc/isan/bin/vsh_lc -c "clear platform internal counters port internal";
                fi;
                ';
EOF
            CMD+='
            '
            CMD+="$CMD2"' sshpass -p root ssh -o StrictHostKeyChecking=no root@mod'$fm' "$R_CMD" '

        #For non BV LC's, commands to run should be the same
        else
            read -r -d '' CMD1 <<EOF
                mkdir -p /bootflash/admin;
                export HOME=/bootflash/admin;
                R_CMD='
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                fi;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    /lc/isan/bin/vsh_lc -c "show platform internal counters port detail";
                    int_list=$(/lc/isan/bin/vsh_lc -c "show platform internal usd port info" | egrep -o "Int.{2}" | egrep -o "[0-9]+");
                    for int in $int_list; do
                        /lc/isan/bin/vsh_lc -c "show plat internal counters port internal $int";
                    done;
                fi;
                if [[ $clear_cnt == yes ]] ; then
                    /lc/isan/bin/vsh_lc -c "clear platform internal counters port";
                    /lc/isan/bin/vsh_lc -c "clear platform internal counters port internal";
                fi;
                ';
EOF
            CMD+='
            '
            CMD+="$CMD2"' sshpass -p root ssh -o StrictHostKeyChecking=no root@mod'$lc' "$R_CMD" '

        fi
    fi

#gen2_fixed_spine
    if [[ $node_role == "fixed_spine" ]]; then

        #For N9K-C9364C BV ports are p49-64
        if [[ $mod_model =~ N9K-C9364C ]] ; then
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $clear_bv == yes ]] ; then
                    clear_bv=yes;
                    op=24;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                    op=22;
                fi;

                bv=(
                49 0 1
                50 0 0
                51 1 0
                52 1 1
                53 2 0
                54 2 1
                55 3 0
                56 3 1
                57 4 1
                58 4 0
                59 5 0
                60 5 1
                61 6 1
                62 6 0
                63 7 1
                64 7 0);

                n=49;
                i=0;
                p=1;
                d=2;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                    cat /dev/null > /var/sysmgr/tmp_logs/bv.log;
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;

                if [[ $clear_bv == yes ]] || [[ $dump_cnt == yes ]]; then
                    while [ $n -le 64 ]; do
                        echo "BV_PORT_${bv[$i]}_HOST_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 0 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        echo "BV_PORT_${bv[$i]}_LINE_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 1 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        n=$((n+1));
                        i=$((i+3));
                        p=$((p+3));
                        d=$((d+3));
                    done;
                fi;
                if [[ $dump_cnt == yes ]]; then
                    cat /var/sysmgr/tmp_logs/bv.log;
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"

        #For N9K-C9332C BV ports are p25-32
        elif [[ $mod_model =~ N9K-C9332C ]] ; then
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $clear_bv == yes ]] ; then
                    clear_bv=yes;
                    op=24;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                    op=22;
                fi;

                bv=(
                25 0 1
                26 0 0
                27 1 1
                28 1 0
                29 2 1
                30 2 0
                31 3 1
                32 3 0);

                n=25;
                i=0;
                p=1;
                d=2;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                    cat /dev/null > /var/sysmgr/tmp_logs/bv.log;
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;

                if [[ $clear_bv == yes ]] || [[ $dump_cnt == yes ]]; then
                    while [ $n -le 32 ]; do
                        echo "BV_PORT_${bv[$i]}_HOST_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 0 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        echo "BV_PORT_${bv[$i]}_LINE_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 1 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        n=$((n+1));
                        i=$((i+3));
                        p=$((p+3));
                        d=$((d+3));
                    done;
                fi;
                if [[ $dump_cnt == yes ]]; then
                    cat /var/sysmgr/tmp_logs/bv.log;
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"
        else
        #Handle non-bv, gen2+ fixed spines
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                fi;

EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"
        fi
    fi

#gen2_leaf
    if [[ $node_role == "leaf" ]]; then

        #For N9K-C9336C-FX2, bv ports are p1-6 , p33-36
        if [[ $mod_model =~ N9K-C9336C-FX2 ]] ; then
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $clear_bv == yes ]] ; then
                    clear_bv=yes;
                    op=24;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                    op=22;
                fi;

                bv=(
                1 0 0
                2 0 1
                3 1 0
                4 1 1
                5 2 0
                6 2 1
                33 3 0
                34 3 1
                35 4 0
                36 4 1);

                n=1;
                i=0;
                p=1;
                d=2;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                    cat /dev/null > /var/sysmgr/tmp_logs/bv.log;
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;

                if [[ $clear_bv == yes ]] || [[ $dump_cnt == yes ]]; then
                    while [ $n -le 10 ]; do
                        echo "BV_PORT_${bv[$i]}_HOST_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 0 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        echo "BV_PORT_${bv[$i]}_LINE_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 1 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        n=$((n+1));
                        i=$((i+3));
                        p=$((p+3));
                        d=$((d+3));
                    done;
                fi;
                if [[ $dump_cnt == yes ]]; then
                    cat /var/sysmgr/tmp_logs/bv.log;
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"

        #For N9K-C93240YC-FX2, bv ports are p51-54
        elif [[ $mod_model =~ N9K-C93240YC-FX2 ]] ; then
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $clear_bv == yes ]] ; then
                    clear_bv=yes;
                    op=24;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                    op=22;
                fi;

                bv=(
                51 0 0
                52 1 0
                53 1 1
                54 0 1);

                n=51;
                i=0;
                p=1;
                d=2;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                    cat /dev/null > /var/sysmgr/tmp_logs/bv.log;
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;

                if [[ $clear_bv == yes ]] || [[ $dump_cnt == yes ]]; then
                    while [ $n -le 54 ]; do
                        echo "BV_PORT_${bv[$i]}_HOST_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 0 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        echo "BV_PORT_${bv[$i]}_LINE_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 1 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        n=$((n+1));
                        i=$((i+3));
                        p=$((p+3));
                        d=$((d+3));
                    done;
                fi;
                if [[ $dump_cnt == yes ]]; then
                    cat /var/sysmgr/tmp_logs/bv.log;
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"

        #For N9K-C93360YC-FX2, bv ports are p97-108
        elif [[ $mod_model =~ N9K-C93360YC-FX2 ]] ; then
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $clear_bv == yes ]] ; then
                    clear_bv=yes;
                    op=24;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                    op=22;
                fi;

                bv=(
                97 0 1
                98 0 0
                99 1 1
                100 1 0
                101 2 0
                102 2 1
                103 3 1
                104 3 0
                105 4 1
                106 4 0
                107 5 1
                108 5 0);

                n=97;
                i=0;
                p=1;
                d=2;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                    cat /dev/null > /var/sysmgr/tmp_logs/bv.log;
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;

                if [[ $clear_bv == yes ]] || [[ $dump_cnt == yes ]]; then
                    while [ $n -le 108 ]; do
                        echo "BV_PORT_${bv[$i]}_HOST_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 0 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        echo "BV_PORT_${bv[$i]}_LINE_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 1 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        n=$((n+1));
                        i=$((i+3));
                        p=$((p+3));
                        d=$((d+3));
                    done;
                fi;
                if [[ $dump_cnt == yes ]]; then
                    cat /var/sysmgr/tmp_logs/bv.log;
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"

        #For N9K-C93216TC-FX2, bv ports are p97-108
        elif [[ $mod_model =~ N9K-C93216TC-FX2 ]] ; then
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $clear_bv == yes ]] ; then
                    clear_bv=yes;
                    op=24;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                    op=22;
                fi;

                bv=(
                97 0 1
                98 0 0
                99 1 1
                100 1 0
                101 2 1
                102 2 0
                103 3 1
                104 3 0
                105 4 1
                106 4 0
                107 5 1
                108 5 0);

                n=97;
                i=0;
                p=1;
                d=2;
EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                    cat /dev/null > /var/sysmgr/tmp_logs/bv.log;
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;

                if [[ $clear_bv == yes ]] || [[ $dump_cnt == yes ]]; then
                    while [ $n -le 108 ]; do
                        echo "BV_PORT_${bv[$i]}_HOST_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 0 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        echo "BV_PORT_${bv[$i]}_LINE_SIDE" >> /var/sysmgr/tmp_logs/bv.log;
                        vsh_lc -c "debug platform internal usd bearvalley op $op phy-id ${bv[$p]} side 1 lane 0 dev-id ${bv[$d]} reg-val 0xffffffff data 0";
                        n=$((n+1));
                        i=$((i+3));
                        p=$((p+3));
                        d=$((d+3));
                    done;
                fi;
                if [[ $dump_cnt == yes ]]; then
                    cat /var/sysmgr/tmp_logs/bv.log;
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"

        #Get counters for non-bv, gen2+ leafs. Note, even though the 93180yc-fx3 (sundown) has a BV retimer on every port, it is operating in transparent mode which means that the BV itself doesn't record stats. Because of this, just getting the "show plat internal counters..." should be sufficient
        else
            read -r -d '' CMD1 <<EOF
                if [[ $clear_cnt == yes ]] ; then
                    clear_cnt=yes;
                fi;
                if [[ $dump_cnt == yes ]] ; then
                    dump_cnt=yes;
                fi;

EOF
            CMD+="$CMD1"
            read -r -d '' CMD2 <<'EOF'
                if [[ $dump_cnt == yes ]]; then
                    vsh_lc -c "show platform internal counters port detail";
                fi;

                if [[ $clear_cnt == yes ]]; then
                    vsh_lc -c "clear platform internal counters port";
                fi;
EOF
            CMD+='
            '
            CMD+="$CMD2"
        fi
    fi

}

#This function sends the commands to the remote node through ssh. For each module on a modular spine, a separate connection is built. For each leaf/fixed-spine, one connection is built.
function connect() {
    nodeAddr=$(icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.id,"'"$1"'")' 2>/dev/null  | python -m json.tool | egrep  "\"address\"\:" | awk -F "\"" '{print $4}')

    if [[ $node_role == "mod_spine" ]]; then
        for lc in $lc_list; do
            mod_model=$(icurl 'http://localhost:7777/api/mo/'"$node_dn"'/ch/lcslot-'"$lc"'/lc.json' 2>/dev/null  | python -m json.tool | egrep  "\"model\"\:" | awk -F "\"" '{print $4}')

            build_remote_commands
            CMD=$(echo "$CMD" | perl -pe 's/^\s+//g')

            log "Starting connection to node $1 linecard $lc (model: $mod_model)..."
            echo "Connecting to node $1 at $nodeAddr: module $lc..." > $DIR/node-$1.txt
            if [[ $nodeAddr != "" ]]; then
                echo "NODE $node_dn : MOD $lc : MODEL $mod_model" > $DIR/node-$1-mod-$lc.txt
                $ssh_c@$nodeAddr "$CMD" 1>>$DIR/node-$1-mod-$lc.txt 2>>$DIR/node-$1-mod-$lc-Err.txt
                exit_code=$?
                    if [ "$exit_code" -eq 5 ]; then
                        log "Failed to connect to $1 due to incorrect/invalid password"
                        exit 1
                    elif [ "$exit_code" -ne 0 ]; then
                        log "Failed to connect to $1 (exit code: $exit_code)"
                        log "$(cat "$DIR/node-$1-mod-$lc-Err.txt")"
                    fi
            else
                log "Non-existent node-id, skipping $1"
            fi
        done

        for fm in $fm_list; do
            fm_num=$(echo $fm | cut -b2)
            mod_model=$(icurl 'http://localhost:7777/api/mo/'"$node_dn"'/ch/fcslot-'"$fm_num"'/fc.json' 2>/dev/null  | python -m json.tool | egrep  "\"model\"\:" | awk -F "\"" '{print $4}')

            build_remote_commands
            CMD=$(echo "$CMD" | perl -pe 's/^\s+//g')

            log "Starting connection to node $1 fabric module $fm (model: $mod_model)..."
            echo "Connecting to node $1 at $nodeAddr: module $fm..." > $DIR/node-$1.txt
            if [[ $nodeAddr != "" ]]; then
                echo "NODE $node_dn : MOD $fm : MODEL $mod_model" > $DIR/node-$1-mod-$fm.txt
                $ssh_c@$nodeAddr "$CMD" 1>>$DIR/node-$1-mod-$fm.txt 2>>$DIR/node-$1-mod-$fm-Err.txt
                exit_code=$?
                    if [ "$exit_code" -eq 5 ]; then
                        log "Failed to connect to $1 due to incorrect/invalid password"
                        exit 1
                    elif [ "$exit_code" -ne 0 ]; then
                        log "Failed to connect to $1 (exit code: $exit_code)"
                        log "$(cat "$DIR/node-$1-mod-$lc-Err.txt")"
                    fi
            else
                log "Non-existent node-id, skipping $1"
            fi
        done
    fi

    if [[ $node_role == "leaf" ]] || [[ $node_role == "fixed_spine" ]]; then
        mod_model=$(icurl 'http://localhost:7777/api/mo/'"$node_dn"'/ch.json' 2>/dev/null  | python -m json.tool | egrep  "\"model\"\:" | awk -F "\"" '{print $4}')

        build_remote_commands
        CMD=$(echo "$CMD" | perl -pe 's/^\s+//g')

        log "Starting connection to node $1 $node_role (model: $mod_model)..."
        echo "Connecting to node $1 at $nodeAddr..." > $DIR/node-$1.txt
        if [[ $nodeAddr != "" ]]; then
            echo "NODE $node_dn : : MODEL $mod_model" > $DIR/node-$1.txt
            $ssh_c@$nodeAddr "$CMD" 1>>$DIR/node-$1.txt 2>>$DIR/node-$1Err.txt
            exit_code=$?
                if [ "$exit_code" -eq 5 ]; then
                    log "Failed to connect to $1 due to incorrect/invalid password"
                    exit 1
                elif [ "$exit_code" -ne 0 ]; then
                    log "Failed to connect to $1 (exit code: $exit_code)"
                    log "$(cat "$DIR/node-$1-mod-$lc-Err.txt")"
                fi
        else
            log "Non-existent node-id, skipping $1"
        fi
    fi
}

#Once script has run, this function takes FCS errors, CRC/Stomps, and TX Frame Errors from the output files and sorts into a single file - /data/techsupport/int_counters/summary_sorted.txt
function display_counters() {
    if [[ -d "$DIR" ]]; then
        if [[ -f "$DIR"/summary_sorted.txt ]]; then
            cat "$DIR"/summary_sorted.txt
        else
            rm -f "$DIR"/summary.txt
            regex_search='BV\_PORT.*|CRC\sErr\s\(Stomped\).*|RX\_CRCERR.*|RX\_FCS\_ERR.*|Frames\sReceived\swith\sFCS\sErr.*|TX\_FRM\_ERROR.*|eth\-\S*|Int[0-9]+\S*|Frames\sTransmitted\swith\sErr.*|MAC\sStats.*Channel\s+\S+'

            printf "%-20s %-40s %-13s %-13s %s\n" "NodeID" "Interface" "RX_FCS_Error" "RX_CRC_Stomp" "TX_Frame_Error" >> "$DIR"/summary.txt

            #Handle eth-x/y ports
            egrep -o "$regex_search" "$DIR"/node* | sed -e "s@$DIR/@@g"  | egrep -A 3 "eth\-\S*" | sed -re 's/^.*ERR\S*\s*//g' | tr '\r\n' ' ' | sed -e 's/node/\nnode/g' | sed -e 's/\.txt:/ /g' | awk '{ printf "%-20s %-40s %-13s %-13s %s\n", $1,$2,$3,$4,$5}' >> "$DIR"/summary.txt

            #Handle Int[0-9]+ ports
            egrep -o "$regex_search" "$DIR"/node* | sed -e "s@$DIR/@@g" | egrep -A 3 "Int[0-9]+.*" | sed -re 's/^.*ERR\S*\s*//g' | tr '\r\n' ' ' | sed -e 's/node/\nnode/g' | sed -e 's/\.txt:/ /g' | awk '{ printf "%-20s %-40s %-13s %-13s %s\n", $1,$2,$3,$4,$5}' >> "$DIR"/summary.txt

            #Handle BV_PORT
            egrep -o "$regex_search" "$DIR"/node* | sed -e "s@$DIR/@@g" | grep -B 1 -A 3  "\sChannel\s" | sed -re 's/^.*MAC\sStats.*Channel\s*/-Channel-/g' | sed -re 's/^.*Err.*:\s+//g' | sed -e 's/\.txt:/ /g' | tr '\r\n' ' ' | sed -e 's/node/\nnode/g' | sed -e 's/--//g' > "$DIR"/bv_ports.txt

            while IFS='' read -r line || [[ -n "$line" ]]; do
                bv_list=($line)
                wc=${#bv_list[@]}
                    if [[ $wc -gt 6 ]]; then
                        n=${bv_list[0]}
                        i=${bv_list[1]}

                        while [ "$wc" -ge 6 ] ; do
                            printf "%-20s %-40s %-13s %-13s %s\n" "$n" "$i${bv_list[2]}" "${bv_list[3]}" "${bv_list[4]}" "${bv_list[5]}" >> "$DIR"/summary.txt
                            unset 'bv_list[2]'
                            unset 'bv_list[3]'
                            unset 'bv_list[4]'
                            unset 'bv_list[5]'
                            tmp=${bv_list[@]}
                            bv_list=($tmp)
                            wc=${#bv_list[@]}
                        done
                    else
                        printf "%-20s %-40s %-13s %-13s %s\n" "${bv_list[0]}" "${bv_list[1]}${bv_list[2]}" "${bv_list[3]}" "${bv_list[4]}" "${bv_list[5]}" >> "$DIR"/summary.txt
                    fi
            done < "$DIR"/bv_ports.txt
            sed -i '/^\s*$/d' "$DIR"/summary.txt

            #Read output. k3 is fcs errors, k4 is rx stomps, k5 is tx frame errors
            cat "$DIR"/summary.txt | (sed -u 1q; sort -k3 -k4 -k5 -b -rn) > "$DIR"/summary_sorted.txt
            log "Sorted summary of Errors available at $DIR/summary_sorted.txt"
            cat "$DIR"/summary_sorted.txt | egrep -v "\s0\s+0\s+0$" | more
        fi
    else
        log "Counters from previous script run were not found at $DIR."
        log "Please get counters using the -d option before formatting data."
        log "Exiting..."
        exit 1
    fi
}

#####HELP
function display_help() {
    echo -e \\n"Help documentation for $0"\\n
    echo "****************************************************************************************************"
    echo "This script automates collection of platform level interface counters across all gen2+ ACI switches"
    echo "Using the -d option it supports getting interface counters for:"
    echo "    -Normal platform interface counters"
    echo "    -Internal interface counters on line cards and fabric modules"
    echo "    -BearValley interface counters on platforms that support it"
    echo ""
    echo "The script requires a root password!"
    echo ""
    echo "Once counters are collected, it is organized using the -s option into a listed sorted by FCS Errors,"
    echo "CRC Stomps, and TX Frame Errors"
    echo ""
    echo "It also supports clearing platform counters."
    echo ""
    echo "Supported Options:"
    echo "n:    Specify list of node id's separated by commands. Use 'all' keyword to execute for all nodes. -n"
    echo "      is required if dumping or clearing counters."
    echo "d:    Get interface counters. Can't be used in conjunction with the clear options. Automatically"
    echo "      displays sorted summary of FCS, CRC/Stomps, and TX Frame Errors after collection."
    echo "c:    Clear platform counters (excluding BearValley counters). Can't be used in conjunction -d."
    echo "x:    Clear BearValley counters. Can't be used in conjunction -d."
    echo ""
    echo "Example Usage:"
    echo "      /tmp/crc_checker.sh -n all -d <--collect platform counters for all gen2+ nodes"
    echo "      /tmp/crc_checker.sh -n all -x -c <--clear platform and BearValley counters for all gen2+ nodes"
    echo "      /tmp/crc_checker.sh -n 1001,1002 -c <--clear platform counters for nodes 1001 and 1002"
    echo ""
    echo "All outputs are logged to /data/techsupport/int_counters"
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

##################
#Define Variables#
##################

DIR="/data/techsupport/int_counters_$(date +%Y-%m-%dT%H:%M:%S)"
dump_cnt=no
clear_cnt=no
clear_bv=no

#####Take Args from Command
optspec="n:dcxh"
while getopts "$optspec" optchar; do
  case $optchar in
    n)
        if [[ $OPTARG == "all" ]]; then
            nodeList=$(icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=ne(topSystem.role,"controller")' 2>/dev/null  | python -m json.tool | egrep  "\"id\"\:" | awk -F "\"" '{print $4}' | sed -e 'H;${x;s/\n/ /g;s/^\s//;p;};d')
        else
            nodeList=$(echo "$OPTARG" | sed -e "s/,/ /g")
        fi
        ;;
    d)
        #dump interface counters
        dump_cnt=yes
        ;;
    c)
        #clear platform counters
        clear_cnt=yes
        ;;
    x)
        #clear bv mac stats
        clear_bv=yes
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
if [ -z ${nodeList+x} ]; then
    log "List of node id's are required using -n option. Check the -h/--h/--help for options"
    exit 1
fi

if [[ $dump_cnt == "yes" ]] && ( [[ $clear_cnt == "yes" ]] || [[ $clear_bv == "yes" ]] ); then
    log "Specify -d OR (-x and/or -c). Don't specify -d AND the clear stats options."
    exit 1
fi

if [[ $dump_cnt == "no" ]] && [[ $clear_cnt == "no" ]] && [[ $clear_bv == "no" ]]; then
    log "Please specify to dump or clear counters. Check the -h/--h/--help for options"
    exit 1
fi

rm -rf "$DIR"
mkdir -p "$DIR"

#make sure this is gen2 and remove gen 1 nodes from $nodeList
nodeList_gen1=$(icurl 'http://localhost:7777/api/class/eqptSilicon.json?query-target-filter=and(and(eq(eqptSensor.type,"asic"))and(wcard(eqptSilicon.model,"Alpine|Donner|Trident")))' 2>/dev/null | python -m json.tool | grep dn | egrep -o "node\-[0-9]+" | sort | uniq | sed -e 's/^node\-//g' | sed -e 'H;${x;s/\n/ /g;s/^\s//;p;};d')

log "Removing gen 1 nodes from list... Gen 1 nodes are not supported."
for n in $nodeList_gen1; do
    nodeList=$(echo "$nodeList" | sed -e "s/\b$n\b/ /g")
done

#Test if all nodes in nodeList exist. Remove non-existent nodes.
node_arr=( $(icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=ne(topSystem.role,"controller")' 2>/dev/null  | python -m json.tool | egrep  "\"id\"\:" | awk -F "\"" '{print $4}' | sed -e 'H;${x;s/\n/ /g;s/^\s//;p;};d') )
for node in $nodeList; do
    if ! nodeExists "$node" "${node_arr[@]}"; then
        log "Node $node doesn't exist"
        nodeList=$(echo "$nodeList" | sed -e "s/\b$node\b/ /g")
    fi
done

if [[ -z "${nodeList// }" ]]; then
    log "No existent node id's found. Exiting..."
    exit 1
fi

log "List of nodes to process: $nodeList"

#Set parameters for ssh
global_conn_params

#Do Things
log "Starting to process nodes..."
max_jobs=10
for node in $nodeList; do
    # Wait if we've reached max concurrent jobs
    while [ $(jobs -r | wc -l) -ge $max_jobs ]; do
        sleep 0.1
    done
    
    {
        log "Processing node $node..."
        get_node_role "$node"
        connect "$node"
        log "Completed dispatching connections for node $node"
    } &
done

#Since ssh uses the -f option to background the threads but doesn't set the PID to be a child of the main script PID, setting script to wait 30 seconds for all threads to complete before finishing.
if [[ $dump_cnt == "yes" ]]; then
    log "All connections dispatched. Waiting for background threads to complete (30 seconds)..."
    for (( c=30; c>=0; c-- )); do
        if [[ $((c % 10)) -eq 0 ]]; then
            log "Waiting for threads... ($c seconds remaining)"
        fi
        sleep 1
    done
    log "Wait period complete. All threads should be finished."
    log "Raw command outputs are collected at $DIR"
    log "Generating sorted summary..."
    display_counters
else
    log "All connections dispatched. Waiting for background threads to complete (30 seconds)..."
    for (( c=30; c>=0; c-- )); do
        if [[ $((c % 10)) -eq 0 ]]; then
            log "Waiting for threads... ($c seconds remaining)"
        fi
        sleep 1
    done
    log "Wait period complete. All threads should be finished."
    log "Raw command outputs are collected at $DIR"
fi
