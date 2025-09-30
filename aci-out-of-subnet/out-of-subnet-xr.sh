#!/bin/bash
#
#This script is showing out of subnets Remote EPs in the fabric.
#To be used to evaluate impact from enabling Global Subnet Check.
#
#Made by Igor Derybas

ip_in_subnet() {
    local ip=$1
    local subnet=$2

    # Split subnet into address and mask
    local subnet_ip=${subnet%/*}
    local mask_bits=${subnet#*/}

    # Convert dotted-quad to integer
    local ip_int=$(ip2int "$ip")
    local subnet_int=$(ip2int "$subnet_ip")

    # Build mask integer
    local mask=$(( 0xFFFFFFFF << (32 - mask_bits) & 0xFFFFFFFF ))

    # Compare masked values
    if (( (ip_int & mask) == (subnet_int & mask) )); then
        echo 1
    else
        echo 0
    fi
}

ip2int() {
    local IFS=.
    read -r o1 o2 o3 o4 <<< "$1"
    echo $(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
}

echo "Started checking Remote EPs at" `date`
echo ""

# Discover Subnets deployed with VRF names
subnets=$(moquery -c ipv4Addr -f 'ipv4.Addr.ctrl=="pervasive"' | grep dn | sed 's/^.*dom-//' | sed 's/\/if-.*addr-\[/__/' | sed 's/\]//'| sort | uniq)

# Discover all XR EPs with VRF VNID
xr=$(moquery -c epmIpEp -f 'epm.IpEp.flags=="ip"' | grep ^dn | sed 's/.*node-//' | sed 's/\/sys\/ctx-\[vxlan-/___/' | sed 's/\].*-\[/__/' | sed 's/\]//' | grep "__" | grep -v ":" )

# Discover VRF Names and VNIDs
vrf_vnid=$(moquery -c fvCtx  | egrep "dn|scope" | sed 's/^.*uni\/tn-/ /' | sed 's/\/ctx-/:/' | sed 's/^.*: /___/' | tr -d '\n' | tr " " "\n")

for i in $xr; do
	node=`echo $i | sed 's/___.*//'`
        vnid=`echo $i | sed 's/^.*___//' | sed 's/__.*//'`
        xr_ip=`echo $i | sed 's/^.*__//g'`

        for v in $vrf_vnid; do
            xr_vrf_temp=$(echo $v | grep $vnid | sed 's/___.*//')
	    if [ "$xr_vrf_temp" != "" ]; then
                xr_vrf=$xr_vrf_temp
	    fi
        done
        out_xr=1
        for s in $subnets; do
                sn=$(echo $s | grep $xr_vrf | sed 's/^.*__//')
                if [ "$sn" != "" ]; then
# Uncoment below line and comment next one if you want to see output for every good Remote EP inside a subnet.
#                        (( $(ip_in_subnet $xr_ip $sn) )) && echo "The $xr_ip on node-$node is part of $sn in VRF $xr_vrf" && out_xr=0
			(( $(ip_in_subnet $xr_ip $sn) )) && out_xr=0
                fi
        done
        if [ $out_xr == 1 ]; then
                echo "Remote EP $xr_ip on node-$node is out of subnets in VRF $xr_vrf"
        fi
done

echo ""
echo "Finished checking Remote EPs at" `date`
