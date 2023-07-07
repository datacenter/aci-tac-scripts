# mcast-validator

This tool is intended to verify and assist in troubleshooting routed multicast (PIM enabled) in ACI.

# Usage
1. Place the mcast_validator file in the apic.
2. cd to the location of the file.
3. Execute - ```./mcast_validator```

The tool will prompt for user inputs or inputs can be supplied at the command line. Refer to the help documentation for argument examples.

The tool also allows for option datapath debugging using the ftriage tool which automates end to end elams of the flow. Elams are a 'tripwire' in hardware where a condition is set and the first packet that matches the condition trips it, dumping a large amount of information about what the asic is doing.

There is no impact to running this tool as it only uses show commands and API GET requests.

# Limitations
This tool can assist with verifying the following routed multicast topologies:
- Mcast source is EXTERNAL to ACI (behind l3out) AND mcast receiver is INTERNAL to ACI (endpoint)
- Mcast source is INTERNAL to ACI (endpoint) AND mcast receiver is EXTERNAL to ACI (behind l3out)
- Both mcast source AND mcast receiver are INTERNAL to ACI (learned endpoints)
- Both mcast source AND mcast receiver are EXTERNAL to ACI (multicast transit routing)

It does not support the following topologies:
- Intersite multicast
- Intervrf multicast (vrf transit occurs inside of ACI, if an external device does vrf stitching this is fine)
- Additionally, while it validates many things both at the APIC and switch level, it does not validate route-maps do to the complexity this would entail.

The tool relies on many different API calls (GETs only) and show outputs, both at the switch and APIC level. Its possible some api calls will fail if switches are on a much older version than the apic.

# Help Documentation
```
usage: mcast_validator [-h] [-u USERNAME] [-t TENANT] [-v VRF] [-r RCVR]
                       [-s SRC] [-g GROUP]

This code orchestrates debugging of multicast routing in ACI.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Specify the username used for remote connections.
  -t TENANT, --tenant TENANT
                        Specify the tenant name of the multicast flow
  -v VRF, --vrf VRF     Specify the vrf name of the multicast flow
  -r RCVR, --rcvr RCVR  Specify the IP address of the multicast receiver
  -s SRC, --src SRC     Specify the IP address of the multicast source
  -g GROUP, --group GROUP
                        Specify the IP address of the multicast group
```

# Example Usage
In this example the source is not active and thus none of the necessary devices have the source installed. Its important to note anywhere the script reports a FAILURE. Datapath testing at the end also confirmed the traffic wasn't being received from the source.
```
apic1# ./mcast_validator -u josephyo -t jy -v l3vrf1 -r 39.99.61.0 -s 192.168.255.100 -g 229.0.0.103
Describe the multicast topology:
1. Mcast source is EXTERNAL to ACI (behind l3out) AND mcast receiver is INTERNAL to ACI (endpoint)
2. Mcast source is INTERNAL to ACI (endpoint) AND mcast receiver is EXTERNAL to ACI (behind l3out)
3. Both mcast source AND mcast receiver are INTERNAL to ACI (learned endpoints)
4. Both mcast source AND mcast receiver are EXTERNAL to ACI (multicast transit routing)
Enter your choice (1-4), or 'q' to quit: 4
EDT 2023-07-07T09:31:59.257||INFO||Pim is correctly enabled on Vrf uni/tn-jy/ctx-l3vrf1.
EDT 2023-07-07T09:31:59.257||INFO||VRF GIPO used for L3 Multicast Flooding - 225.1.192.96/32
EDT 2023-07-07T09:31:59.437||INFO||The following PIM-enabled l3outs were found in tn-jy/ctx-l3vrf1:
['uni/tn-jy/out-randomL3out', 'uni/tn-jy/out-mc-l3out']
EDT 2023-07-07T09:31:59.520||INFO||Pim-enabled loopbacks were found on BL's for Vrf uni/tn-jy/ctx-l3vrf1.
EDT 2023-07-07T09:31:59.521||INFO||The following pim-enabled loopbacks were found in vrf uni/tn-jy/ctx-l3vrf1:
node-202            ['202.202.202.202']
node-201            ['201.201.201.201']
node-203            ['203.203.203.203']
EDT 2023-07-07T09:31:59.602||INFO||Static RP not configured in VRF uni/tn-jy/ctx-l3vrf1.
EDT 2023-07-07T09:31:59.670||INFO||Fabric RP not configured in VRF uni/tn-jy/ctx-l3vrf1.
EDT 2023-07-07T09:31:59.749||INFO||Auto RP is enabled in VRF uni/tn-jy/ctx-l3vrf1
EDT 2023-07-07T09:31:59.824||INFO||BSR RP not enabled in VRF uni/tn-jy/ctx-l3vrf1.
EDT 2023-07-07T09:31:59.825||INFO||BEGINNING SWITCH-LEVEL MULTICAST FORWARDING CHECKS!
Enter password used for remote connections:
EDT 2023-07-07T09:32:03.576||INFO||Determining stripe-winner. The stripe winner is responsible for sending PIM joins back to the source and/or RP.
EDT 2023-07-07T09:32:09.976||INFO||Stripe winner for group 229.0.0.103 is node ['203'] , loopback 203.203.203.203
EDT 2023-07-07T09:32:09.977||INFO||Checking that external outgoing interfaces exist in vrf uni/tn-jy/ctx-l3vrf1
EDT 2023-07-07T09:32:10.093||INFO||The following external OUTGOING interfaces interfaces were found in vrf uni/tn-jy/ctx-l3vrf1:
Mroute: (0.0.0.0, 229.0.0.103)
          {'202': ['eth1/8.50']}
EDT 2023-07-07T09:32:10.093||INFO||Checking that external incoming interfaces exist in vrf uni/tn-jy/ctx-l3vrf1
EDT 2023-07-07T09:32:10.205||INFO||The following external INCOMING interfaces were found in vrf uni/tn-jy/ctx-l3vrf1:
Mroute: (0.0.0.0, 229.0.0.103)
          {'203': ['eth1/9.103']}
EDT 2023-07-07T09:32:10.205||INFO||Checking if operational RP exists for group 229.0.0.103 on each node...
EDT 2023-07-07T09:32:14.410||INFO||Operational RP was found on each node for group 229.0.0.103.
Role Index - SL is Source Leaf, BL is Border Leaf, RL is Receiver Leaf


node-203 mroute checks: Role - ['BL']
    Source: *    Group: 229.0.0.103    :
      Incoming Interface: Ethernet1/9.103
      RPF Neighbor: 39.99.2.0
        INFO: External PIM Neighbor found matching RPF neigh 39.99.2.0
      Outgoing Interface(s): ['Tunnel24']


node-202 mroute checks: Role - ['BL']
    Source: *    Group: 229.0.0.103    :
      Incoming Interface: Tunnel10
      RPF Neighbor: 10.2.168.65
        INFO: Fabric internal PIM neighbor node-201/201.201.201.201 found matching RPF neigh 10.2.168.65
      Outgoing Interface(s): ['Ethernet1/8.50']


EDT 2023-07-07T09:32:19.827||WARNING||FAILURE - No S,G tree matching 192.168.255.100,229.0.0.103 was found on stripe winner node - 203! If source is external this is incorrect. Is the source correct? Is the multicast flow being received by ACI?


EDT 2023-07-07T09:32:19.827||INFO||Validating that multicast group is installed as /32 in hardware on both internal and border leafs.
EDT 2023-07-07T09:32:23.963||INFO||Group 229.0.0.103 is installed in hardware on nodes ['203', '202']
EDT 2023-07-07T09:32:23.963||INFO||Group 229.0.0.103 is correctly installed in hardware on stripe-winner node 203.
EDT 2023-07-07T09:32:23.963||INFO||Validating that src is installed as /32 in hardware on BLs with incoming and outgoing external interfaces
EDT 2023-07-07T09:32:28.014||WARNING||FAILURE - Src 192.168.255.100 is NOT installed in hardware on any Border Leaf Nodes. Is dataplane active? Is it making it to ACI? Does the BL have a route to the source?
EDT 2023-07-07T09:32:28.014||INFO||Current apic version support datapath debugging for L3 Multicast via Ftriage!
Execute datapath debugging for multicast flow? (Note: This test may take up to 15 mins to complete): (y/n)
y
EDT 2023-07-07T09:32:45.848||INFO||Beginning dataplane testing for flow using ftriage. Ftriage is a tool that orchestrates ELAMs end to end. There is no impact to this test but please be patient
Starting ftriage
Log file name for the current run is: ftlog_2023-07-07-09-32-46-487.txt
2023-07-07 09:32:46,492 INFO     /controller/bin/ftriage -user josephyo route -ii LEAF:203 -dip 229.0.0.103 -sip 192.168.255.100
Request password info for username: josephyo
Password:
2023-07-07 09:33:26,808 INFO     ftriage:     main:2064 Invoking ftriage with username: josephyo
2023-07-07 09:34:47,843 ERROR    ftriage:     main:1511 Failed to capture L3 packet on {a2-leaf3: []}
2023-07-07 09:34:47,843 ERROR    ftriage:     main:1511 Failed to capture L3 packet on {a2-leaf3: []}
2023-07-07 09:34:47,843 INFO     ftriage:     main:1515 : Ftriage Completed with hunch: Packet capture failed.
EDT 2023-07-07T09:34:48.196||INFO||FINISHED!
```

# Additional Information
- Examples of how the ftriage tool works (and ELAM) can be found here - https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/application-policy-infrastructure-controller-apic/217995-troubleshoot-aci-intra-fabric-forwarding.html
- This tool was built using pyInstaller. The source python code that it was built from is in the pythonSource folder
