# crc_checker

This tool is designed to automate clearing, collection, and formatting/sorting of platform counters for all gen 2 and later aci leafs and spines from an APIC.

# IMPORTANT UPDATE
This tool is natively included in version 6.1(4) and later. To execute simply run:
`acidiag show fabric crc-counters --nodes ...`

# Quick Usage
###### Method 1
1. SSH to the APIC
2. ```cd /tmp```
3. ```vim crc_checker.sh```
4. Copy the entire script to your clipboard
5. Paste it into the crc_checker file
6. Type ```ESC``` and then ```:wq!```
7. Set permissions with ```chmod 777 /tmp/crc_checker.sh```
8. Execute: ```/tmp/crc_checker.sh ARGS```

###### Method 2
Have the customer scp/sftp the script into ```/tmp``` on the apic.

Then set permissions and execute:
```chmod 777 /tmp/crc_checker.sh```
```/tmp/crc_checker.sh ARGS```

###### Examples
```/tmp/crc_checker.sh -n all -d``` <--collect platform counters for all gen2+ nodes

```/tmp/crc_checker.sh -n all -x -c``` <--clear platform and (including BearValley counters) for all gen2+ nodes

```/tmp/crc_checker.sh -n 1001,1002 -c``` <--clear platform counters for nodes 1001 and 1002

```/tmp/crc_checker.sh -s``` <--created sorted list of FCS, CRC/Stomps, and TX Frame Errors based on last counters in /data/techsupport/int_counters
 
All outputs are logged to /data/techsupport/int_counters

# Help Documentation
The script supports the following options:
```
admin@a-apic1:tmp> ./crc_checker.sh -h
 
Help documentation for ./crc_checker.sh
 
****************************************************************************************************
This script automates collection of platform level interface counters across all gen2+ ACI switches
Using the -d option it supports getting interface counters for:
    -Normal platform interface counters
    -Internal interface counters on line cards and fabric modules
    -BearValley interface counters on platforms that support it
 
The script requires a admin password!
 
Once counters are collected, it is organized using the -s option into a listed sorted by FCS Errors,
CRC Stomps, and TX Frame Errors
 
It also supports clearing platform counters.
 
Supported Options:
n:    Specify list of node id's separated by commands. Use 'all' keyword to execute for all nodes. -n
      is required if dumping or clearing counters.
d:    Get interface counters. Can't be used in conjunction with the clear options.
c:    Clear platform counters (excluding BearValley counters). Can't be used in conjunction -d.
x:    Clear BearValley counters. Can't be used in conjunction -d.
s:    Once the script has been run, -s formats data into a list sorted by FCS, Stomp, and TX Err.
 
Example Usage:
      /tmp/crc_checker.sh -n all -d <--collect platform counters for all gen2+ nodes
      /tmp/crc_checker.sh -n all -x -c <--clear platform and BearValley counters for all gen2+ nodes
      /tmp/crc_checker.sh -n 1001,1002 -c <--clear platform counters for nodes 1001 and 1002
      /tmp/crc_checker.sh -s <--created sorted list of FCS, CRC/Stomps, and TX Frame Errors based on
                             last counters in /data/techsupport/int_counters
 
All outputs are logged to /data/techsupport/int_counters
****************************************************************************************************
 ```

# Examples
###### Clear Counters
```
admin@a-apic1:tmp> ./crc_checker.sh -x -c -n all
2021-05-14T19:41:29 Removing gen 1 nodes from list...
2021-05-14T19:41:29 Final list of nodes:
101 102 103 205 1002 1001 2001 2010
 
Script requires admin credentials.
Enter Admin Password:
 
2021-05-14T19:41:31 Connecting to node 101 at 10.0.88.68...
2021-05-14T19:41:32 Connecting to node 102 at 10.0.88.69...
2021-05-14T19:41:34 Connecting to node 103 at 10.0.88.64...
2021-05-14T19:41:35 Connecting to node 205 at 10.0.240.65...
2021-05-14T19:41:36 Connecting to node 1002 at 10.0.88.66...
2021-05-14T19:41:37 Connecting to node 1001 at 10.0.88.65: module 2...
2021-05-14T19:41:38 Connecting to node 1001 at 10.0.88.65: module 3...
2021-05-14T19:41:38 Connecting to node 1001 at 10.0.88.65: module 22...
2021-05-14T19:41:39 Connecting to node 1001 at 10.0.88.65: module 23...
2021-05-14T19:41:40 Connecting to node 1001 at 10.0.88.65: module 24...
2021-05-14T19:41:40 Connecting to node 1001 at 10.0.88.65: module 26...
2021-05-14T19:41:41 Connecting to node 2001 at 10.0.240.64: module 1...
2021-05-14T19:41:42 Connecting to node 2001 at 10.0.240.64: module 22...
2021-05-14T19:41:43 Connecting to node 2001 at 10.0.240.64: module 23...
2021-05-14T19:41:43 Connecting to node 2001 at 10.0.240.64: module 24...
2021-05-14T19:41:44 Connecting to node 2001 at 10.0.240.64: module 26...
2021-05-14T19:41:45 Connecting to node 2010 at 192.168.99.40...
2021-05-14T19:41:45 Completed!
2021-05-14T19:41:45 Raw command outputs are at /data/techsupport/int_counters
2021-05-14T19:41:45 To view sorted/formatted data run ./crc_checker.sh -s
2021-05-14T19:41:45 Once the -s option has been used, the sorted output can be viewed at /data/techsupport/int_counters/summary_sorted.txt
 ```

##### Identify FCS Errors that are Cut-Through Switched
```
####### Counters were collected:
admin@a-apic1:tmp> ./crc_checker.sh -d -n all
2021-05-14T14:39:12 Removing gen 1 nodes from list...
2021-05-14T14:39:12 Final list of nodes:
101 102 103 205 1002 1001 2010 2001
 
Script requires admin credentials.
Enter admin Password:
 
2021-05-14T14:39:16 Connecting to node 101 at 10.0.88.68...
2021-05-14T14:39:17 Connecting to node 102 at 10.0.88.69...
2021-05-14T14:39:17 Connecting to node 103 at 10.0.88.64...
2021-05-14T14:39:18 Connecting to node 205 at 10.0.240.65...
2021-05-14T14:39:19 Connecting to node 1002 at 10.0.88.66...
2021-05-14T14:39:21 Connecting to node 1001 at 10.0.88.65: module 2...
2021-05-14T14:39:22 Connecting to node 1001 at 10.0.88.65: module 3...
2021-05-14T14:39:22 Connecting to node 1001 at 10.0.88.65: module 22...
2021-05-14T14:39:23 Connecting to node 1001 at 10.0.88.65: module 23...
2021-05-14T14:39:24 Connecting to node 1001 at 10.0.88.65: module 24...
2021-05-14T14:39:24 Connecting to node 1001 at 10.0.88.65: module 26...
2021-05-14T14:39:25 Connecting to node 2010 at 192.168.99.40...
2021-05-14T14:39:26 Connecting to node 2001 at 10.0.240.64: module 1...
2021-05-14T14:39:27 Connecting to node 2001 at 10.0.240.64: module 22...
2021-05-14T14:39:28 Connecting to node 2001 at 10.0.240.64: module 23...
2021-05-14T14:39:28 Connecting to node 2001 at 10.0.240.64: module 24...
2021-05-14T14:39:29 Connecting to node 2001 at 10.0.240.64: module 26...
2021-05-14T14:39:30 Waiting for connections to complete...
 
2021-05-14T14:40:01 Completed!
2021-05-14T14:40:01 Raw command outputs are at /data/techsupport/int_counters
2021-05-14T14:40:01 To view sorted/formatted data run /tmp/crc_checker.sh -s
2021-05-14T14:40:01 Once the -s option has been used, the sorted output can be viewed at /data/techsupport/int_counters/summary_sorted.txt
 ```

###### outputs:
```
admin@a-apic1:tmp> /tmp/crc_checker.sh -s | head -50
NodeID               Interface                                RX_FCS_Error  RX_CRC_Stomp  TX_Frame_Error
node-103             eth-1/49                                 4496877       0             0
node-1002            eth-1/25                                 0             4496877       0
node-1002            BV_PORT_31_HOST_SIDE-Channel-0           0             4496877       0
node-1002            BV_PORT_25_LINE_SIDE-Channel-0           0             4496877       0
node-103             eth-1/54                                 0             0             4496877
node-1002            eth-1/31                                 0             0             4496877
node-1002            BV_PORT_31_LINE_SIDE-Channel-0           0             0             4496877
node-1002            BV_PORT_25_HOST_SIDE-Channel-0           0             0             4496877
node-205             eth-1/9                                  0             0             0
node-205             eth-1/8                                  0             0             0
node-205             eth-1/7                                  0             0             0
 ```
For the above we can see the following happens:
1.	    FCS errors are received on a leaf port (leaf103, eth1/49)
2.	    Leaf 103 sends these frames as TX Frame errors out eth1/54
3.	    RX Stomps are received on the BV LINE Side of spine 1002, port eth1/25
4.	    TX Frame errors are sent out the BV HOST Side of spine 1002, port eth1/25, towards the spine ASIC.
5.	    The spine receives CRC stomps on eth1/25
6.	    The spine transmits there's errors on eth1/31.
7.	    The spine BV chip on eth1/31 receives CRC Stomps on the HOST side of the BV from the ASIC.
8.	    The spine BV chip on eth1/31 transmits frame errors on the LINE side of the BV chip.
 
# Identify Errors seen on Modular Spines
```
admin@a-apic1:tmp> /tmp/crc_checker.sh -s | head -50
NodeID               Interface                                RX_FCS_Error  RX_CRC_Stomp  TX_Frame_Error
node-103             eth-1/49                                 12060635      0             0
node-1001-mod-24     Int11                                    0             16089730      0
node-1001-mod-3      Int22                                    0             15881058      0
node-1001-mod-2      eth-2/24                                 0             13360886      0
node-101             eth-1/51                                 0             13220954      0
node-1001-mod-24     Int19                                    0             0             16074193
node-1001-mod-2      Int17                                    0             0             15811911
node-1001-mod-3      eth-3/18                                 0             0             13430008
node-103             eth-1/53                                 0             0             12060569
node-101             eth-1/25                                 0             0             6610813
 ```

For the above we can see how stomps frames are forwarded through a spine:
1.	    FCS errors are received on a leaf port (leaf103, eth1/49)
2.	    Leaf 103 sends these frames as TX Frame errors out eth1/53
3.	    RX stomps are received on spine 1001, module 2, eth2/24
4.	    TX frame errors are sent by spine 1001, module 2, internal port Int17 towards an FM.
5.	    On spine 1001, FM 24 receives stomped CRC errors on Int11
6.	    On spine 1001, FM 24 transmits TX Frame Errors towards an LC on Int19.
7.	    On spine 1001, module 3 receives CRC stomps from the FM on Int22.
8.	    On Spine 1001, module 3 transmits TX Frame Errors on eth3/18.
9.	    On leaf 101, RX CRC Stomps are received on eth1/51.
10.	    On leaf 101, TX Frame Errors are transmitted on eth1/25.


