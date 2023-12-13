# ep_checker

This tool is intended to automate idenfying any stale or incorrect remote endpoint learns within a give bd or vrf.

# Usage
###### Method 1
1. SSH to the APIC.
2. ```cd ~```
3. ```vim ep_checker.sh```
4. Type ```:set paste``` then go into insert mode by typing ```i```
5. Copy entire script into clipboard and then paste into the script by typing ```shift + insert```
6. Type ```ESC``` and then ```:wq!```
7. Type ```chmod 777 ep_checker.sh```
8. Execute: ```./ep_checker.sh <args>```
 

###### Method 2
1. SCP or SFTP the script into some directory on an APIC.
2. SSH to that apic and ```cd``` into the directory.
3. Execute: ```./ep_checker.sh <args>```

###### Examples - 
```
      ./ep_checker.sh -s vrf -v 2916356 <--Check for incorrect remote IP endpoint learns in VRF vnid 2916356
      ./ep_checker.sh -s bd -v 16056286 <--Check for incorrect remote MAC endpoint learns in BD vnid 16056286
```

# Limitations
- This script will not be able to detect incorrect endpoint learns when a remote learn is pointing to a remote site, unicast etep.
- This script will also not be able to detect incorrect endpoint learns if a remote learn points to the TEP of a Remote Leaf

# Example Usage
```
####Endpoint 192.168.254.101 has been migrated behind and l3out but internal remote learns still exist
apic1:~> ./ep_checker.sh -v 2293766 -s vrf
2023-12-12T15:32:47 Collecting 10 relevant endpoint objects within the specified vnid
2023-12-12T15:32:48 Getting tep info...
2023-12-12T15:32:48 Processing 64 overlay teps.
Completion Check: 64/64
2023-12-12T15:32:48 Checking for down VPC members and interfaces...
2023-12-12T15:32:48 Processing 21 down vpc interfaces.
Completion Check: 21/21
2023-12-12T15:32:48 Getting tunnel info from each node...
2023-12-12T15:32:48 Processing 199 fabric tunnels
Completion Check: 199/199
2023-12-12T15:32:49 Getting vtep info if applicable...
2023-12-12T15:32:49 Processing 2 ipv4 VTEPs
Completion Check: 2/2
2023-12-12T15:32:49 Processing 2 ipv4 VTEPs
Completion Check: 2/2
2023-12-12T15:32:49 Building database of ipv4 endpoint learns...
2023-12-12T15:32:49 Processing 10 ipv4 endpoints
Completion Check: 10/10
2023-12-12T15:32:49 Checking for ipv4 endpoint incorrect learns..
2023-12-12T15:32:49 There are 1 relevant l3 endpoints to check.
2023-12-12T15:32:49 Determining expected TEPs for 1 ipv4 endpoints...
Completion Check: 1/1
2023-12-12T15:32:49 Checking 4 remote ipv4 endpoints for incorrect learns
2023-12-12T15:32:49 WARNING! Found incorrect remote learn on node-103 for ep 192.168.254.101
2023-12-12T15:32:49 WARNING! Found incorrect remote learn on node-101 for ep 192.168.254.101
2023-12-12T15:32:49 WARNING! Found incorrect remote learn on node-102 for ep 192.168.254.101
Completion Check: 4/4
2023-12-12T15:32:49 WARNING! Found incorrect remote learn on node-202 for ep 192.168.254.101
2023-12-12T15:32:49 Finished!
2023-12-12T15:32:49 Found 4 incorrect endpoint learns!
2023-12-12T15:32:49 For a full list of bad learn information check: /data/techsupport/stale_learn_checker/bad_learns
2023-12-12T15:32:49 All objects used by this checker are stored in: /data/techsupport/stale_learn_checker/
```

# Viewing the bad_learns file
```
cat /data/techsupport/stale_learn_checker/bad_learns
2023-12-12T15:32:47 The following incorrect endpoint learns were found in vrf vnid 2293766:
Note: In scenarios where an Endpoint is vpc_attached and one side of the vpc is down but that member is up, the extected TEP of the endpoint could be the VPC tep or the PTEP of the active leg.
Endpoint: node-103_192.168.254.101
        Destination TEP: 10.2.168.65
        Destination Node(s): node-201
        Expected TEP(s): not_fabric_local
        Expected Node(s): not_fabric_local

Endpoint: node-101_192.168.254.101
        Destination TEP: 10.2.168.65
        Destination Node(s): node-201
        Expected TEP(s): not_fabric_local
        Expected Node(s): not_fabric_local

Endpoint: node-102_192.168.254.101
        Destination TEP: 10.2.168.65
        Destination Node(s): node-201
        Expected TEP(s): not_fabric_local
        Expected Node(s): not_fabric_local

Endpoint: node-202_192.168.254.101
        Destination TEP: 10.2.168.65
        Destination Node(s): node-201
        Expected TEP(s): not_fabric_local
        Expected Node(s): not_fabric_local
```
