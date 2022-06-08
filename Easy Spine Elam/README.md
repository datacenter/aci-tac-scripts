# easy-spine-elam

This tool is intended to automate running elams on modular gen 2 or later aci spines directly from the cli.

# Usage
###### Method 1
1. SSH to the modular spine.
2. ```cd /bootflash```
3. ```vim easy-spine-elam.sh```
4. Type ```:set paste``` then go into insert mode by typing ```i```
5. Copy entire script into clipboard and then paste into the script by typing ```shift + insert```
6. Type ```ESC``` and then ```:wq!```
7. Execute: ```bash ./easy-spine-elam.sh <args>```
 

###### Method 2
1. SCP or SFTP the script into ```/bootflash``` on the spine.
2. ```cd /bootflash```
3. Execute: ```bash ./easy-spine-elam.sh <args>```

###### More Examples - 
```
      ./easy-spine-elam.sh -m 2,3 -d ingress  <--check for traffic arriving from front panel on modules 2 and 3
      ./easy-spine-elam.sh -m all             <--check for traffic arriving from front-panel on all lc's and fm's
      ./easy-spine-elam.sh -m lc -d egress    <--check for traffic arriving on all LC's from fm's
      ./easy-spine-elam.sh -m fm              <--check all FM's for traffic
      ./easy-spine-elam.sh -m 2 -i 2/10       <--check for traffic arriving on module 2, interface eth2/10
      ./easy-spine-elam.sh -m all -r          <--check all modules for previously triggered elams
      ./easy-spine-elam.sh -m all -o 0 -n 6   <--check all modules using in-select 6 and out-select 0
```

# Limitations
- The script is supported only on gen 2 and later modular spines. Trying to run it on other chassis will cause the script to fail to run.
- In-selects 6, 7, and 14 are supported as well as most important trigger conditions within those in-selects (note that inner ipv6 is ineffective with in-select 14).
- Parsing is done through the ereport functionality if the switch is on 14.2.3j or later.
- If direction is not specified, ingress is picked (captures LC traffic arriving from a front-panel port).
- If specifying an ingress interface, specify the module that contains it using the -m option.
- If not specified, in-select 14 and out-select 1 are used.

- When elam-ing all modules for traffic, the elam may trigger many times across all modules and asics if the traffic is hitting the spines multiple times. For instance, if setting source and destination IP addresses and there are multiple flows between these IP's using different l4 ports, this would result in varied hashing and most likely traffic would hash across multiple FM's. Additionally, if traffic is looping in and out of ACI (for example, if leaving through an l3out in vrf a going to a firewall, and then coming back in vrf b) this could result in triggering multiple locations since it is potentially hitting the spine many times. For this reason, it may be useful to set additional filters that make the flow unique, such as the vxlan vnid.

# Help Documentation
```
a-spine1# bash ./easy-spine-elam.sh --help
 
Help documentation for ./easy-spine-elam.sh
 
This script automates elams on gen2 and later modular spines. Unless an interface is specified, the
tool will run elams on all asics for each module specified by the -m option in order to quickly find
out the path of the packet through each module.
 
Note, this script doesn't do elam parsing/interpretation, it is intended only to collect the elams.
 
 
Supported Options:
m:    (Required) Specify a comma-separated list of modules to run the elam on. Use keywords all to run on
      all modules. Keyword lc or fc/fm can be used to select all LC's or FM's.
i:    Specify the front-panel ingress interface to match in the elam. Example: -i 2/10. If specified
      specify only the one module using the -m option that contains this interface.
d:    Specify direction (for line card elams). 'ingress' captures traffic arriving from a front-
      panel port. 'egress' captures traffic arriving from an FM. Not supported with in-select 7.
      By default the direction is set to ingress.
r:    Don't arm new elam, check on specified modules for previously triggered elams.
o:    Specify out-select (0 or 1). By default 1 is used. In most cases this is sufficient. For scenarios
      where met pointer and other flood programming is being checked, use 0.
n:    Specify in-select (6,7, or 14). Use 6 to match outer headers or non vxlan encap'd traffic. Use 14
      to match outer or inner headers. Use 7 to only match inner conditions. Available conditions that
      can be set will change based on in-select value. Default value is 14.
k:    If the script doesn't complete on a previous run it may leave open ssh sockets. This option closes
      previous ssh sockets. Note, that these old sockets are checked for when running the script so there
      should be no need to use this option.
```

# Example Usage
```
####Capture tcp traffic between two IP's on all modules destined to l4 port 8989
a-spine1# bash ./easy-spine-elam.sh -m all -d ingress
Final module list is:
2 23 26 3
2022-06-08T14:55:57 Previous ssh sockets from past script runs exist. Closing them out then continuing...
2022-06-08T14:55:57 Closing existing ssh sockets...
2022-06-08T14:55:57 In-select - 14 and out-select - 0 are being used.
2022-06-08T14:55:57 Gathering required hardware information...
10. outer l2 destination mac        > Format : aaaa.bbbb.cccc
11. outer l2 source mac             > Format : aaaa.bbbb.cccc
30. outer ipv4 dscp                 > Format : 0-64
31. outer ipv4 source ip            > Format : d.d.d.d
32. outer ipv4 protocol             > Format : 0-255
33. outer ipv4 destination ip       > Format : d.d.d.d
40. outer l4 vnid                   > Format : 0x0-0xffffff
41. outer l4 src policy applied     > Format : 0-1
42. outer l4 DL bit set             > Format : 0-1
43. outer l4 sclass                 > Format : 0-65535
44. outer l4 flags                  > Format : 0x0-0xff
50. inner l2 source mac             > Format : aaaa.bbbb.cccc
51. inner l2 destination mac        > Format : aaaa.bbbb.cccc
60. inner arp source ip             > Format : d.d.d.d
61. inner arp target ip             > Format : d.d.d.d
62. inner arp target mac            > Format : aaaa.bbbb.cccc
70. inner ipv4 destination ip       > Format : d.d.d.d
71. inner ipv4 protocol             > Format : 0-255
72. inner ipv4 dscp                 > Format : 0-64
73. inner ipv4 source ip            > Format : d.d.d.d
80. inner ipv6 next-header          > Format : 0-255
81. inner ipv6 destination ip       > Format : A:B::C:D
82. inner ipv6 source ip            > Format : A:B::C:D
90. inner l4 source port            > Format : 0-65535
91. inner l4 dest port              > Format : 0-65535
 
    Select corresponding numbers of conditions to set. Separate numbers with commas.
    Ex: 1,2,3,4,5
Enter selections: 70,73,71,91
Enter inner ipv4 destination ip > Format : d.d.d.d: 80.0.0.1
Enter inner ipv4 source ip > Format : d.d.d.d: 150.0.0.100
Enter inner ipv4 protocol > Format : 0-255: 6
Enter inner l4 dest port > Format : 0-65535: 8989
2022-06-08T14:56:17 Setting elam for module 2
2022-06-08T14:56:18 Setting elam for module 23
2022-06-08T14:56:18 Setting elam for module 26
2022-06-08T14:56:18 Setting elam for module 3
2022-06-08T14:56:28 Checking elam status for module 2
2022-06-08T14:56:28 Checking elam status for module 23
2022-06-08T14:56:28 Checking elam status for module 26
2022-06-08T14:56:28 Checking elam status for module 3
 
NO ELAMS HAVE TRIGGERED!
 
Type "status" to check elam status again. Type "report" or "report detail" to collect all reports. Hit enter to finish: status
2022-06-08T14:56:28 Checking elam status for module 2
2022-06-08T14:56:28 Checking elam status for module 23
2022-06-08T14:56:28 Checking elam status for module 26
2022-06-08T14:56:28 Checking elam status for module 3
 
 
ELAM TRIGGERED on module 26:
ASIC: 0 SLICE: 1
 
 
ELAM TRIGGERED on module 2:
ASIC: 3 SLICE: 1
 
 
Type "status" to check elam status again. Type "ereport", "report" or "report detail" to collect all reports.
If on 14.2 or later, the report can be generated in ereport format. Hit enter to finish: ereport
2022-06-08T14:57:36 Collecting report for module 26 asic 0...
2022-06-08T14:57:36 Collecting report for module 2 asic 3...
2022-06-08T14:57:42 Module 26 Asic 0 report saved to - /data/techsupport/mod26-asic0-elamreport-2022-06-08T14-57-36
2022-06-08T14:57:46 Module 2 Asic 3 report saved to - /data/techsupport/mod2-asic3-elamreport-2022-06-08T14-57-36
2022-06-08T14:57:46 Converting reports to ereport format!
The following decoded elams are available -
/data/techsupport/mod26-asic0-elamreport-2022-06-08T14-57-36-EREPORT
/data/techsupport/mod2-asic3-elamreport-2022-06-08T14-57-36-EREPORT
2022-06-08T14:57:48 Cleaning up sockets...
2022-06-08T14:57:48 Closing existing ssh sockets...
2022-06-08T14:57:49 CLI's sent to hardware are saved in /tmp/elam_output-mod<id>
2022-06-08T14:57:49 FINISHED!
```

# Viewing the Generated Report
The parsed ereport files (if applicable) can be viewed by cat-ing the files mentioned when the script completes. For more information about understanding the contents of the ereport, take a look at CiscoLive session BRKDCN-3900a and BRKDCN-3900b

# Additional Information
- On modular spine ALL traffic goes to the FM's. Even if the ingress and egress ports are on the same module, asic, and slice.
- On modular spines, ALL traffic is forwarded to a single FM, even if it is BUM traffic. This means that (unlike leafs and 1 RU spines) the ingress LC will always set an ovector that points to the destination FM.
- On modular spines, BUM replication is done on the FM so a BUM frame would be seen in multiple locations in the egress path through the LC. This also means that if a BUM flow must be forwarded out four front-panel LC ports on the same asic, the FM will send 4 unique copies down to the LC and the LC forwards out the correct port based on the vntag set by the FM. For more info on how the vntag points to the egress, physical port refer to https://techzone.cisco.com/t5/Application-Centric/ACI-Troubleshooting-Deep-Dive-on-Ovector-Validatio...



