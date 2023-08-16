# aci-ftag-viewer
Official Fork of https://github.com/agccie/aci-ftag-viewer

Check the FTAG topology in an ACI fabric

This script builds and validates all forwarding trees (FTAG) within all on pods on a Cisco ACI fabric. From the ACI managed information tree (MIT), it collects required isis, lldp, and fmcast objects to verify per-node status matches the expected value.  Additionally, the script prints the logical tree to help understand the path for multicast/broadcast/unknown uncast traffic. 

To begin, upload the script to the APIC directory. Then execute the script with optional filters.
For example:
```
apic1# python aci_ftag_viewer.py --help
usage: aci_ftag_viewer.py [-h] [--debug {debug,info,warn,error}]
                          [--offline OFFLINE] [--offlineHelp] [--ftag FTAG]
                          [--pod POD]

Check the FTAG topology in an ACI fabric

optional arguments:
  -h, --help            show this help message and exit
  --debug {debug,info,warn,error}
                        debug level
  --offline OFFLINE     Use this option when executing the script on offline
                        data. If not set, this script assumes it is executing
                        on a live system and will query objects directly.
  --offlineHelp         print further offline help instructions
  --ftag FTAG           tree/ftag to verify (default all)
  --pod POD             pod to verify (default all)

apic1# python aci_ftag_viewer.py --pod 2 --ftag 0


################################################################################
#  Pod 2 FTAG 0
#  Root spine-203
#  active nodes: 6, inactive nodes: 0
################################################################################
spine-203
  +- 1/3 -------- 1/55 leaf-102
  +- 1/4 ------- 1/103 leaf-103
  |                      +- 1/104 ------- 1/4 spine-204
  |
  +- 1/5 -------- 1/57 leaf-105
  +- 1/6 -------- 1/53 leaf-106
  +- 1/1 ....... (EXT) Ethernet1/23 IPN


Pod 2 FTAG 0: all nodes reachable on tree
```
