# Introduction

This script is designed to assist in troubleshooting when an APIC will not join the cluster. It is designed to be run on the APIC that is not joining the ACI cluster. 

Specifically, it will analyze various conditions that will lead to the "wiringIssues" value of the LLDP Interface object (class lldp.If) for interfaces connected to APICs to have various error messages set. The script will analyze the conditions that cause the wiring issue and give a Pass/Fail report for various checks. 

The script will log a report and debug file to the /data/techsupport directory, as well as providing a summary of all checks at the end of the report.
 
When opening the report, use "less -r" or "less -R" for the colors to be read properly.
```
================================================================================
Summary of All Checks
================================================================================
Pod ID Match:                                                             PASSED
Fabric Name Match:                                                        PASSED
Controller UUID Match:                                                    PASSED
Infra VLAN Match:                                                         PASSED
Wiring Mismatch:                                                          FAILED
Unapproved Serial Number:                                                 PASSED
Fabric Mode Check:                                                        PASSED
SSL Certificate Date Check:                                               PASSED
Missing CA Certificate Check:                                             PASSED
UCS PID of APIC SN Check:                                                 PASSED
Infra VLAN Deployed as EPG:                                               PASSED
targetMbSn Check:                                                         PASSED
Leaf SSL Certificate Date Check:                                          PASSED
================================================================================
Report and Debug File Locations
================================================================================
Report saved to: /data/techsupport/apic_wiring_report_20251119_121033.log
Debug log saved to: /data/techsupport/apic_wiring_debug_20251119_121033.log
```

## What about 'acidiag cluster' and 'show discoveryissues'

These are both excellent troubleshooting commands that check on health and APIC connection more generally than this script. 

'show discoveryissues' checks for active links, connectivity to the infra GW, active nodes, and several other checks. 

'acidiag cluster' checks connectivity to switches and APICs, which APICs are active, database status, and some policy checks. 

This script focues more narrowly on issues that result in the "wiringIssues" value of the LLDP Interface object (class lldp.If) for interfaces connected to APICs to be set to an error message. It checks not just for whether an issue is present, but multiple conditions that can result in one of the errors.

## Link to the Script

https://github.com/datacenter/aci-tac-scripts/blob/main/wiringIssues/wiringIssues.sh

 
## Running the Script

The script should be copied to the /data/techsupport directory of the APIC that is not joining the cluster. This can be done via file transfer (SFTP or SCP) to the APIC or by pasting the contents of the file into vim.

For vim:

```
apic1# cd /data/techsupport
apic1# vim wiringIssues.sh

Then copy and paste the script in, and then exit vim by pressing ':' and then entering 'wq!' and pressing 'Enter'

```
Once the script is loaded to the APIC, the permissions must be changed:
```
chmod 777 /data/techsupport/wiringIssues.sh
```
If you are getting a permission denied error, double check the file permissions are set correctly.

 

With the permissions set, the script can be executed.
```
2-apic2# /data/techsupport/wiringIssues.sh
```
The script will ask for a Leaf Login Information - this will be used by the APIC to connect to the directly connected leaves.

```
================================================================================
Leaf Login Information
================================================================================
Enter your username: aahacket
Enter your password: 
```
 


After this, the APIC will begin to gather all of the required data
```
================================================================================
Starting Information Gathering
================================================================================
Gathering APIC Information... DONE
Gathering LLDP Information... DONE
Connecting to Leaf 101 (10.122.143.21)... DONE
Connecting to Leaf 102 (10.122.143.22)... DONE
```

## Reported Wiring Issues

The script will then output the reported wiring issues gathered from the directly connected leaves. It will then proceed into the individual checks.
```
================================================================================
Reported Wiring Issues
================================================================================
Node ID Number: 101
Wiring Issue: No Issue Reported

Node ID Number: 102
Wiring Issue: wiring-mismatch
```
All checks are run regardless of the reported wiring issue.

 
# Checks
## Check 1: Pod ID Match

The Pod ID configured across the fabric must match. This information is exchanged via LLDP between the APIC and the leaves. If the APIC Pod ID does not match the rest of the fabric, it will not be admitted to the fabric.
```
================================================================================
Check 1: Pod ID Match
================================================================================
Leaf Reported Pod IDs
---------------------
Leaf 101:         1
Leaf 102:         1

APIC Reported Pod ID:         7

Pod ID Match:                                                             FAILED
```
If the reported POD IDs do not match, then the APIC will need to be clean reloaded and the configuration corrected.

 
## Check 2: Fabric Name Match

The Fabric Name configured across the fabric must match. This information is exchanged via LLDP between the APIC and the leaves. If the APIC Fabric Name does not match the rest of the fabric, it will not be admitted to the fabric.
```
================================================================================
Check 2: Fabric Name Match
================================================================================
Leaf Reported Fabric Name
-------------------------
Leaf 101:         POD2
Leaf 102:         POD2

APIC Reported Fabric Name:         ACI Fabric1

Fabric Name Match:                                                        FAILED
```
If the reported Fabric Names do not match, then the APIC will need to be clean reloaded and the configuration corrected.

 
## Check 3: Controller UUID Match

The UUID of the APIC and the UUID in the fabric database for that APIC must match. This information is shared via LLDP between the APIC and Leaves.
```
================================================================================
Check 3: Controller UUID Match
================================================================================
Leaf Reported Controller UUID
-----------------------------
Leaf 101: d54ef4aa-3313-11ef-bd85-cbc15318f90f
Leaf 102: d54ef4aa-3313-11ef-bd85-cbc15318f90f

APIC Reported UUID: 1ebac698-c493-11f0-bdd9-41d9e9bf150c

Controller UUID Match:                                                    FAILED
```
If these do not match, the typical cause is that the APIC was replaced, re-installed, or another operation resulting in a clean reload of the APIC, without the APIC being decommissioned from the fabric.

 

To resolve this, decommission the APIC from one of the APICs that is still in the fabric, wait for at least 5 minutes, and then recommission the APIC.

 
## Check 4: Infra VLAN Match

The Infra VLAN configured across the fabric must match. This information is exchanged via LLDP between the APIC and the leaves. If the APIC Infra VLAN does not match the rest of the fabric, it will not be admitted to the fabric.
```
================================================================================
Check 4: Infra VLAN Match
================================================================================
Leaf Reported Infra VLAN
------------------------
Leaf 101:         3967
Leaf 102:         3967

APIC Reported Infra VLAN:         987

Infra VLAN Match:                                                         FAILED
```
If the reported Infra VLAN does not match, then the APIC will need to be clean reloaded and the configuration corrected.
 
## Check 5: Wiring Mismatch

If this check fails, the interface connecting to the interface is configured incorrectly as a uplink, or spine facing, interface. APICs require the interface to be configured as a downlink interface.
```
================================================================================
Check 5: Wiring Mismatch
================================================================================
Leaf Node ID: 101
  Leaf Interface: eth1/2
  Usage: controller,epg,infra
Wiring Mismatch Check:                                                    PASSED

Leaf Node ID: 102
  Leaf Interface: eth1/2
  Usage: fabric,fabric-ext
Wiring Mismatch Check:                                                    FAILED

Overall Wiring Mismatch Check:                                            FAILED
```
If only one of the links is misconfigured, the APIC may still not join the cluster, and the wiring-issue for the correctly configured interface can be seen as unapproved-ctrlr:
```
pod8-leaf1# cat /mit/sys/lldp/inst/if-\[eth1--3\]/summary
# LLDP Interface
id           : eth1/3
adminRxSt    : enabled
adminSt      : enabled
adminTxSt    : enabled
childAction  : 
descr        : 
dn           : sys/lldp/inst/if-[eth1/3]
lcOwn        : local
mac          : A0:23:9F:56:56:33
modTs        : 2024-10-17T10:06:02.215-06:00
monPolDn     : uni/fabric/monfab-default
name         : 
operRxSt     : up
operTxSt     : up
portDesc     : topology/pod-1/paths-101/pathep-[eth1/3]
portMode     : normal
portVlan     : unspecified
rn           : if-[eth1/3]
status       : 
sysDesc      : topology/pod-1/node-101
wiringIssues : unapproved-ctrlr

pod8-leaf2# cat /mit/sys/lldp/inst/if-\[eth1--3\]/summary
# LLDP Interface
id           : eth1/3
adminRxSt    : enabled
adminSt      : enabled
adminTxSt    : enabled
childAction  : 
descr        : 
dn           : sys/lldp/inst/if-[eth1/3]
lcOwn        : local
mac          : A0:23:9F:56:48:C3
modTs        : 2024-10-17T10:06:02.215-06:00
monPolDn     : uni/fabric/monfab-default
name         : 
operRxSt     : up
operTxSt     : up
portDesc     : topology/pod-1/paths-102/pathep-[eth1/3]
portMode     : normal
portVlan     : unspecified
rn           : if-[eth1/3]
status       : 
sysDesc      : topology/pod-1/node-102
wiringIssues : wiring-mismatch
```
In this case, determine the cause of the wiring-mismatch and resolve the issue. This could occur if the APIC has been cabled improperly, in which case the cabling should be fixed, or the  interface has been misconfigured. In the case of proper cabling, the leaf interface may be configured as an uplink instead of a downlink to the APIC.

 

Disabling the interface with the wiring-mismatch should allow the controller to successfully join the fabric as a workaround until the misconfiguration is fixed.

 
## Check 6: Unapproved Serial Number

If this check fails, the APIC Serial Number is not a trusted Serial Number. It is not recommended to allow a device into the ACI fabric with an incorrect serial number.
```
================================================================================
Check 6: Unapproved Serial Number
================================================================================
APIC Serial Number: FCH2113V1NZ
Serial Number Check:                                                      PASSED
```
 
## Check 7: Fabric Mode

If the fabric is in Strict cluster mode, then the SN of the APIC must be accepted through the GUI before the controller will join the fabric.
```
================================================================================
Check 7: Fabric Mode
================================================================================
Fabric Discovery Mode: STRICT
Fabric Mode Check:                                 MANUAL APIC APPROVAL REQUIRED
```

This can be double checked from the first part of the avread -a output:
```
a-apic1# avread -a
Cluster:
-------------------------------------------------------------------------
operSize                3
clusterSize             3
fabricDomainName        calo-a
version                 apic-6.0(4c)
discoveryMode           PERMISSIVE
drrMode                 OFF
kafkaMode               ON
autoUpgradeMode         OFF
```
If the 'discoveryMode' is set to 'STRICT', then the APIC must be accepted in the GUI

 
## Check 8: SSL Certificate Date Check

If this check fails, there may be an issue with the date of the APIC being outside the valid dates for the certificate.
```
================================================================================
Check 8: SSL Certificate Date Check
================================================================================
Certificate Start Date: Apr 19 17:57:33 2021 GMT
Certificate End Date: May 14 20:25:41 2029 GMT

Current APIC Date: Fri Jan  1 00:02:15 UTC 2016

Certificate Date Check:                                                   FAILED
```
It can be confirmed with:
```
rtp-aci08-apic3# acidiag verifyapic
openssl_check: certificate details
subject=CN=FCH2113V1W3,serialNumber=PID:APIC-SERVER-M2 SN:FCH2113V1W3
issuer=CN=Cisco Manufacturing CA,O=Cisco Systems
notBefore=May 24 10:29:45 2017 GMT
notAfter=May 24 10:39:45 2027 GMT
installation_check.sh ERROR: openssl_check: cert verify failed
```
Check that the APIC date is within the certificate range:
```
rtp-aci08-apic3# date
Thu 01 Jan 2015 12:14:53 PM CST
```
In this case, the date is not within the valid range, so we can log in as root and set the date to as close to the other APICs as possible:

*Note: root access requires Cisco TAC - if facing this issue, please open a TAC case*

```
root@rtp-aci08-apic3:/securedata/cacerts# date -s '2024-10-17 11:15:00'
Thu Oct 17 11:15:00 CST 2024
```
And the 'acidiag verifyapic' command should complete successfully:
```
rtp-aci08-apic3# acidiag verifyapic
openssl_check: certificate details
subject=CN=FCH2113V1W3,serialNumber=PID:APIC-SERVER-M2 SN:FCH2113V1W3
issuer=CN=Cisco Manufacturing CA,O=Cisco Systems
notBefore=May 24 10:29:45 2017 GMT
notAfter=May 24 10:39:45 2027 GMT
openssl_check: passed
openssl_check: certificate details
subject=serialNumber = PID:APIC-SERVER-M2 SN:FCH2113V1W3, CN = FCH2113V1W3
Cert Type: APIC Cert
apic_cert_format_check: passed
ssh_check: passed
all_checks: passed
```
Proper NTP configuration in the fabric should prevent this issue.

 
## Check 9: Missing CA Certificate Check

If this check fails, the CA Certificate is missing:
```
================================================================================
Check 9: Missing CA Certificate Check
================================================================================
Warning - File not Found: /securedata/cacerts/cacert.crt
CA Certificate Check                                                      FAILED
```
This can be double checked with:
```
rtp-aci08-apic3# acidiag verifyapic
file not found: /securedata/cacerts/cacert.crt
installation_check.sh ERROR: openssl_check: files check failed
```
If the acidiag verifyapic command does not exist on the version of ACI you are checking, you can log in as root to the APIC and check for it in the following location:

*Note: root access requires Cisco TAC - if facing this issue, please open a TAC case*
```
root@rtp-aci08-apic3:/securedata/cacerts# ls -lah
total 32K
drwxrwxr-x.  2 root root 4.0K Oct 17 10:56 .
drwxr-xr-x  23 root root 4.0K Oct 17 10:40 ..
-rwxrwxr-x   1 root root 7.0K Jul 26  2023 cabundle.crt
-rwxrwxr-x   1 root root 5.8K Oct 18  2023 cacert-org.crt
-rwx------   1 root root 7.0K Oct 17 10:56 cacert.crt
```
If the cacert.crt file is missing or has a file size of 0, it will be reported missing:
```
root@rtp-aci08-apic3:/securedata/cacerts# ls -lah
total 32K
drwxrwxr-x.  2 root root 4.0K Oct 17 10:56 .
drwxr-xr-x  23 root root 4.0K Oct 17 10:40 ..
-rwxrwxr-x   1 root root 7.0K Jul 26  2023 cabundle.crt
-rwxrwxr-x   1 root root 5.8K Oct 18  2023 cacert-org.crt
-rwx------   1 root root 0    Oct 17 10:56 cacert.crt
```
This can be fixed by copying cacert-org.crt to cacert.crt, or copying the cacert.crt file from another APIC:
```
root@rtp-aci08-apic3:/securedata/cacerts# cp cacert-org.crt cacert.crt
cp: overwrite 'cacert.crt'? Yes
```
And the acidiag verifyapic command should complete successfully (if there are no other issues.):
```
rtp-aci08-apic3# acidiag verifyapic
openssl_check: certificate details
subject=CN=FCH2113V1W3,serialNumber=PID:APIC-SERVER-M2 SN:FCH2113V1W3
issuer=CN=Cisco Manufacturing CA,O=Cisco Systems
notBefore=May 24 10:29:45 2017 GMT
notAfter=May 24 10:39:45 2027 GMT
openssl_check: passed
openssl_check: certificate details
subject=serialNumber = PID:APIC-SERVER-M2 SN:FCH2113V1W3, CN = FCH2113V1W3
Cert Type: APIC Cert
apic_cert_format_check: passed
ssh_check: passed
all_checks: passed
```
## Check 10: UCS PID as APIC SN Check

If this check fails, the APIC has failed to pull the correct values of the APIC Product ID (PID) and SN from the TPM during bootup.
```
================================================================================
Check 10: UCS PID as APIC SN Check:
================================================================================
APIC Serial Number: UCSC-C220-M4
UCS PID Check:                                                            FAILED
```
It will instead pull a UCS PID and generic Serial Number. This will prevent the APIC from joining the cluster, and can be checked in the  avread or acidiag avread outputs. It will show 'UCSC-C220-M4' or similar instead of the APIC SN, as seen in the example output below:
```
a-apic1# avread
Appliance Director is not running locally hence below av information could be stale!
Cluster:
-------------------------------------------------------------------------
fabricDomainName        calo-a
discoveryMode           PERMISSIVE
clusterSize             3
version                 5.2(7g)
kafkaMode               OFF
drrMode                 OFF
operSize                2

APICs:
-------------------------------------------------------------------------
                    APIC 1                  APIC 2                  APIC 3                  
version           5.2(7g)                 5.2(7g)                 5.2(7g)                
address           10.0.0.1                10.0.0.2                10.0.0.3                
oobAddress        10.122.141.98/27        10.122.141.99/24        10.122.141.100/27                       
routableAddress   172.16.11.231           172.16.11.232           172.16.22.232           
tepAddress        10.0.0.0/16             10.0.0.0/16             10.0.0.0/16             
podId             1                       1                       2                       
chassisId         e581a5e2-.-4599477d     c4a53638-.-1c8dc405     64513c52-.-74b92b64     
cntrlSbst_serial  (APPROVED,FCH1929V153)  (APPROVED,FCH2045V1X2)  (APPROVED,UCSC-C220-M4)  
active            YES                     YES                     YES                     
flags             cra-                    cra-                    cra-                    
health            255                     255                     1
```
Alternatively, you can check if /var/log/dme/log/svc_ifc_policymgr.bin.log has the error message indicating "Failed to matching sys-product-name".

 

From root, you can verify you are encountering this issue by checking that the Product Name is showing a UCS PID:
*Note: root access requires Cisco TAC - if facing this issue, please open a TAC case*
 

Incorrect:
```
root@rtp-aci08-apic3:~# dmidecode | grep -A 9 'System Info'
System Information
        Manufacturer: Cisco Systems Inc
        Product Name: UCSC-C220-M4
        Version: A0
        Serial Number: 123456789
        UUID: a35ba40f-2386-6141-9528-0cf09db25b62
        Wake-up Type: Power Switch
        SKU Number: Not Specified
        Family: Not Specified
```
The correct output would look like this:
```
root@rtp-aci08-apic3:~# dmidecode | grep -A 9 'System Info'
System Information
        Manufacturer: Cisco Systems Inc
        Product Name: APIC-SERVER-M2
        Version: A0
        Serial Number: FCH2113V1W3
        UUID: a35ba40f-2386-6141-9528-0cf09db25b62
        Wake-up Type: Power Switch
        SKU Number: Not Specified
        Family: Not Specified
```
This can be fixed by a power cycle of the APIC and the CIMC (note: you may need to remove power to the APIC/CIMC entirely for a few minutes to allow everything to reset) and after rebooting, check that the correct PID was pulled by the APIC.

 
## Check 11: Infra VLAN Deployed as EPG

In the event that the infra VLAN is deployed as an EPG VLAN, the APIC will not be allowed to join the cluster if that EPG VLAN gets deployed to the switch.
```
================================================================================
Check 11: Infra VLAN Deployed as EPG
================================================================================
APIC Infra VLAN: 3967

Leaf Reported Infra VLAN Usage
------------------------------
Leaf 101: Infra VLAN deployed 2 times
Leaf 102: Infra VLAN deployed 2 times

Infra VLAN Deployed as EPG Check:                                        FAILED
```
Check the connected leaf switches for the infra vlan being deployed as anything other than infra:
```
pod8-leaf1# show vlan extended 

 VLAN Name                             Encap            Ports                    
 ---- -------------------------------- ---------------- ------------------------ 
 1    tenant1:BD_1                     vxlan-15728623   --                       
 2    common:bd_services               vxlan-14942232   Eth1/37                  
 3    common:ss:epg_ss_services        vlan-1945        Eth1/37                  
                                                                                          
 10   infra:default                    vxlan-16777209,  Eth1/1, Eth1/2, Eth1/3   
                                       vlan-3908                                                                                            

 14   tenant2:bd-1                     vxlan-16383939   Eth1/31, Eth1/32, Po3,   
                                                        Po4                      
 15   tenant2:ap1:epg1                 vlan-1487        Eth1/31, Eth1/32, Po3,   
                                                        Po4                      
 16   tenant3:BD-badInfra              vxlan-16580505   Eth1/31, Eth1/32, Po3,     
                                                        Po4     

 17   tenant3:AP:EPG-badInfra          vlan-3908        Eth1/31, Eth1/32, Po3,   
                                                        Po4                                                   

 42   mgmt:default:Inband              vlan-1167        Eth1/1, Eth1/2, Eth1/3   
```
The infra VLAN cannot be used for anything else in the fabric. The problematic configuration should be removed.

 
## Check 12: targetMbSn Check

The script is unable to check this directly (because it would require connecting to the APICs) but will warn a manual check is required if the 'unapproved-ctrlr' condition is set. 
```
================================================================================
Check 12: targetMbSn Check
================================================================================
targetMbSn Check:                                          MANUAL CHECK REQUIRED

Please check the output of 'avread -a' or 'acidiag avread' for a targetMbSn value
on the other APICs that are in the cluster
If this value is present, please use 'replace-controller reset x' to correct it,
replacing the value of x with the APIC number that is not joining the cluster.
```
This issue should only occur when bringing in a replacement APIC, as the SN will not match.

 

The targetMbSn value is set during a failover operation to the standby APIC using the command:
```
replace-controller replace <APIC ID> <Backup Sn>
```
For example:
```
replace-controller replace 3 FCH1824V2VR
```
This value does not get automatically cleared prior to 6.0(1g), and when present, will prevent the new APIC with a different Serial Number from joining the cluster.


In this case, let's assume we are replacing APIC 3 and it is not joining the cluster.


Check the output of acidiag avread, avread -a, or moquery -c infraWiNode for a value in the 'targetMbSn' field from APICs 1 and 2.

 

Here is an example with the value present:
```
a-apic1# avread -a
Cluster:
-------------------------------------------------------------------------
operSize                3
clusterSize             3
fabricDomainName        calo-a
version                 apic-6.0(4c)
discoveryMode           PERMISSIVE
drrMode                 OFF
kafkaMode               ON
autoUpgradeMode         OFF

APICs:
-------------------------------------------------------------------------
                    APIC 1                                  APIC 2                                  APIC 3                                  
version           6.0(4c)                                 6.0(4c)                                                                  
address           10.0.0.1                                10.0.0.2                                0.0.0.0                                
oobAddress        10.122.141.98/27                        10.122.141.99/24                        10.122.141.100/27                       
oobAddressV6      ::                                      ::                                      ::                                      
routableAddress   172.16.11.231                           172.16.11.232                           0.0.0.0                           
tepAddress        10.0.0.0/16                             10.0.0.0/16                             0.0.0.0                             
podId             1                                       1                                       0                                       
chassisId         e581a5e2-a1d9-11ed-81e6-d3294599477d    c4a53638-a1e1-11ed-8c5e-c7731c8dc405       
cntrlSbst_serial  (APPROVED,FCH1929V153)                  (APPROVED,FCH2045V1X2)                  (ERASED,)                  
commissioned      YES                                     YES                                     YES                                     
registered        YES                                     YES                                     NO                                     
active            YES                                     YES                                     NO (zeroTime)                                    
health            255                                     255                                     0                                     
id                1                                       2                                       3                                       
capabilities      0X17EEFFFFFFFFF--0X2020--0X7--0X1       0X17EEFFFFFFFFF--0X2020--0X7--0X1       0XFFFFFFF--0X2020--0       
rk                (stable,present,0X206173722D687373)     (stable,present,0X206173722D687373)     (stable,absent,0)    
ak                (stable,present,0X206173722D687373)     (stable,present,0X206173722D687373)     (stable,absent,0)     
oobrK             (stable,present,0X206173722D687373)     (stable,present,0X206173722D687373)     (stable,absent,0)     
oobaK             (stable,present,0X206173722D687373)     (stable,present,0X206173722D687373)     (stable,absent,0)     
targetMbSn                                                                                        FCH1824V2VR                                        
failoverStatus    0                                       0                                       255                                       
standby           NO                                      NO                                      NO                                      
DRR               NO                                      NO                                      NO                                      
apicX             NO                                      NO                                      NO                                      
virtual           NO                                      NO                                      NO    
```
If the SN of the new APIC is not the SN listed, the APIC will not be allowed to join the cluster. This is the result of the TargetMbSn and failoverStatus not getting cleared after a failover to a Standby APIC.

 

To fix this, use the command replace-controller reset 3 or if that fails, from root: av.bin resetTargetMbSn 3 abcd

*Note: root access requires Cisco TAC - if replace-controller reset fails, please open a TAC case*
 

Replace the number with the appropriate number for the controller your are replacing.

 

APIC3 will need to be decommissioned, clean reloaded, and commissioned into the fabric after this is done.

 

This is fixed in ACI release 6.0(1g) per CSCwb69095, and in the fixed version, the targetMbSn value will be automatically cleared on the replacement succeeds or fails.


## Check 13: Leaf SSL Certificate Check

If this check fails, there may be an issue with the date of the connected switch being outside the valid dates for the certificate.
```
================================================================================
Check 13: Leaf SSL Certificate Date Check
================================================================================
Leaf 103:
  Certificate Start Date: 2024-11-02T11:42:02.000-04:00
  Certificate End Date: 2029-05-14T16:25:42.000-04:00
  Current Leaf Date: Wed Mar 11 12:37:25 EDT 2026
  Leaf 103 Certificate Date Check:                                       PASSED

Leaf 101:
  Certificate Start Date: 2026-02-23T17:00:10.000-04:00
  Certificate End Date: 2036-02-21T17:00:10.000-04:00
  Current Leaf Date: Wed Mar 11 12:37:35 EDT 2026
  Leaf 101 Certificate Date Check:                                       PASSED


```
It can be confirmed with:
```
a1-leaf1# moquery -c pkiFabricNodeSSLCertificate | egrep 'validity'
validityNotAfter               : 2036-02-21T17:00:10.000-04:00
validityNotBefore              : 2026-02-23T17:00:10.000-04:00
```
Check that the switch date is within the certificate range:
```
a1-leaf1# date
Wed Mar 11 12:44:38 EDT 2026
```
In this case, the date is not within the valid range, so we can log in as root and set the date to as close to the other APICs as possible:

*Note: root access requires Cisco TAC - if facing this issue, please open a TAC case*
```
a1-leaf1# date -s '2026-03-11 11:15:00'
```
Proper NTP configuration in the fabric should prevent this issue.

If the certificate is expired, please contact TAC.

# Appendix A - Full Output
```
a-apic1# ./wiringIssues.sh 
================================================================================
Leaf Login Information
================================================================================
Enter your username: aahacket
Enter your password: 
================================================================================
Operations You Must Avoid
================================================================================
These are operations that must be avoided, as they will make the clustering issue worse, and potentially unrecoverable.

Operations You Must Avoid When Cluster is Diverged
1. Disrupt a healthy/fully-fit APIC to recover an unhealthy APIC
2. Clean or Regular reload more than 1 APIC at a time
3. Decommission more than 1 APIC at a time

Operations You Must Avoid During an Upgrade/Downgrade
1. Don't reload any APIC in the cluster.
2. Don't decommission any APIC in the cluster.
3. Don't change the firmware target version back to the original version.

================================================================================
Starting Information Gathering
================================================================================
Gathering APIC Information... DONE
Gathering LLDP Information... DONE
Connecting to Leaf 103 (10.122.141.103)... DONE
Connecting to Leaf 101 (10.122.141.101)... DONE
================================================================================
Incoming LLDP Info
================================================================================
Interface: eth2-1
Node ID Number: 103
Out-of-Band Management IP: 10.122.141.103
APIC-Connected Leaf Interface: eth1/1

Interface: eth2-2
Node ID Number: 101
Out-of-Band Management IP: 10.122.141.101
APIC-Connected Leaf Interface: eth1/1

================================================================================
Reported Wiring Issues
================================================================================
Node ID Number: 103
Wiring Issue: No Issue Reported

Node ID Number: 101
Wiring Issue: No Issue Reported

================================================================================
Starting APIC Wiring Checks
================================================================================
================================================================================
Check 1: Pod ID Match
================================================================================
Leaf Reported Pod IDs
---------------------
Leaf 103: 	1
Leaf 101: 	1

APIC Reported Pod ID: 	1

Pod ID Match:                                                             PASSED

================================================================================
Check 2: Fabric Name Match
================================================================================
Leaf Reported Fabric Name
-------------------------
Leaf 103: 	calo-a
Leaf 101: 	calo-a

APIC Reported Fabric Name: 	calo-a

Fabric Name Match:                                                        PASSED

================================================================================
Check 3: Controller UUID Match
================================================================================
Leaf Reported Controller UUID
-----------------------------
Leaf 103: 442222ad-6bf5-11f0-979c-d4c93cff9e08
Leaf 101: 442222ad-6bf5-11f0-979c-d4c93cff9e08

APIC Reported UUID: 442222ad-6bf5-11f0-979c-d4c93cff9e08

Controller UUID Match:                                                    PASSED

================================================================================
Check 4: Infra VLAN Match
================================================================================
Leaf Reported Infra VLAN
------------------------
Leaf 103: 	3967
Leaf 101: 	3967

APIC Reported Infra VLAN: 	3967

Infra VLAN Match:                                                         PASSED

================================================================================
Check 5: Wiring Mismatch
================================================================================
Leaf Node ID: 103
  Leaf Interface: eth1/1
  Usage: controller,epg,infra
Wiring Mismatch Check:                                                    PASSED

Leaf Node ID: 101
  Leaf Interface: eth1/1
  Usage: controller,epg,infra
Wiring Mismatch Check:                                                    PASSED

Overall Wiring Mismatch Check:                                            PASSED

================================================================================
Check 6: Unapproved Serial Number
================================================================================
APIC Serial Number: WZP22441B1C
Serial Number Check:                                                      PASSED

================================================================================
Check 7: Fabric Mode
================================================================================
Fabric Discovery Mode: STRICT
Fabric Mode Check:                                                        PASSED

================================================================================
Check 8: SSL Certificate Date Check
================================================================================
Certificate Start Date: Feb 19 04:27:54 2019 GMT
Certificate End Date: May 14 20:25:42 2029 GMT

Current APIC Date: Wed Mar 11 12:37:11 EDT 2026

Certificate Date Check:                                                   PASSED

================================================================================
Check 9: Missing CA Certificate Check
================================================================================
CA Certificate Check                                                      PASSED

================================================================================
Check 10: UCS PID as APIC SN Check:
================================================================================
APIC Serial Number: WZP22441B1C
UCS PID Check:                                                            PASSED

================================================================================
Check 11: Infra VLAN Deployed as EPG
================================================================================
APIC Infra VLAN: 3967

Leaf Reported Infra VLAN Usage
------------------------------
Leaf 103: Infra VLAN deployed 1 time
Leaf 101: Infra VLAN deployed 1 time

Infra VLAN Deployed as EPG Check:                                         PASSED

================================================================================
Check 12: targetMbSn Check
================================================================================
targetMbSn Check:                                                         PASSED

================================================================================
Check 13: Leaf SSL Certificate Date Check
================================================================================
Leaf 103:
  Certificate Start Date: 2024-11-02T11:42:02.000-04:00
  Certificate End Date: 2029-05-14T16:25:42.000-04:00
  Current Leaf Date: Wed Mar 11 12:37:25 EDT 2026
  Leaf 103 Certificate Date Check:                                       PASSED

Leaf 101:
  Certificate Start Date: 2026-02-23T17:00:10.000-04:00
  Certificate End Date: 2036-02-21T17:00:10.000-04:00
  Current Leaf Date: Wed Mar 11 12:37:35 EDT 2026
  Leaf 101 Certificate Date Check:                                       PASSED

================================================================================
Summary of All Checks
================================================================================
Pod ID Match:                                                             PASSED
Fabric Name Match:                                                        PASSED
Controller UUID Match:                                                    PASSED
Infra VLAN Match:                                                         PASSED
Wiring Mismatch:                                                          PASSED
Unapproved Serial Number:                                                 PASSED
Fabric Mode Check:                                                        PASSED
SSL Certificate Date Check:                                               PASSED
Missing CA Certificate Check:                                             PASSED
UCS PID of APIC SN Check:                                                 PASSED
Infra VLAN Deployed as EPG:                                               PASSED
targetMbSn Check:                                                         PASSED
Leaf SSL Certificate Date Check:                                          PASSED
================================================================================
Report and Debug File Locations
================================================================================
Report saved to: /data/techsupport/apic_wiring_report_20260311_123658.log
Debug log saved to: /data/techsupport/apic_wiring_debug_20260311_123658.log
```
