# ACI Out of subnet EP check

It's a script that checks ACI Remote IP EPs (XRs) against subnets in a VRF. <br>
It could be useful for validation and assessing impact before enabling Global Subnet Check setting in ACI.  <br>
Author - igderyba@cisco.com

### How to use it:
- Create script file at APIC directory
```
  cat < out-of-subnet-xr.sh
```
- Paste the script code with Enter at the end and Ctrl+C
```
  chmod a+x out-of-subnet-xr.sh
```
- Run it from APIC bash
```
./out-of-subnet-xr.sh
```

### Output example when there are out of subnet EPs:
```
admin@apic1:scripts> ./out-of-subnet-xr.sh 
Started checking Remote EPs at Mon Sep 29 11:27:43 UTC 2025

Remote EP 100.1.1.1 on node-101 is out of subnets in VRF igderyba:vrf2
Remote EP 100.1.1.1 on node-102 is out of subnets in VRF igderyba:vrf2

Finished checking Remote EPs at Mon Sep 29 11:27:45 UTC 2025
```
### Output example when there are no out of subnet EPs:
```
admin@apic1:scripts> ./out-of-subnet-xr.sh 
Started checking Remote EPs at Mon Sep 29 11:27:47 UTC 2025


Finished checking Remote EPs at Mon Sep 29 11:27:48 UTC 2025

```

### Limitations:
 - The script is focusing on checkng only Remote IP EPs, localy learned EPs are ignored.
 - The script is checking only for IPv4 EPs, IPv6 EPs are ignored.
