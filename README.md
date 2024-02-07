# Intro

A collection of TAC scripts curated for general use.

## [Collect TacOutput](https://github.com/datacenter/aci-tac-scripts/tree/main/collect%20TacOutput)

For ACI fabrics running pre-5.2, the `collect TacOutput` script can be used to collect extended fault, events and audits for RCA.

If your ACI Fabric is running 5.2+, instead use the [trigger tacoutput](https://techzone.cisco.com/t5/Application-Centric/Guide-to-collect-Tech-Support-and-TAC-requested-outputs-for-ACI/ta-p/1341503#toc-hId--1445615761) command from any APIC.

## [Access Log Analyzer](https://github.com/datacenter/aci-tac-scripts/tree/main/Access%20Log%20Analyzer)

For APICs, this script can be run to scan the latest access.log file and produce a summary output.

This script should be used while troubleshooting issues related to a slow APIC UI experience.

## [Easy Spine Elam](https://github.com/datacenter/aci-tac-scripts/tree/main/Easy%20Spine%20Elam)

This cli-based tool automates running elams on modular spines so that the user doesn't have to know the architecture of the platform, which lc's/fm's the traffic is hitting, etc. It also converts the report to the ereport format for easy readability.

## [Cloudsec KeySync Analyzer](https://github.com/datacenter/aci-tac-scripts/tree/main/Cloudsec%20KeySync%20Analyzer)

This cli-based tool automates cloudsec key sync triage and monitor for on-premium MSO/NDO sites, which can speed up cloudsec connectivity validation, and allow timely monitor and alert in case the key were run out of sync by any chance.

## [APIC Websocket Starter](https://github.com/datacenter/aci-tac-scripts/tree/main/APIC%20Websocket%20Starter)

Run on a python3 environment. This script can be run to quickly instantiate APIC Query Subscriptions for the purposes of testing, monitoring, troubleshooting and isolation of an ACI Fabric.

## [Multicast Validator](https://github.com/datacenter/aci-tac-scripts/tree/main/multicast-validator)

This cli-based tool automates verification and troubleshooting of many L3 multicast topologies in ACI. It is executed from the apic and gathers fabric-wide information about a multicast flow in order to determine if there are any problems to flag

## [FTAG Viewer](https://github.com/datacenter/aci-tac-scripts/tree/main/FTAG%20Viewer)

Official Fork of https://github.com/agccie/aci-ftag-viewer. This script builds and validates all forwarding trees (FTAG) within all on pods on a Cisco ACI fabric. Updated for Python3.

## [APIC PostUpgradeCb Checker](https://github.com/datacenter/aci-tac-scripts/tree/main/Post-Upgrade-CB-Checker)

This script query the new managed object (mo) created by postUpgradeCb function of existing class, then compare the Mo count and warning customer contact TAC for investigation if mismatch found. 
