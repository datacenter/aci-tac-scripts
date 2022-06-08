# Intro

A collection of TAC scripts curated for general use.

## [Collect TacOutput](https://github.com/datacenter/aci-tac-scripts/tree/main/collect%20TacOutput)

For ACI fabrics running pre-5.2, the `collect TacOutput` script can be used to collect extended fault, events and audits for RCA.

If your ACI Fabric is running 5.2+, instead use the [trigger tacoutput](https://techzone.cisco.com/t5/Application-Centric/Guide-to-collect-Tech-Support-and-TAC-requested-outputs-for-ACI/ta-p/1341503#toc-hId--1445615761) command from any APIC.

## [Access Log Analyzer](https://github.com/datacenter/aci-tac-scripts/tree/main/Access%20Log%20Analyzer)

For APICs, this script can be run to scan the latest access.log file and produce a summary output.

This script should be used while troubleshooting issues related to a slow APIC UI experience.

## [Easy Spine Elam](https://github.com/datacenter/aci-tac-scripts/tree/main/Easy%20Spine%20Elam)

This cli-based tool automates running elams on modular spines so that the user doesn't have to know the architecture of the platform, whic lc's/fm's the traffic is hitting, etc. It also convers the report to the ereport format for easy readability.
