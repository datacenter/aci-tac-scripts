Support Information

This script is designed for ACI 4.2+ and requires the nxos_binlog_decode utility. For issues or enhancements, consult with your Cisco TAC engineer.

Version Compatibility: ACI 4.2 and higher
Resource Requirements: Minimum 3GB free space in /data/techsupport/
Processing Time: 2-5 minutes (optimized) vs 15-30 minutes (traditional)


Command Reference
Parameter	Description	Example
-S	Search parameter (IP, MAC, or date) - Enables optimization	-S 10.1.1.100
-C	Context lines - Show X lines before/after each match	-C 25
-D	Days - Only process files from last X days	-D 7
-T	Tar results - Compress output file	-T true
-P	Preserve files - Keep temporary files for analysis	-P false
-V	Verbose - Show detailed processing information	-V true
-h	Help - Show all options and examples	-h
 

Quick Start Guide

Download script ep_decoder.sh

1. Copy Script to Leaf Node

scp ep_decoder.sh admin@<leaf-ip>:/data/techsupport/
2. Set Permissions

leaf_X# chmod 755 /data/techsupport/ep_decoder.sh
Check the help
 

Simple Endpoint Search (Most Common)

leaf_X# sh ep_decoder.sh -h
Help documentation for ep_decoder.sh

Supported Options:
S: Search parameter - ALSO OPTIMIZES file selection
* IP = 10.1.1.111
* MAC = 0000.0101.1101
* Date 2026-01-01
When specified, only binary files containing this Search parameter will be copied and processed

C: Context lines - will be used as egrep -C parameter (X lines before and after match)
D: Days - Only copy and process files from the last X days (optimized for performance)
P: Preserve files - Keep the source EPM/EPMC files on /data/techsupport/ep_decoder without the default cleanup (default: true - cleanup enabled)
T: Tar search result if there is one specific already define or Tar all to contents /data/techsupport/ep_decoder/search_data folder
V: Verbose result information with detail of commands been run on Leaf
h: Help

Note: Search results are output directly to /data/techsupport/ folder and SORTED BY DATE
Default behavior is to cleanup temporary files unless -P false is specified
Usage Examples
Simple Endpoint Search (Most Common)

# Search for specific IP address in EPM/EPMC logs
leaf_X# sh ep_decoder.sh -S 10.1.1.100

# Search for specific MAC address in EPM/EPMC logs
leaf_X# sh ep_decoder.sh -S 0022.bdf8.19ff

# Search for specific Date in EPM/EPMC logs
leaf_X# sh ep_decoder.sh -S 2025-12-27
