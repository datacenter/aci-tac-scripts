- [accLogAnalyzer](#accloganalyzer)
  - [How to use](#how-to-use)
  - [Outputs](#outputs)
  - [acclogAnalysis Summary example](#accloganalysis-summary-example)
  - [Burst Analysis Example](#burst-analysis-example)

# accLogAnalyzer

accLogAnalyzer, written to be run directly on an APIC.

Scrapes all entries in the latest access.log and aggregates it into a summary output + burst aggregation file.

## How to use

```
apic# /tmp/accLogAnalyzer.py -h
usage: accLogAnalyzer.py [-h] [-f [FILENAME]] [-o [OUTPUT_LOCATION]]

optional arguments:
  -h, --help            show this help message and exit
  -f [FILENAME], --file [FILENAME]
                        Fullpath to access.log file to analyze
  -o [OUTPUT_LOCATION], --output [OUTPUT_LOCATION]
                        Directory to write output files
```

1. Copy the script onto the APIC `/tmp`
2. `chmod 755 /tmp/accLogAnalyzer.py`
3. `/tmp/accLogAnalyzer.py` to run with default locations

default locations are:

- Look for the latest `access.log` at `/var/log/dme/log/` (default APIC location)
- write output to `/data/techsupport/acclogAnalysis_<datetime>.output`

```
apic1# /tmp/accLogAnalyzer.py
03-May-2023 (19:54:53.705990) Starting accLogAnalyzer
03-May-2023 (19:54:53.706246) Found /var/log/dme/log/access.log, beginning run
03-May-2023 (19:54:53.706360) Parsing START
03-May-2023 (19:54:54.350068) Parsing FIN. Begin Summary.
03-May-2023 (19:54:54.350193) Got 34180 lines to summarize
03-May-2023 (19:55:28.059610) Run finished, Wrote Summary to /data/techsupport/acclogAnalysis_2023-05-03T19:54:53.output
03-May-2023 (19:55:28.059854) Wrote Burst analysis to /data/techsupport/acclogBurstAnalysis_2023-05-03T19:54:53.output
```

## Outputs

This script produces 2 output files:

1. The summary file; `acclogAnalysis*`
2. The burst analysis file: `acclogBurstAnalysis*`

## acclogAnalysis Summary example

```
apic1# cat /data/techsupport/acclogAnalysis_2023-05-03T19:54:53.output
Access Log Time Analysis Summary:

    Log Start Time: 02/May/2023:20:17:13
    Log End Time: 03/May/2023:19:54:47

    Total # of Requests: 34180

    Time Coverage: 1417.5666666666666 Minutes (85054.0 s)
    Avg # of Reqs: 0.4 Queries per second

    Burst Summary: 480 15+ requests-per-second bursts found.

Remote Address Summary:

    Remote addr '127.0.0.1' request count: 34180 (%100.0 of total reqs)

Real IP Summary (Proxy-in-play):

    Real IP '10.0.0.1' request count: 14305 (%41.85 of total reqs)
    Real IP '127.0.0.1' request count: 10230 (%29.93 of total reqs)
    Real IP 'None' request count: 2548 (%7.45 of total reqs)
    Real IP '172.18.217.56' request count: 737 (%2.16 of total reqs)
    Real IP '10.122.254.141' request count: 72 (%0.21 of total reqs)
    Real IP '10.24.246.160' request count: 6288 (%18.4 of total reqs)

User-Agent Summary:

    User-agent 'Python-urllib/3...' request count: 285 (%0.83 of total reqs)
    User-agent 'python-requests...' request count: 5874 (%17.19 of total reqs)
    User-agent 'Go-http-client/...' request count: 18749 (%54.85 of total reqs)
    User-agent 'python-requests...' request count: 2876 (%8.41 of total reqs)
    User-agent '-...' request count: 36 (%0.11 of total reqs)
    User-agent 'go-resty/2.7.0 ...' request count: 72 (%0.21 of total reqs)
    User-agent 'Mozilla/5.0 (Wi...' request count: 6288 (%18.4 of total reqs)

Response Status Summary:

    Response code '200' count: 34033 (%99.57 of total reqs)
    Response code '400' count: 12 (%0.04 of total reqs)
    Response code '403' count: 134 (%0.39 of total reqs)
    Response code '304' count: 1 (%0.0 of total reqs)

=============Summary End================
```

## Burst Analysis Example

```
apic1# tail -n 40 /data/techsupport/acclogBurstAnalysis_2023-05-03T21:13:09.output

18 Request Burst found at 03/May/2023:21:06:04:
     127.0.0.1 ::ffff 10.0.0.1 03/May/2023:21:06:04 GET /api/class/fvCEp.json?rsp-subtree-include=count HTTP/1.1 200 108 - python-requests/2.28.2
     127.0.0.1 ::ffff 10.0.0.1 03/May/2023:21:06:04 GET /api/class/fvIp.json?rsp-subtree-include=count HTTP/1.1 200 108 - python-requests/2.28.2
     127.0.0.1 ::ffff 10.0.0.1 03/May/2023:21:06:04 GET /api/class/fvBD.json?rsp-subtree-include=count HTTP/1.1 200 108 - python-requests/2.28.2
     ...snip...

18 Request Burst found at 03/May/2023:21:11:04:
     127.0.0.1 ::ffff 10.0.0.1 03/May/2023:21:11:04 GET /api/class/fvCEp.json?rsp-subtree-include=count HTTP/1.1 200 108 - python-requests/2.28.2
     127.0.0.1 ::ffff 10.0.0.1 03/May/2023:21:11:04 GET /api/class/fvIp.json?rsp-subtree-include=count HTTP/1.1 200 108 - python-requests/2.28.2
     127.0.0.1 ::ffff 10.0.0.1 03/May/2023:21:11:04 GET /api/class/fvBD.json?rsp-subtree-include=count HTTP/1.1 200 108 - python-requests/2.28.2
     ...snip...
```
