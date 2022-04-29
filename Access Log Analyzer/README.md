# accLogAnalyzer

accLogAnalyzer, written to be run directly on an APIC.

Scrapes all entries in the latest access.log and aggregates it into a summary output.

## How to use

1. Copy the script onto the APIC `/tmp`
2. `chmod 755 /tmp/accLogAnalyzer.py`
3. `/tmp/accLogAnalyzer.py` to run

output is written to `/data/techsupport/acclogAnalysis_<datetime>.output`

```
apic1# /tmp/acclogtest.py       
29-Apr-2022 (13:27:42.977702) Starting accLogAnalyzer
29-Apr-2022 (13:27:42.978161) Found /var/log/dme/log/access.log, beginning run
29-Apr-2022 (13:27:42.978205) Parsing START
29-Apr-2022 (13:27:43.629108) Parsing FIN, begin analysis
29-Apr-2022 (13:27:43.629199) Got 40790 lines to analyze, this could take a few minutes...
29-Apr-2022 (13:36:16.712436) Run finished, Wrote analysis to /data/techsupport/acclogAnalysis_2022-04-29T13:27:42.output
```

## Output Contents example
```
apic1# cat /data/techsupport/acclogAnalysis_2022-04-29T13:27:42.output
Access Log Time Analysis Summary: 

    Log Start Time: 27/Apr/2022:14:01:04
    Log End Time: 29/Apr/2022:13:27:00

    Total # of Requests: 40790

    Time Coverage: 2845.93333333 Minutes (170756.0 s)
    Avg # of Reqs: 0.24 Queries per second

    Burst Summary: 267 15+ requests-per-second bursts found.

Remote Address Summary: 

    Remote addr '192.168.1.19' request count: 18239 (%44.71 of total reqs) 
    Remote addr '192.168.2.149' request count: 5930 (%14.54 of total reqs) 
    Remote addr '10.0.0.1' request count: 11364 (%27.86 of total reqs) 
    Remote addr '127.0.0.1' request count: 5257 (%12.89 of total reqs) 

User-Agent Summary: 

    User-agent 'Go-http-client/...' request count: 5223 (%12.8 of total reqs) 
    User-agent 'python-requests...' request count: 2 (%0.0 of total reqs) 
    User-agent 'Java/1.8.0_222...' request count: 11364 (%27.86 of total reqs) 
    User-agent 'Mozilla/5.0 (Wi...' request count: 24201 (%59.33 of total reqs) 

Response Status Summary: 

    Response code '200' count: 34825 (%85.38 of total reqs) 
    Response code '101' count: 1 (%0.0 of total reqs) 
    Response code '403' count: 5962 (%14.62 of total reqs) 
    Response code '400' count: 2 (%0.0 of total reqs) 

=============Summary End================

Burst Analysis - Checking for 15+ requests-per-second

59 Request Burst found at 27/Apr/2022:14:01:08:

59 Request Burst found at 27/Apr/2022:14:01:31:

59 Request Burst found at 27/Apr/2022:14:01:38:

55 Request Burst found at 27/Apr/2022:14:02:01:

57 Request Burst found at 27/Apr/2022:14:02:08:

54 Request Burst found at 27/Apr/2022:14:02:31:

58 Request Burst found at 27/Apr/2022:14:02:38:

59 Request Burst found at 27/Apr/2022:14:03:01:

59 Request Burst found at 27/Apr/2022:14:03:08:

59 Request Burst found at 27/Apr/2022:14:03:31:

57 Request Burst found at 27/Apr/2022:14:03:38:

Burst Display Limit of 10 hit, bursts output stopped
```