# Cloudsec Key Sync Analyzer

Support triage mode and monitor mode, with minimal argument (ND/MSO IP address), where APIC (on-premises) IP for the site (with cloudsec enabled) is retrieved.

For each site, fetch APIC’s local key’s sequence number and associated channel to match peer site APIC’s remote key policy from same site.

In triage mode, audit log is also analyzed to see if sequenceNumber used to run out of sequence for remote keys for last 1000 audit logs.

In monitor mode, syslog alert will be sent if syslog server IP is given, and key is out of sync.
Both console and file-based logs are supported by default.


# Required python3 and below packages

urllib3
requests

## Quickstart

python.exe C:/wksp/cloudseckey.py -n 192.168.10.41

## Full Run Example

<pre>

python.exe C:/wksp/cloudseckey.py -n 192.168.10.41
Enter ND/MSO password for admin:
AUS Eastern Standard Time 2022-09-14T20:11:21.771||INFO||(376)||Retrieving Sites Info from ND/MSO
Enter APIC password for admin:
AUS Eastern Standard Time 2022-09-14T20:11:27.840||INFO||(384)||Retrieving Key Policy Info from APIC
AUS Eastern Standard Time 2022-09-14T20:11:27.841||INFO||(392)||Running in Triage Mode
AUS Eastern Standard Time 2022-09-14T20:11:28.596||INFO||(280)||Analyzing site fabric-site2 Audit Log for sequenceNumber out of order
AUS Eastern Standard Time 2022-09-14T20:11:28.651||INFO||(280)||Analyzing site fabric-site1 Audit Log for sequenceNumber out of order
AUS Eastern Standard Time 2022-09-14T20:11:30.128||INFO||(308)||Analyzing site fabric-site1 Share Key Policy for Matching
AUS Eastern Standard Time 2022-09-14T20:11:36.084||INFO||(308)||Analyzing site fabric-site2 Share Key Policy for Matching
AUS Eastern Standard Time 2022-09-14T20:11:37.586||WARNING||(413)|| Site 2 used to received remote key with sequenceNumber out of order
AUS Eastern Standard Time 2022-09-14T20:11:37.586||WARNING||(415)||2022-09-14T09:54:44.483+00:00, Local Site ID: 2 , Peer Site ID: 1 , sequenceNumber  (Old: 5126, New: 1)
AUS Eastern Standard Time 2022-09-14T20:11:37.586||WARNING||(415)||2022-09-07T11:02:34.511+00:00, Local Site ID: 2 , Peer Site ID: 1 , sequenceNumber  (Old: 4891, New: 4893)
AUS Eastern Standard Time 2022-09-14T20:11:37.586||INFO||(419)||Cross site validation for shared keys in using
AUS Eastern Standard Time 2022-09-14T20:11:37.587||INFO||(438)||fabric-site1       id 1 --> fabric-site2     id 2 , keys synced at sequenceNumber: 1 , assocNum: 0
AUS Eastern Standard Time 2022-09-14T20:11:37.587||INFO||(438)||fabric-site2       id 2 --> fabric-site1     id 1 , keys synced at sequenceNumber: 8512 , assocNum: 0

python.exe C:/wksp/cloudseckey.py -m -n 192.168.10.41 

Enter ND/MSO password for admin:
AUS Eastern Standard Time 2022-09-14T20:12:02.816||INFO||(376)||Retrieving Sites Info from ND/MSO
Enter APIC password for admin:
AUS Eastern Standard Time 2022-09-14T20:12:08.073||INFO||(384)||Retrieving Key Policy Info from APIC
AUS Eastern Standard Time 2022-09-14T20:12:08.074||INFO||(387)||Running in Monitor Mode for every 180 seconds
AUS Eastern Standard Time 2022-09-14T20:12:08.938||INFO||(308)||Analyzing site fabric-site2 Share Key Policy for Matching
AUS Eastern Standard Time 2022-09-14T20:12:08.940||INFO||(308)||Analyzing site fabric-site1 Share Key Policy for Matching
AUS Eastern Standard Time 2022-09-14T20:12:10.444||INFO||(419)||Cross site validation for shared keys in using
AUS Eastern Standard Time 2022-09-14T20:12:10.444||INFO||(438)||fabric-site2       id 2 --> fabric-site1     id 1 , keys synced at sequenceNumber: 8513 , assocNum: 1
AUS Eastern Standard Time 2022-09-14T20:12:10.445||INFO||(438)||fabric-site1       id 1 --> fabric-site2     id 2 , keys synced at sequenceNumber: 1 , assocNum: 0
\Ctrl-c Pressed,Bye

</pre>

## Help documentation

```
./cloudseckey.py -h

Triage/Monitor cloudsec shared key

optional arguments:
  -h, --help            show this help message and exit
  -n HOST               ND hostname
  -d {debug,info,warn}
  -u USER               admin user id
  -s SYSLOG_SERVER      syslog server IP
  -i INTERVAL           monitor frequency
  -m                    monitor mode
