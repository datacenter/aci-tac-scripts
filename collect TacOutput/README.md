# Collect tacOutput
If your ACI fabric is running 5.2+, 
[trigger tacoutput](https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/application-policy-infrastructure-controller-apic/214520-guide-to-collect-tech-support-and-tac-re.html#anc13) 
should be used on an APIC to collect the extended faults, events and audit+ logs

For ACI fabrics on pre-5.2, this `collect tacOutput` script can be used to collect extended fault, events and audit+ logs.

# Usage

## Quickstart

1. Copy the script onto a customer APIC `/tmp`
2. Change permissions of the script: 
```
apic# chmod 755 /tmp/collectTacOutputs.sh
```
3. Run the script with desired timerange:
```
apic# /tmp/collectTacOutputs.sh -b 2022-02-16T08:30:00 -e 2022-03-16T09:30:28 -o 1,2,3,4,5
```
NOTE: `-o 1,2,3,4,5`  will leave out epRecord, healthRecord and healtInst. Check Full Run Example for all options

## Full Run Example

<pre>
apic# <b>/tmp/collectTacOutputs.sh</b>
Select corresponding numbers of objects to collect. Separate numbers with commas. *Note, topSystem, fabricNode, and firmwareARunning are automatically included.
Ex: 1,2,3,4,5
1. faultInfo *collected unfiltered
2. faultRecord
3. eventRecord
4. aaaModLR
5. polDeploymentRecord
6. epRecord
7. healthRecord
8. healthInst *collected unfiltered
Enter selections: <b>1,2,3,4,5,6,7,8</b>
Enter record start date (format: 2019-12-15T00:00:00) *default is one month prior to current date: <b>2019-12-25T00:00:00</b>
Enter record end date (format: 2019-12-15T00:00:00) *default is current date: <b>2020-01-05T00:00:00</b>

<i>...script collection runs...</i>

Compression completed
Logs available for SCP or SFTP download from <b>/data/techsupport/TacOutput-2019-12-25T00:00:00-to-2020-01-05T00:00:00.tgz</b>
To download through your web browser go to <b>https://<apic address>/files/1/techsupport/TacOutput-2019-12-25T00:00:00-to-2020-01-05T00:00:00.tgz</b>

To remove files when done run
rm -rf /tmp/TacOutput2020-01-07T10-00-35
rm -f /data/techsupport/TacOutput-2019-12-25T00:00:00-to-2020-01-05T00:00:00.tgz
</pre>

## Help documentation

```
apic# /tmp/collectTacOutputs.sh --help

Help documentation for /tmp/collectTacOutputs.sh

Script will prompt for input or user can supply arguments with below options.

Supported Options:
b:      start date for collected objects.       Ex format: 2019-12-15T00:00:00
                specify "default" to choose a starting date one month prior to current time.
e:      end date for collected objects.         Ex format: 2019-12-15T00:00:00
                specify "default" to choose an ending date one month prior to current time.
o:      Select corresponding number for each object to collect from the following list. keyword 'all' will get all objects. Separate with commas. Ex: 1,2,3,4
                *Note, topSystem, fabricNode, and firmwareARunning are automatically included.
                1. faultInfo *collected unfiltered
                2. faultRecord
                3. eventRecord
                4. aaaModLR *collected unfiltered
                5. polDeploymentRecord
                6. epRecord
                7. healthRecord
                8. healthInst *collected unfiltered

d:      destination directory for output file.
z:      disable collection of implicit mo's (topSystem, fabricNode, firmwareARunning)
q:      run script in quiet mode.
To supply all or some arguments to Script: collectOutputs -b 2019-12-15T00:00:00 -e 2019-12-15T00:00:00 -o 1,2,3,4
To run script and follow prompts: collectOutputs