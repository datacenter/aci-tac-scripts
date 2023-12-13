# SchedulerAnalyzer

## Getting started

This script help diagnose APIC scheduler issue related to nomad, consul, kron, etc.

By default the script will run in "verification mode" and no fix will be attempted


## What is checked ?

1. Cluster health
2. F3254 - missing podman image on APIC (warning only)
3. Scheduler status for all APIC
4. CSCwa45126 - nomad logmon orphaned process + fork rejected by pids controller in dmesg
5. CSCvw05302 - consul/nomad/nomad_client/kron orphaned process
6. av_state.json file and /var/log/dme/log disk usage
7. CSCvr78486 - APIC key/cert mismatch (only if requested)

## How to use it?

Copy the script to any of the APIC using vim 

```
vim scheduler.sh
```

- Type `i` to enter INSERT mode
- Paste the script
- Exit and save vim using ESC key, type `:wq` and ENTER

Add the execute permission to the file

```
chmod u+x scheduler.sh
```

Execute the script 

```
./scheduler {args}
```



### Run in verification mode

By default, the script will run for all APIC in the cluster. When the script will run for the non-local APIC, the user will be prompted with the remote APIC user's password.

```sh
bdsol-aci13-apic1# ./scheduler

 Running APIC scheduler analyzer

→ Gathering facts
  [i] Running on bdsol-aci13-apic1 (apic id: 1, cluster of 3, version 5.2(8d))
→ Verifying cluster health
  [√] Cluster health is healthy (fully-fit and available)
→ Verifying existence of fault F3254
  [√] No fault F3254 found

 Running verification on APIC 3

→ Verifying scheduler status for APIC 3
  [√] Scheduler is up
  [i] APIC 3 admin's password is required to continue
  Do you wish to continue? [y/N] y
  Enter APIC 3's password for admin (attempt 1/3): 
→ Verifying orphaned nomad logmon process
  [√] No orphaned nomad logmon process
→ Verifying scheduler processes with invalid PID
  [√] Scheduler processes are up
→ Verifying state files and disk usage
  [√] av_state.json file is populated
  [√] /var/log/dme/log partition usage is lower than 95%

 Running verification on APIC 2

→ Verifying scheduler status for APIC 2
  [√] Scheduler is up
→ Verifying orphaned nomad logmon process
  [√] No orphaned nomad logmon process
→ Verifying scheduler processes with invalid PID
  [√] Scheduler processes are up
→ Verifying state files and disk usage
  [√] av_state.json file is populated
  [√] /var/log/dme/log partition usage is lower than 95%

 Running verification on APIC 1

→ Verifying scheduler status for APIC 1
  [√] Scheduler is up
→ Verifying orphaned nomad logmon process
  [√] No orphaned nomad logmon process
→ Verifying scheduler processes with invalid PID
  [√] Scheduler processes are up
→ Verifying state files and disk usage
  [√] av_state.json file is populated
  [√] /var/log/dme/log partition usage is lower than 95%

```

#### Options arguments

- Execute the script for 1 given APIC (the APIC where the script is run from do not matters)
```sh
./scheduler --apic [APIC_ID] 
```

- Execute the certification checks (requires root password)
```sh
./scheduler --check-cert {--root-pwd [ROOT_PWD]}
```

- Execute the script in `--fix-me` mode (attempt a fix for the failed verification) 

Note: this requires a root password which you can provide at the CLI using the --root-pwd PWD args, or the script will ask for it when needed
```sh
./scheduler --fix-me {--root-pwd [ROOT_PWD]}
```

- Generate a techsupport bundle with all the scheduler related logs (not a techsupport)

Note: the script will not run the verification when `--generate-ts`` is supplied
```sh
./scheduler --generate-ts
```

- General usage
```sh
bdsol-aci13-apic1# ./scheduler.sh -h
APIC scheduler analyzer

usage: ./scheduler [-h] [-v] [--apic ID] [--apic-pwd PWD] [--root-pwd PWD] [--fix-me] [--check-certs] | [--generate-ts]

optional arguments:
  --apic {APIC-ID}  : run the verification on the provided APIC id (default is all)
  --apic-pwd        : APIC password (used if verification are performed on remote APICs)
  --root-pwd        : root password (provided by TAC)
  --check-certs     : run the certificiation verification (requires root password)
  --fix-me          : attempts to run an fix when a verification fails
  --generate-ts     : generate a tar.gz archives containing the scheduler logs for TAC

  -v, --verbose     : show traces
  -h, --help        : show this help message

examples:
  ./scheduler : run the scheduler for all APICs
  ./scheduler --apic 2 : run the scheduler for APIC 2 only
  ./scheduler --apic 2 --root-pwd 1234 --fix-me : run the scheduler for APIC 2 and attemps fix
  ./scheduler --generate-ts : generate the techsupport bundle
```

### Run in fix mode

Work in progress

### Generate ts bundle

```bash
admin@bdsol-aci13-apic1:techsupport> ./scheduler.sh --generate-ts
/var/log/dme/log/insieme_fwhdr.ifc.log
/var/log/dme/log/insieme_fwhdr.root.log
/var/log/dme/log/scheduler.log
...
/var/log/dme/log/consul_member.log-20231022-1698004862.gz
/var/log/dme/log/kafka_provision.log
[i] A tar.gz archive has been generated under /data/techsupport/Scheduler-2023-10-30.tgz
admin@bdsol-aci13-apic1:techsupport> ls | grep Scheduler
Scheduler-2023-10-30-09:35:26.tgz
```
