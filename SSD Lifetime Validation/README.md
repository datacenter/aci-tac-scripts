# SSD Lifetime Validation Script

**File:** `SSD-Lifetime-Validation.py`  
**Compatibility:** Python 2.7 and Python 3.x  
**Must run on:** Cisco APIC

---

## Table of Contents

1. [Background](#background)
2. [How It Works](#how-it-works)
3. [Usage](#usage)
   - [Command-line Arguments](#command-line-arguments)
4. [Console Output](#console-output)
   - [Section 1 — SSDs Actually Over 80% (Action Required)](#section-1--ssds-actually-over-80-action-required)
   - [Section 2 — Switches Hitting CSCwt38698 (False Positives)](#section-2--switches-hitting-cscwt38698-false-positives)
5. [CSV Output](#csv-output)
   - [Columns](#columns)
6. [Supported SSD Models and P/E Thresholds](#supported-ssd-models-and-pe-thresholds)
7. [Log Files](#log-files)
8. [Requirements](#requirements)
9. [Relevant Defect](#relevant-defect)
10. [Example Run](#example-run)

---

## Background

Starting in **ACI version 6.1(5e)** and later, smartctl **Attribute 202** was incorrectly added to SSD fault monitoring. This causes switches with **Micron SSDs** to raise SSD lifetime faults (**F3074** – minor, **F3073** – major) even when the SSD has **not** crossed 80% usage when measured correctly against the Program/Erase (P/E) cycle, Raw Read Error (RRE), and Grown Bad Block (GBB) thresholds.

This is tracked under Cisco defect **CSCwt38698**:  
https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwt38698

This script provides customers with:

1. **Accurate P/E-based lifetime calculations** for all switches in the fabric (not just Micron).
2. **Identification of which Micron switches have a fault raised incorrectly** (false positives due to CSCwt38698).
3. **Actual lifetime values** for those switches so the customer has a source of truth.
4. A **CSV export** of all findings for offline review or TAC case attachment.

---

## How It Works

The script performs the following steps:

| Step | Description |
|------|-------------|
| 1 | Queries `topSystem` REST API to retrieve the fabric name and domain. |
| 2 | Queries `firmwareCtrlrRunning` REST API to retrieve the ACI version. |
| 3 | Queries `fabricNode` REST API to collect all switch nodes. Only nodes with `fabricSt = active` are retained — inactive nodes have no corresponding `eqptFlash` record. |
| 4 | Queries `eqptFlash` REST API to collect SSD records per node including: `model`, `vendor`, `peCycles`, `lifetime`, `minorAlarm`, `majorAlarm`. |
| 5 | Matches each SSD model against the `SSD_THRESHOLDS` table to look up the rated maximum P/E cycle count (`pe_max`). |
| 6 | For **Micron drives only**: calculates `pe_lifetime_pct = (peCycles / pe_max) × 100`. For all other vendors the APIC-reported `lifetime` field is accurate and is used directly as the drive's lifetime. |
| 7 | Derives **Actual Lifetime %**: `pe_lifetime_pct` for Micron, `lifetime` from `eqptFlash` for all other vendors. This is the single source-of-truth lifetime value used for sorting, threshold evaluation, and the console report. |
| 8 | Reads `minorAlarm` (F3074) and `majorAlarm` (F3073) fields from `eqptFlash`. |
| 9 | Flags **CSCwt38698**: Micron SSD + alarm raised + `pe_lifetime_pct < 80%`. |
| 10 | Writes a CSV report (sorted by **Actual Lifetime % descending**). |
| 11 | Prints a console summary with two clearly separated sections (see below). |

---

## Usage

Run directly on the **APIC** (requires `icurl` and `acidiag`):

```bash
# Auto-generated filename (includes fabric name + timestamp)
python SSD-Lifetime-Validation.py

# Specify a custom output filename
python SSD-Lifetime-Validation.py --csv my_output.csv
```

### Command-line Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--csv <filename>` | `<FabricName>_ssd-lifetime-validation-<YYYY-MM-DD_HHMM>.csv` | Output CSV filename |

---

## Console Output

The summary report is printed to stdout with two sections in priority order:

### Section 1 — SSDs Actually Over 80% (Action Required)

```
╔═════════════════════════════════════════════════════════════════╗
║  SWITCH SSDs ACTUALLY OVER 80% USAGE  -  ACTION REQUIRED        ║
║  These switches have a genuine lifetime >= 80%.                 ║
║  They are NOT hitting CSCwt38698; the fault is valid.           ║
╚═════════════════════════════════════════════════════════════════╝
```

- Applies to **all vendors** (not just Micron). Uses **`Actual Lifetime %`** as the threshold.
- Sorted **descending by Actual Lifetime %** — most critical drives listed first.
- Console column header: `Actual Life%`.
- If any alarm is raised on these switches, it is **genuine and requires attention**.

### Section 2 — Switches Hitting CSCwt38698 (False Positives)

```
┌─────────────────────────────────────────────────────────────────┐
│  SWITCHES HITTING CSCwt38698  -  ALARM IS WRONG                 │
│  Micron SSD + alarm raised + P/E lifetime < 80%.                │
│  The fault (F3073/F3074) is a false positive due to CSCwt38698. │
└─────────────────────────────────────────────────────────────────┘
```

- Only Micron SSDs where an alarm is raised but `pe_lifetime_pct < 80%`.
- Sorted **descending by Actual Lifetime %** — drives closest to 80% are at the top.
- Console column header: `Actual Life%`.
- The reported alarm is **not reflecting true SSD wear** and is caused by the defect.

---

## CSV Output

The CSV is written to the current working directory, sorted by **Actual Lifetime % descending**.

### Columns

| Column | Description |
|--------|-------------|
| `Fabric Name` | ACI fabric domain name (from `topSystem.fabricDomain`) |
| `Fabric Version` | ACI software version |
| `Switch Name` | Node hostname |
| `Switch IP` | Management IP address |
| `Node ID` | Fabric node ID |
| `Platform` | Hardware model (e.g. N9K-C93180YC-FX) |
| `Switch Serial` | Switch chassis serial number |
| `Node State` | Fabric state (e.g. `active`) |
| `SSD Vendor` | SSD vendor (Micron, Intel, Hynix, Smart Modular) |
| `SSD Model` | Full SSD model string |
| `SSD Serial` | SSD drive serial number |
| `Firmware` | SSD firmware revision |
| `P/E Cycles (current)` | Current Program/Erase cycle count from `eqptFlash.peCycles` |
| `P/E Max (threshold)` | Rated maximum P/E cycles from `SSD_THRESHOLDS` (empty for WLC-based vendors) |
| `Actual Lifetime %` | **Primary lifetime column.** `P/E Lifetime %` for Micron drives; `APIC Reported Lifetime %` for all other vendors. CSV is sorted descending by this column. |
| `P/E Lifetime %` | Calculated `(peCycles / pe_max) × 100` — **Micron only**. Empty for Intel, Hynix, and Smart Modular. |
| `APIC Reported Lifetime %` | Raw `lifetime` field from `eqptFlash`. May be incorrect for Micron on affected ACI versions (CSCwt38698). Accurate for all other vendors. |
| `Minor Alarm - F3074 (yes/no)` | Value of `eqptFlash.minorAlarm` |
| `Major Alarm - F3073 (yes/no)` | Value of `eqptFlash.majorAlarm` |
| `Alarm Raised` | `Yes` if either F3073 or F3074 is active |
| `CSCwt38698 Hit` | `Yes` if Micron + alarm raised + P/E lifetime < 80% |
| `CSCwt38698 URL` | Link to the public defect (populated only when `CSCwt38698 Hit = Yes`) |
| `Notes` | Additional context (e.g. unrecognized model, missing P/E data) |

> **Note:** Switches where the SSD model is not found in `SSD_THRESHOLDS` will have empty `P/E Max` and `P/E Lifetime %` fields. A note is added in the `Notes` column. For non-Micron drives, `P/E Lifetime %` is always empty — `Actual Lifetime %` reflects `APIC Reported Lifetime %` instead.

---

## Supported SSD Models and P/E Thresholds

| Vendor | Model | P/E Max |
|--------|-------|---------|
| Micron | M550-64G (`Micron_M550_MTFDDAT064`) | 15,000 |
| Micron | M550-256G (`Micron_M550_MTFDDAT256`) | 15,000 |
| Micron | M600-64G (`Micron_M600_MTFDDAT064`) | 5,000 |
| Micron | M600-64G-MBF (`Micron_M600_MTFDDAT064MBF`) | 5,000 |
| Micron | M600-256G (`Micron_M600_MTFDDAT256`) | 24,000 |
| Micron | M1100-256G (`Micron_1100_MTFDDAV256TBN`) | 6,000 |
| Micron | M500IT-64G (`Micron_M500IT_MTFDDAT064SBD`) | 35,000 |
| Micron | M500IT-256G (`Micron_M500IT_MTFDDAT256MBD`) | 35,000 |
| Micron | M5100-240G (`Micron_5100_MTFDDAV240TCB`) | 10,000 |
| Micron | M5300-240G (`Micron_5300_MTFDDAV240TDS`) | 10,000 |
| Micron | M5400-240G (`Micron_5400_MTFDDAV240TGA`) | 8,500 |
| Hynix | HFS064G3AMNC-3310A DX | — (WLC-based, P/E not applicable) |
| Smart Modular | SHMST064G3FECTLP51 | 30,000 |
| Smart Modular | SHMST064G3FDCTL121 | 3,600 |
| Smart Modular | SR9MST6D064BQF71C | 10,000 |
| Smart Modular | SR9MST6D240GQF71C | 10,000 |
| Smart Modular | SRM28128AF1M2BC2C | 10,000 |
| Smart Modular | SMART128 (`SRM2SH6Q128AQT51C`) | 3,600 |
| Smart Modular | SMART60 (`SA9MST6060GKP21C`) | 30,000 |
| Intel | SSDSCKJB150G7 | — (WLC-based, P/E not applicable) |
| Intel | SSDSCKKB240G8K | — (WLC-based, P/E not applicable) |

> Hynix and Intel drives use a **Wear Level Count (WLC)** metric instead of P/E cycles. `P/E Lifetime %` will be empty for these drives — their `Actual Lifetime %` is sourced from the APIC-reported `lifetime` field directly. The same applies to Smart Modular drives.

---

## Log Files

Logs are written to `./logs/ssd-lifetime-validation-<YYYY-MM-DD>.log` in the directory where the script is run.

- **DEBUG** level: full per-node detail (model match, P/E values, alarm states, CSCwt38698 determination)
- **INFO/WARNING/ERROR**: operational issues (API failures, parse errors)
- Log files rotate at 10 MB, keeping up to 5 backups.

---

## Requirements

- Must be run **on a Cisco APIC**.
- Python 2.7 or Python 3.x (no external packages required beyond the standard library).
- No credentials are required.

---

## Relevant Defect

| Field | Value |
|-------|-------|
| Defect ID | CSCwt38698 |
| Summary | Micron SSD lifetime fault raised incorrectly due to Attribute 202 in ACI 6.1(5e)+ |
| Affected versions | ACI 6.1(5e) and later |
| Affected SSD vendor | Micron |
| Faults raised | F3073 (major / 90%), F3074 (minor / 80%) |
| Public URL | https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwt38698 |

## Example Run
```
admin@apic1:jl> python SSD-Lifetime-Validation.py 
======================================================
 ACI SSD Lifetime Validation Script
 2026-03-02 07:38:15.973264
======================================================

Collecting fabric information...
  Fabric     : Fabric1
  ACI version: 6.1(5e)

Collecting switch (fabricNode) data...
  Found 506 switches.
Collecting SSD (eqptFlash) data...
  Found eqptFlash records for 506 nodes.

Processing switches...
  Processed 506 switches.

Generating CSV report: Fabric1_ssd-lifetime-validation-2026-03-02_0738.csv

======================================================================
 SSD Lifetime Validation Summary
 Fabric : Fabric1  |  Version : 6.1(5e)
 Run at : 2026-03-02 07:38:16.799558
======================================================================
  Total switches processed       : 506
  Switches with Micron SSD       : 421
  *** SSDs actually over 80%     : 5 ***
  Switches with active alarm     : 70
  CSCwt38698 affected (false +ve): 65
======================================================================

  ╔═════════════════════════════════════════════════════════════════╗
  ║  SWITCH SSDs ACTUALLY OVER 80% USAGE  -  ACTION REQUIRED        ║
  ║  These switches have a genuine lifetime >= 80%.                 ║
  ║  They are NOT hitting CSCwt38698; the fault is valid.           ║
  ╚═════════════════════════════════════════════════════════════════╝
  Switch                 IP              Node ID   SSD Model      Actual Life%  Vendor   F3074    F3073   
  ----------------------------------------------------------------------------------------------------
  leaf415         10.0.24.65      415       Micron_M600_M  110.5%        Micron   no       yes     
  leaf416         10.0.160.73     416       Micron_M600_M  107.2%        Micron   no       yes     
  leaf417         10.0.0.78       417       Micron_M600_M  105.9%        Micron   no       yes     
  pod7-leaf26     10.7.16.65      1726      Micron_M600_M  87.7%         Micron   no       yes     
  leaf430         10.0.248.3      430       Micron_M550_M  80.2%         Micron   no       yes     

  ┌─────────────────────────────────────────────────────────────────┐
  │  SWITCHES HITTING CSCwt38698  -  ALARM IS WRONG                 │
  │  Micron SSD + alarm raised + P/E lifetime < 80%.                │
  │  The fault (F3073/F3074) is a false positive due to CSCwt38698. │
  └─────────────────────────────────────────────────────────────────┘
  Switch                 IP              Node ID   SSD Model      Actual Life%  F3074    F3073   
  --------------------------------------------------------------------------------------------
  leaf431         10.0.248.6      431       Micron_M600_M  77.6%      no       yes     
  pod7-leaf34     10.7.16.89      1734      Micron_M600_M  76.8%      no       yes     
  pod7-leaf27     10.7.16.81      1727      Micron_M600_M  68.9%      no       yes     
  pod5-leaf6      10.5.248.0      1506      Micron_M600_M  64.4%      no       yes     
  leaf33          10.0.0.75       133       Micron_1100_M  35.2%      no       yes     
  leaf10          10.0.48.80      110       Micron_1100_M  33.5%      no       yes     
  leaf9           10.0.48.92      109       Micron_1100_M  33.4%      no       yes     
  leaf4           10.0.48.77      104       Micron_1100_M  32.8%      no       yes     
  leaf5           10.0.248.11     105       Micron_1100_M  32.4%      no       yes     
  leaf38          10.0.232.83     138       Micron_1100_M  32.4%      no       yes     
  leaf31          10.0.40.65      131       Micron_1100_M  32.2%      no       yes     
  leaf39          10.0.48.86      139       Micron_1100_M  32.1%      no       yes     
  leaf30          10.0.232.92     130       Micron_1100_M  32.0%      no       yes     
  leaf35          10.0.24.68      135       Micron_1100_M  31.6%      no       yes     
  leaf29          10.0.16.76      129       Micron_1100_M  31.2%      no       yes     
  leaf45          10.0.40.73      145       Micron_1100_M  30.9%      no       yes     
  leaf47          10.0.0.85       147       Micron_1100_M  30.8%      no       yes     
  leaf53          10.0.16.74      153       Micron_1100_M  30.7%      no       yes     
  leaf60          10.0.56.76      160       Micron_1100_M  30.7%      no       yes     
  leaf32          10.0.32.91      132       Micron_1100_M  30.5%      no       yes     
  leaf27          10.0.24.67      127       Micron_1100_M  30.4%      no       yes     
  leaf7           10.0.48.93      107       Micron_1100_M  30.3%      no       yes     
  leaf57          10.0.24.64      157       Micron_1100_M  30.3%      no       yes     
  leaf42          10.0.24.84      142       Micron_1100_M  30.2%      no       yes     
  leaf43          10.0.64.131     143       Micron_1100_M  30.2%      no       yes     
  leaf44          10.0.248.21     144       Micron_1100_M  30.1%      no       yes     
  leaf51          10.0.96.66      151       Micron_1100_M  30.1%      no       yes     
  leaf28          10.0.56.85      128       Micron_1100_M  30.1%      no       yes     
  leaf34          10.0.48.74      134       Micron_1100_M  30.0%      no       yes     
  leaf8           10.0.248.25     108       Micron_1100_M  29.9%      no       yes     
  leaf54          10.0.56.70      154       Micron_1100_M  29.9%      no       yes     
  leaf41          10.0.40.64      141       Micron_1100_M  29.9%      no       yes     
  leaf46          10.0.48.72      146       Micron_1100_M  29.6%      no       yes     
  leaf50          10.0.48.71      150       Micron_1100_M  29.6%      no       yes     
  leaf11          10.0.48.66      111       Micron_1100_M  29.5%      no       yes     
  leaf12          10.0.248.18     112       Micron_1100_M  29.4%      no       yes     
  leaf13          10.0.104.93     113       Micron_1100_M  29.0%      no       yes     
  leaf20          10.0.40.121     120       Micron_1100_M  29.0%      no       yes     
  leaf130         10.0.248.0      230       Micron_1100_M  28.5%      no       yes     
  leaf69          10.0.8.67       169       Micron_1100_M  28.1%      no       yes     
  leaf48          10.0.136.73     148       Micron_1100_M  28.0%      no       yes     
  leaf2           10.0.48.81      102       Micron_1100_M  27.0%      no       yes     
  leaf1           10.0.48.78      101       Micron_1100_M  25.7%      no       yes     
  leaf65          10.0.176.94     165       Micron_1100_M  25.3%      no       yes     
  pod7-leaf23     10.7.16.83      1723      Micron_1100_M  25.0%      no       yes     
  leaf84          10.0.200.75     184       Micron_1100_M  24.2%      no       yes     
  leaf6           10.0.176.82     106       Micron_1100_M  24.1%      no       yes     
  leaf70          10.0.232.94     170       Micron_1100_M  24.1%      no       yes     
  pod9-spine1     10.9.200.64     3901      Micron_M600_M  23.3%      no       yes     
  leaf83          10.0.24.87      183       Micron_1100_M  23.2%      no       yes     
  leaf86          10.0.48.75      186       Micron_1100_M  23.2%      no       yes     
  pod7-leaf24     10.7.136.70     1724      Micron_1100_M  23.0%      no       yes     
  leaf62          10.0.120.81     162       Micron_1100_M  22.7%      no       yes     
  leaf36          10.0.232.68     136       Micron_1100_M  22.4%      yes      no      
  leaf63          10.0.24.73      163       Micron_1100_M  22.3%      yes      no      
  leaf64          10.0.136.65     164       Micron_1100_M  22.1%      yes      no      
  leaf389         10.0.40.96      389       Micron_1100_M  21.5%      yes      no      
  leaf154         10.0.64.130     254       Micron_1100_M  21.4%      yes      no      
  leaf66          10.0.40.110     166       Micron_1100_M  21.4%      yes      no      
  leaf153         10.0.200.80     253       Micron_1100_M  21.2%      yes      no      
  leaf14          10.0.136.78     114       Micron_1100_M  21.1%      yes      no      
  leaf390         10.0.56.65      390       Micron_1100_M  20.9%      yes      no      
  leaf67          10.0.248.24     167       Micron_1100_M  20.2%      yes      no      
  pod7-spine2     10.7.16.75      3702      Micron_M600_M  15.0%      no       yes     
  spine3          10.0.248.1      303       Micron_M500IT  7.0%       no       yes     

  Defect URL: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwt38698

  Full CSV report for all switches : Fabric1_ssd-lifetime-validation-2026-03-02_0738.csv
======================================================================

Completed in 0.8 seconds.
```
