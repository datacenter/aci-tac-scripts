# Post Upgrade CB Checker

To extend/enhance an existing feature, one approach is to invoke the postUpgradeCb of existing class, so that new class are created after a successful upgrade.

With that, we expect the existing Mo's count should be exactly match the newly created Mos.

Leverage the strongest ever API of APIC, This script query both existing classes and new classes, then compare the MoCount, if mismatch found, then raise the alert.

Only the Mos exsited in current version will be queried, more info can bd found from the NewMoDict.


# Required python3 and below packages

N/A, this script should be run from APIC directly.

## Quickstart

Upload the script to /data/techsupport, then run it

python /data/techsupport/postUpgChecker

## Full Run Example

<pre>

apic# python  /data/techsupport/postUpgChecker

AEDT 2024-02-07T16:50:04.986||INFO||(150)||infraRsConnectivityProfile has 19 Mo, postUpgradeCb successfully created 19 infraRsConnectivityProfileOpt
AEDT 2024-02-07T16:50:05.256||INFO||(150)||infraImplicitSetPol has 1 Mo, postUpgradeCb successfully created 1 infraRsToImplicitSetPol
AEDT 2024-02-07T16:50:05.584||INFO||(150)||infraRsToEncapInstDef has 11 Mo, postUpgradeCb successfully created 11 infraAssocEncapInstDef
AEDT 2024-02-07T16:50:05.859||INFO||(150)||infraImplicitSetPol has 1 Mo, postUpgradeCb successfully created 1 infraImplicitSetPol  
AEDT 2024-02-07T16:50:06.124||INFO||(150)||fvIPSLAMonitoringPol has 1 Mo, postUpgradeCb successfully created 1 fvSlaDef 

//infraRsConnectivityProfile is existing class, each Mo's postUpgradeCb function creates its respective infraRsConnectivityProfileOpt instance.

</pre>

## Help documentation

```
apic# python  /data/techsupport/postUpgChecker 

useage: postUpgChecker [-h] [-d {debug,info,warn}]

optional arguments:
  -h, --help            show this help message and exit
  -d {debug,info,warn}

