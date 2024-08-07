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

UTC 2024-08-07T02:34:08.741||INFO||(179)||compatSwitchHw and compatSwitchHw MoCount are both 70, postUpgradeCb executed successfully.
UTC 2024-08-07T02:34:09.013||INFO||(179)||infraRsToInterfacePolProfile and infraRsToInterfacePolProfileOpt MoCount are both 17, postUpgradeCb executed successfully.
UTC 2024-08-07T02:34:09.286||INFO||(179)||infraRsToEncapInstDef and infraAssocEncapInstDef MoCount are both 11, postUpgradeCb executed successfully.
UTC 2024-08-07T02:34:09.558||INFO||(179)||infraRsConnectivityProfile and infraRsConnectivityProfileOpt MoCount are both 19, postUpgradeCb executed successfully.
UTC 2024-08-07T02:34:09.829||INFO||(179)||fvIPSLAMonitoringPol and fvSlaDef MoCount are both 1, postUpgradeCb executed successfully.
UTC 2024-08-07T02:34:09.964||INFO||(179)||infraImplicitSetPol and infraImplicitSetPol MoCount are both 1, postUpgradeCb executed successfully.
UTC 2024-08-07T02:34:10.234||INFO||(179)||infraImplicitSetPol and infraRsToImplicitSetPol MoCount are both 1, postUpgradeCb executed successfully.

//infraRsConnectivityProfile is existing class, each Mo's postUpgradeCb function creates its respective infraRsConnectivityProfileOpt instance.

</pre>

## Help documentation

```
apic# python  /data/techsupport/postUpgChecker 

useage: postUpgChecker [-h] [-d {debug,info,warn}]

optional arguments:
  -h, --help            show this help message and exit
  -d {debug,info,warn}

