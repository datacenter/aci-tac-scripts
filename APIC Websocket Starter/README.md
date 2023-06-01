# APIC Websocket Starter

Script to quickly instantiate APIC Query Subscriptions (via Web Sockets) for testing, monitoring and/or troubleshooting and isolation.

## Quickstart

## Getting Started

```
$ python apic_query_subscription.py -h
usage: apic_query_subscription.py [-h] [-a [APIC_ADDR]] [-u [USERNAME]] [-x]

optional arguments:
  -h, --help            show this help message and exit
  -a [APIC_ADDR], --apic-ip [APIC_ADDR]
                        APIC IP Address. Ex: '192.168.1.1'
  -u [USERNAME], --username [USERNAME]
                        APIC Account username. Ex: 'apic#fallback\admin'
  -x, --xml             Use xml encoding. Default is json.
```

In a python3 environment:

1. Install requirements.txt
2. Copy the `apic_query_subscription.py`
3. Modify `QUERIES_TO_SUBSCRIBE` with interested APIC Queries
4. [Optional] Modify the default `apic_addr`, `username` and `user_pwd`
5. Run ``apic_query_subscription.py`.

If defaults not modified, explicitly provide the APIC IP and Username arguments:

```
python apic_query_subscription.py -a 192.168.1.1 -u automationUser
```

## Defining QUERIES_TO_SUBSCRIBE

`QUERIES_TO_SUBSCRIBE` is a list of dictionaries with each dict representing an APIC Query broken down into the following Keys:

- **api_ep**: `/api/.../` APIC Endpoint URL
- **filters**: [optional] any additional filters to be added to the query. Must begin with `&`.

Working Example:

```
QUERIES_TO_SUBSCRIBE = [
    {"api_ep": "/api/node/mo/uni/tn-CiscoLive"},
    {"api_ep": "/api/class/fvCtx"},
    {"api_ep": "/api/class/topology/pod-1/node-101/vlanCktEp"},
    {
        "api_ep": "/api/class/fvTenant",
        "filters": "&query-target=subtree&target-subtree-class=fvAEPg,fvBD"
    }
]
```

## Usage Example

```
$ python apic_query_subscription.py -a 192.168.1.1 -u automationUser
automationUser password:
********** WebSocket Subscription URIS and IDs **********
WebSocket Subscription Status Code: 101

https://192.168.1.1/api/class/fvTenant.json?subscription=yes&query-target=subtree&target-subtree-class=fvAEPg,fvBD
- Subscription ID: 72059075820650497


********** WebSocket Subscription Messages **********

...do some changes on the APIC under your subscribed objects to receive events...

{"subscriptionId":["72059075820650497"],"imdata":[{"fvBD":{"attributes":{"childAction":"","configIssues":"","dn":"uni/tn-CL/BD-CLbd","modTs":"2023-05-04T16:02:00.972-04:00","rn":"","status":"modified"}}}]}

...

```
