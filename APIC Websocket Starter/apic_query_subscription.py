# !/usr/bin/env python
from threading import Thread
import websocket
import argparse
import requests
import getpass
import time
import json
import ssl

QUERIES_TO_SUBSCRIBE = [
    {
        "api_ep": "/api/class/fvTenant",
        "filters": "&query-target=subtree&target-subtree-class=fvAEPg,fvBD",
    },
    {"api_ep": "/api/class/topology/pod-1/node-101/vlanCktEp"},
    {"api_ep": "/api/class/commRequestData"},
]

requests.packages.urllib3.disable_warnings()


def get_auth_cookie():
    """Get APIC Cookie"""
    payload = {"aaaUser": {"attributes": {"name": USER, "pwd": PWD}}}
    if ENC == ".xml":
        payload = f"<aaaUser name='{USER}' pwd='{PWD}'/>"
    login_response = requests.post(
        f"{BASE_URL}/api/aaaLogin{ENC}", json=payload, verify=False
    )
    try:
        response_dict = json.loads(login_response.content)
        token = response_dict["imdata"][0]["aaaLogin"]["attributes"]["token"]
    except json.decoder.JSONDecodeError:
        parsed_response = ET.fromstring(login_response.content)
        token = parsed_response.find("aaaLogin").get("token")
    cookie = {"APIC-cookie": token}
    return cookie


def open_web_socket(cookie):
    """Create APIC Web Socket Connection"""
    token = cookie.get("APIC-cookie")
    websocket_url = f"wss://{APIC}/socket{token}"
    ws = websocket.create_connection(websocket_url, sslopt={"cert_reqs": ssl.CERT_NONE})
    print(f"WebSocket Subscription Status Code: {ws.status}\n")
    return ws


def subscribe_to_queries(cookie):
    """Subscribe to all queries in list. Returns a dict of query:subid"""
    query_to_subid = {}
    for query in QUERIES_TO_SUBSCRIBE:
        url = f"{BASE_URL}{query['api_ep']}{ENC}?subscription=yes{query.get('filters','')}"
        subscription_response = requests.get(url, verify=False, cookies=cookie)

        try:
            subid = json.loads(subscription_response.text).get("subscriptionId")
        except json.decoder.JSONDecodeError:
            parsed_response = ET.fromstring(subscription_response.text)
            subid = parsed_response.get("subscriptionId")

        query_to_subid[query["api_ep"]] = subid
        print(f"{url}\n- Subscription ID: {query_to_subid[query['api_ep']]}\n")
    return query_to_subid


def print_mo_updates(ws):
    while True:
        print(ws.recv())


def refresh_ws_subscriptions(query_to_subid, cookie):
    """Refresh the websocket subscription every 30 seconds"""
    while True:
        time.sleep(30)
        for query, subid in query_to_subid.items():
            url = f"{BASE_URL}/api/subscriptionRefresh{ENC}?id={subid}"
            refresh_resp = requests.get(url, verify=False, cookies=cookie)


def main():
    cookie = get_auth_cookie()

    print(f"{'*'*10} WebSocket Subscription URIS and IDs {'*'*10}")
    ws = open_web_socket(cookie)
    query_to_subid = subscribe_to_queries(cookie)

    print(f"{'*'*10} WebSocket Subscription Messages {'*'*10}")
    Thread(target=print_mo_updates, args=[ws]).start()
    Thread(
        target=refresh_ws_subscriptions,
        args=[
            query_to_subid,
            cookie,
        ],
    ).start()


if __name__ == "__main__":
    global APIC
    global USER
    global PWD
    global BASE_URL
    global ENC

    user_pwd = ""  # [optional] Hardcoded APIC User PWD

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-a",
        "--apic-ip",
        dest="apic_addr",
        default="192.168.1.1",
        help="APIC IP Address. Ex: '192.168.1.1'",
        required=False,
        nargs="?",
    )
    parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default="apic#fallback\\admin",
        help="APIC Account username. Ex: 'apic#fallback\\admin'",
        required=False,
        nargs="?",
    )
    parser.add_argument(
        "-x",
        "--xml",
        action="store_true",
        dest="xml_enc",
        help="Use xml encoding. Default is json.",
    )
    args = parser.parse_args()

    APIC = args.apic_addr
    USER = args.username
    BASE_URL = f"https://{APIC}"
    ENC = ".json"

    print(f"Logging into APIC {APIC}")

    if args.xml_enc:
        import xml.etree.ElementTree as ET

        ENC = ".xml"

    if not user_pwd:
        user_pwd = getpass.getpass(prompt=f"{USER} password: ")
    PWD = user_pwd
    main()
