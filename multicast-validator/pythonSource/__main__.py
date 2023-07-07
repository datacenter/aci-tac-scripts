#!/opt/cisco/system-venv3/bin/python3

import sys
version = f'''{sys.version_info[0]}.{sys.version_info[1]}'''
dirs = [f'/opt/cisco/system-venv3/lib64/python{version}/site-packages', f'/opt/cisco/system-venv3/lib/python{version}/site-packages']
sys.path = sys.path + dirs
from mcast import ext_src_int_rcvr, int_src_ext_rcvr, int_src_int_rcvr, ext_src_ext_rcvr
from utils import setup_logger
import os
import json
import argparse
import logging
from functools import partial

logger = logging.getLogger(__name__)
setup_logger(logger, "debug")

#Get node id from a given ptep
def get_node_from_ptep(ptep):
    for k, v in node_info_dic.items():
        if v == key1:
            return k

#Allow user to select their multicast topology
def mcast_topology_menu(options):
    print("Describe the multicast topology:")
    for index, option in enumerate(options):
        print(f"{index+1}. {option[0]}")

    choice = input("Enter your choice (1-{0}), or 'q' to quit: ".format(len(options)))

    if choice.lower() == 'q':
        print("Exiting...")
        return

    try:
        choice = int(choice)
        if 1 <= choice <= len(options):
            selected_option = options[choice - 1]
            selected_option[1]()  # Call the associated action function
        else:
            print("Invalid choice. Please select a valid option.")
    except ValueError:
        print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(
        description='''This code orchestrates debugging of multicast routing in ACI.''')
    
    parser.add_argument('-u', '--username', action='store', type=str, help='Specify the username used for remote connections.')
    parser.add_argument('-t', '--tenant', action='store', type=str, help='Specify the tenant name of the multicast flow')
    parser.add_argument('-v', '--vrf', action='store', type=str, help='Specify the vrf name of the multicast flow')
    parser.add_argument('-r', '--rcvr', action='store', type=str, help='Specify the IP address of the multicast receiver')
    parser.add_argument('-s', '--src', action='store', type=str, help='Specify the IP address of the multicast source')
    parser.add_argument('-g', '--group', action='store', type=str, help='Specify the IP address of the multicast group')
    args                = parser.parse_args()

    #Present arg prompts for anything that wasn't supplied
    uname = args.username if isinstance(args.username, str) else input("Enter username used for ssh to leafs/spines: ")
    tenant = args.tenant  if isinstance(args.tenant  , str) else input("Enter tenant name containing mcast resources: ")
    vrf = args.vrf        if isinstance(args.vrf     , str) else input("Enter vrf name of mcast resources: ")
    rcvr = args.rcvr      if isinstance(args.rcvr    , str) else input("Enter IP address of mcast receiver: ")
    src = args.src        if isinstance(args.src     , str) else input("Enter source IP address of mcast flow: ")
    group = args.group    if isinstance(args.group   , str) else input("Enter multicast group IP address: ")

    #Dict for node id to ptep mapping.
    #host_list = []
    node_info_dic = {} #this dic is set to format of nodeId : ptep
    node_info_list = ((os.popen("""acidiag fnvread | grep " active" | awk '{print $1,$5}' | awk -F "/" '{print $1}'""").read()).replace("\n", ",").strip()).rstrip(',').lstrip(',').split(",")
    for node in node_info_list:
        node_elem = node.split(" ")
        node_info_dic[node_elem[0]] = node_elem[1]

    #Dict for ptep to node id mapping.
    #host_list = []
    node_info_dic2 = {} #this dic is set to format of nodeId : ptep
    for node in node_info_list:
        node_elem = node.split(" ")
        node_info_dic2[node_elem[1]] = node_elem[0]
    #host_list = list(node_info_dic.values())

    param_dic = {"uname"   : uname,
                 "tenant"  : tenant,
                 "vrf"     : vrf,
                 "rcvr"    : rcvr,
                 "src"     : src,
                 "group"   : group,
                 "nd"      : node_info_dic,
                 "nd2"     : node_info_dic2}

    #Get mcast topology info and kick off checks
    menu_options = [("Mcast source is EXTERNAL to ACI (behind l3out) AND mcast receiver is INTERNAL to ACI (endpoint)", partial(ext_src_int_rcvr, param_dic)),
                    ("Mcast source is INTERNAL to ACI (endpoint) AND mcast receiver is EXTERNAL to ACI (behind l3out)", partial(int_src_ext_rcvr, param_dic)),
                    ("Both mcast source AND mcast receiver are INTERNAL to ACI (learned endpoints)", partial(int_src_int_rcvr, param_dic)),
                    ("Both mcast source AND mcast receiver are EXTERNAL to ACI (multicast transit routing)", partial(ext_src_ext_rcvr, param_dic))]
    mcast_topology_menu(menu_options)

