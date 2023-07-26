#!/opt/cisco/system-venv3/bin/python3

import sys
version = f'''{sys.version_info[0]}.{sys.version_info[1]}'''
dirs = [f'/opt/cisco/system-venv3/lib64/python{version}/site-packages', f'/opt/cisco/system-venv3/lib/python{version}/site-packages']
sys.path = sys.path + dirs
from utils import ssh_conn, get_attribute, query_class, query_dn, setup_logger, handle_api_rsp, get_password, ftriage, get_fab_details
import re
import os
import json
import logging

logger = logging.getLogger(__name__)
setup_logger(logger, "debug")

#Use for testing
#arg_dic = {'uname': 'josephyo', 'tenant': 'jy', 'vrf': 'l3vrf1', 'rcvr': '192.168.255.100', 'src': '192.168.254.100', 'group': '229.0.0.100', 'nd': {'102': '10.0.216.68', '103': '10.0.216.67', '201': '10.2.168.65', '202': '10.2.216.67', '203': '10.2.216.65', '1201': '10.0.216.66', '1202': '10.0.216.65', '1203': '10.0.216.69', '2010': '10.20.0.176', '2202': '10.2.216.64'}, 'nd2': {'10.0.216.68': '102', '10.0.216.67': '103', '10.2.168.65': '201', '10.2.216.67': '202', '10.2.216.65': '203', '10.0.216.66': '1201', '10.0.216.65': '1202', '10.0.216.69': '1203', '10.20.0.176': '2010', '10.2.216.64': '2202'}}

version, self_ip, self_node = get_fab_details()
my_ver = version[self_node]
#mcast_role stores info about if each leaf is a receiver leaf (RL), source leaf (SL), border leaf (BL), or multiple
mcast_role = {}
for k in version.keys():
    mcast_role[k] = []

#TODO - Add fault checks for anything related to multicast or PIM

######################################################################
#Handles logic if the source is external and the receiver is internal#
######################################################################
def ext_src_int_rcvr(arg_dic):
    global param_dic
    param_dic = arg_dic
    global msource, mdest
    msource = "external"
    mdest = "internal"
    
    ####
    ####Is PIM enabled on VRF and get gipo
    ####
    vrf_dn, vrf_gipo, vrf_vnid = check_pim_vrf()
    
    ####
    ####Check for pim enabled l3outs configured in the supplied vrf
    ####
    check_pim_l3outs(vrf_dn)
    
    ####
    ####Get BL List that has deployed loopbacks in the intended vrf
    ####
    lo_dic = check_pim_loopbacks(vrf_dn)
    for k in lo_dic.keys():
        mcast_role[k].append("BL")
    
    ####
    ####Get configured RP info
    ####
    rp_info = get_rp(vrf_dn)
    if len(rp_info) == 0:
        logger.warning(f'''FAILURE - No RP addresses were found configured in vrf {vrf_dn}. This config is required.''')
        logger.info('Exiting')
        sys.exit()
    
    ####
    ####Find local endpoint learn for the receiver in format of {ip : '', mac : '', bd : '', node : '', interface : []}
    ####
    rcvr_ep_dic = get_ep_info(vrf_dn, param_dic['rcvr'], vrf_vnid, 'receiver')
    logger.info(f'''Endpoint learn for receiver was found for ip {param_dic['rcvr']} in vrf {vrf_dn}:"''')
    for k, v in rcvr_ep_dic.items():
        mcast_role[k].append("RL")
        print(f'''node-{k}    {v}''')
        bd_vnid = v['bd_vnid']
    
    ####
    ####BD Config Validations
    ####
    bd_dn, bd_name = handle_bd(bd_vnid)

    ####
    ####Validate receiver leafs have outgoing interfaces in the igmp snooping table for the correct BD
    ####
    check_igmpsnoop(rcvr_ep_dic.keys(), bd_vnid)

    ####
    ####Validate receiver leafs have outgoing interfaces for the igmp group
    ####
    check_l3igmp(rcvr_ep_dic.keys())

    ####
    ####Need to get ssh password for cli commands.
    ####
    logger.info("BEGINNING SWITCH-LEVEL MULTICAST FORWARDING CHECKS!")
    global password
    password = get_password()

    ####
    ####Get fabric-wide pim neighbors within the intended vrf
    ####
    pim_neigh_dic = get_pim_neigh(f'''{param_dic['tenant']}:{param_dic['vrf']}''')
    
    ####
    ####Get stripe-winner for group
    ####
    logger.info('Determining stripe-winner. The stripe winner is responsible for sending PIM joins back to the source and/or RP.')
    stripe_winner_node = get_stripe_winner(lo_dic)
    stripe_winner_node = stripe_winner_node[0]

    ####
    ####Check if there are external incoming interfaces for the multicast group
    ####
    global inif_nodes
    logger.info(f'Checking that external incoming interfaces exist in vrf {vrf_dn}')
    inif_dic = pim_in_ifs(vrf_dn)
    inif_nodes = []
    for k, v in inif_dic.items():
        for i in v:
            for k2, v2 in i.items():
                inif_nodes.append(k2)
    
    inif_nodes = [*set(inif_nodes)]
    
    ####
    ####Get fabric-forwarder for group. Usually will be the same as stripe winner unless
    ####a different BL than the stripe winner has the best route to the RP or Src
    ####
    logger.info('Determining fabric-forwarder. The fabric-forwarder is responsible for forwarding external flows into the fabric. Usually this will be the same as the stripe winner unless a different BL than the stripe winner has the best route to the RP or Src.')
    get_fabricForwarder(lo_dic)
    
    ####
    ####Generic Leaf Checks
    ####
    generic_leaf_checks(lo_dic, pim_neigh_dic, stripe_winner_node)
    
    
    ####
    ####Make sure mcast src is programmed on BL(s) as /32 in hardware
    ####
    logger.info('Validating that src is installed as /32 in hardware on Border Leafs')
    node_list = list(lo_dic.keys())
    check_hal_ep(node_list, stripe_winner_node)

    ####
    ####Make sure mcast group is programmed on all nodes as /32 in hardware
    ####
    logger.info('Validating that multicast group is installed as /32 in hardware on both internal and border leafs.')
    node_list = list(lo_dic.keys())
    check_hal_ep(node_list, stripe_winner_node)
    
    ####
    ####Invoke dataplane check if version is 4.0 or later
    ####
    major_ver = int(my_ver.split(".")[0])
    if major_ver >= 4:
        logger.info('''Current apic version supports datapath debugging for L3 Multicast via Ftriage!''')
        r = input("Execute datapath debugging for multicast flow? (Note: This test may take up to 15 mins to complete): (y/n)\n")
        if r == 'y':
            logger.info('''Beginning dataplane testing for flow using ftriage. Ftriage is a tool that orchestrates ELAMs end to end. There is no impact to this test but please be patient''')
            ftriage(param_dic['uname'], list(lo_dic.keys()), param_dic['src'], param_dic['group'])
        else:
            logger.info("Skipping datapath debugging for this flow")
    else:
        logger.info('''APIC version 4.x or higher is required for datapath testing testing of L3 multicast using Ftriage. Skipping...''')
    
    ####
    ####Spine Coop Checks, might do this later if necessary. Don't see problems with this often.
    ####
    
    logger.info('FINISHED!')

######################################################################
#Handles logic if the source is internal and the receiver is external#
######################################################################
def int_src_ext_rcvr(arg_dic):
    global param_dic
    param_dic = arg_dic
    global msource, mdest
    msource = "internal"
    mdest = "external"
    
    ####
    ####Is PIM enabled on VRF and get gipo
    ####
    vrf_dn, vrf_gipo, vrf_vnid = check_pim_vrf()
    
    ####
    ####Check for pim enabled l3outs configured in the supplied vrf
    ####
    check_pim_l3outs(vrf_dn)
    
    ####
    ####Get BL List that has deployed loopbacks in the intended vrf
    ####
    lo_dic = check_pim_loopbacks(vrf_dn)
    for k in lo_dic.keys():
        mcast_role[k].append("BL")
    
    ####
    ####Get configured RP info
    ####
    rp_info = get_rp(vrf_dn)
    if len(rp_info) == 0:
        logger.warning(f'''FAILURE - No RP addresses were found configured in vrf {vrf_dn}. This config is required.''')
        logger.info('Exiting')
        sys.exit()
    
    ####
    ####Find local endpoint learn for the source in format of {ip : '', mac : '', bd : '', node : '', interface : []}
    ####
    src_ep_dic = get_ep_info(vrf_dn, param_dic['src'], vrf_vnid, 'source')
    logger.info(f'''Endpoint learn for source was found for ip {param_dic['src']} in vrf {vrf_dn}:"''')
    for k, v in src_ep_dic.items():
        mcast_role[k].append("SL")
        print(f'''node-{k}    {v}''')
        bd_vnid = v['bd_vnid']
    
    ####
    ####BD Config Validations
    ####
    bd_dn, bd_name = handle_bd(bd_vnid)

    ####
    ####Need to get ssh password for cli commands.
    ####
    logger.info("BEGINNING SWITCH-LEVEL MULTICAST FORWARDING CHECKS!")
    global password
    password = get_password()

    ####
    ####Get fabric-wide pim neighbors within the intended vrf
    ####
    pim_neigh_dic = get_pim_neigh(f'''{param_dic['tenant']}:{param_dic['vrf']}''')

    ####
    ####Get stripe-winner for group
    ####
    logger.info('Determining stripe-winner. The stripe winner is responsible for sending PIM joins back to the source and/or RP.')
    stripe_winner_node = get_stripe_winner(lo_dic)
    stripe_winner_node = stripe_winner_node[0]

    ####
    ####Check if there are external outgoing interfaces for the multicast group
    ####
    global extif_dic
    logger.info(f'Checking that external outgoing interfaces exist in vrf {vrf_dn}')
    extif_dic = pim_ext_ifs(vrf_dn)

    ####
    ####Generic Leaf Checks
    ####
    generic_leaf_checks(lo_dic, pim_neigh_dic, stripe_winner_node)

    ####
    ####Make sure mcast src is programmed on SL(s) and/or BL(s) as /32 in hardware
    ####
    logger.info('Validating that src is installed as /32 in hardware on Border Leafs and/or Source Leafs')
    s_nodes = [key for key,val in mcast_role.items() if any('SL' in s for s in val)]
    sb_nodes = [key for key,val in mcast_role.items() if any('BL' in s for s in val)] + s_nodes
    check_hal_ep(sb_nodes, stripe_winner_node)
    
    ####
    ####Invoke dataplane check if version is 4.0 or later
    ####
    major_ver = int(my_ver.split(".")[0])
    if major_ver >= 4:
        logger.info('''Current apic version support datapath debugging for L3 Multicast via Ftriage!''')
        r = input("Execute datapath debugging for multicast flow? (Note: This test may take up to 15 mins to complete): (y/n)\n")
        if r == 'y':
            logger.info('''Beginning dataplane testing for flow using ftriage. Ftriage is a tool that orchestrates ELAMs end to end. There is no impact to this test but please be patient''')
            ftriage(param_dic['uname'], list(src_ep_dic.keys()), param_dic['src'], param_dic['group'])
        else:
            logger.info("Skipping datapath debugging for this flow")
    else:
        logger.info('''APIC version 4.x or higher is required for datapath testing testing of L3 multicast using Ftriage. Skipping...''')
    

    logger.info('FINISHED!')

#############################################################
#Handles logic if both the source and receiver are internal #
#This scenario is simple to validate because technically, a #
#l3out isn't required, FHRP programs S,G via dataplane and  #
#receiver leaf programs incoming interface based on having  #
#any route to the RP (even if route isn't pointing to PIM ne#
#############################################################
def int_src_int_rcvr(arg_dic):
    global param_dic
    param_dic = arg_dic
    global msource, mdest
    msource = "internal"
    mdest = "internal"
    
    ####
    ####Is PIM enabled on VRF and get gipo
    ####
    vrf_dn, vrf_gipo, vrf_vnid = check_pim_vrf()
    
    ####
    ####Check for pim enabled l3outs configured in the supplied vrf
    ####
    check_pim_l3outs(vrf_dn)
    
    ####
    ####Get BL List that has deployed loopbacks in the intended vrf
    ####
    lo_dic = check_pim_loopbacks(vrf_dn)
    for k in lo_dic.keys():
        mcast_role[k].append("BL")
    
    ####
    ####Get configured RP info
    ####
    rp_info = get_rp(vrf_dn)
    if len(rp_info) == 0:
        logger.warning(f'''FAILURE - No RP addresses were found configured in vrf {vrf_dn}. This config is required.''')
        logger.info('Exiting')
        sys.exit()
    
    ####
    ####Find local endpoint learn for the source in format of {ip : '', mac : '', bd : '', node : '', interface : []}
    ####
    src_ep_dic = get_ep_info(vrf_dn, param_dic['src'], vrf_vnid, 'source')
    logger.info(f'''Endpoint learn for source was found for ip {param_dic['src']} in vrf {vrf_dn}:"''')
    for k, v in src_ep_dic.items():
        mcast_role[k].append("SL")
        print(f'''node-{k}    {v}''')
        bd_vnid = v['bd_vnid']
    
    ####
    ####Find local endpoint learn for the receiver in format of {ip : '', mac : '', bd : '', node : '', interface : []}
    ####
    rcvr_ep_dic = get_ep_info(vrf_dn, param_dic['rcvr'], vrf_vnid, 'receiver')
    logger.info(f'''Endpoint learn for receiver was found for ip {param_dic['rcvr']} in vrf {vrf_dn}:"''')
    for k, v in rcvr_ep_dic.items():
        mcast_role[k].append("RL")
        print(f'''node-{k}    {v}''')
        bd_vnid = v['bd_vnid']
    
    ####
    ####BD Config Validations
    ####
    bd_dn, bd_name = handle_bd(bd_vnid)

    ####
    ####Validate receiver leafs have outgoing interfaces in the igmp snooping table for the correct BD
    ####
    check_igmpsnoop(rcvr_ep_dic.keys(), bd_vnid)

    ####
    ####Validate receiver leafs have outgoing interfaces for the igmp group
    ####
    check_l3igmp(rcvr_ep_dic.keys())

    ####
    ####Need to get ssh password for cli commands.
    ####
    logger.info("BEGINNING SWITCH-LEVEL MULTICAST FORWARDING CHECKS!")
    global password
    password = get_password()
    
    ####
    ####Get fabric-wide pim neighbors within the intended vrf
    ####
    pim_neigh_dic = get_pim_neigh(f'''{param_dic['tenant']}:{param_dic['vrf']}''')
    
    ####
    ####Get stripe-winner for group, probably don't need this if both source and receiver are internal
    ####
    stripe_winner_node = 'emptyString'
    #logger.info('Determining stripe-winner. The stripe winner is responsible for sending PIM joins back to the source and/or RP.')
    #stripe_winner_node = get_stripe_winner(lo_dic)
    #stripe_winner_node = stripe_winner_node[0]
    
    ####
    ####Generic Leaf Checks
    ####
    generic_leaf_checks(lo_dic, pim_neigh_dic, stripe_winner_node)
    
    ####
    ####Make sure mcast src is programmed on SL(s) and/or BL(s) as /32 in hardware
    ####
    logger.info('Validating that src is installed as /32 in hardware on Border Leafs and/or Source Leafs')
    s_nodes = [key for key,val in mcast_role.items() if any('SL' in s for s in val)]
    sb_nodes = [key for key,val in mcast_role.items() if any('BL' in s for s in val)] + s_nodes
    check_hal_ep(sb_nodes, stripe_winner_node)
    
    ####
    ####Invoke dataplane check if version is 4.0 or later
    ####
    major_ver = int(my_ver.split(".")[0])
    if major_ver >= 4:
        logger.info('''Current apic version support datapath debugging for L3 Multicast via Ftriage!''')
        r = input("Execute datapath debugging for multicast flow? (Note: This test may take up to 15 mins to complete): (y/n)\n")
        if r == 'y':
            logger.info('''Beginning dataplane testing for flow using ftriage. Ftriage is a tool that orchestrates ELAMs end to end. There is no impact to this test but please be patient''')
            ftriage(param_dic['uname'], list(src_ep_dic.keys()), param_dic['src'], param_dic['group'])
        else:
            logger.info("Skipping datapath debugging for this flow")
    else:
        logger.info('''APIC version 4.x or higher is required for datapath testing testing of L3 multicast using Ftriage. Skipping...''')
    
    logger.info('FINISHED!')

##########################################################
#Handles logic if both source and receiver are external. #
#Basically this is multicast transit routing             #
##########################################################
def ext_src_ext_rcvr(arg_dic):
    global param_dic
    param_dic = arg_dic
    global msource, mdest
    msource = "transit"
    mdest = "transit"
    
    ####
    ####Is PIM enabled on VRF and get gipo
    ####
    vrf_dn, vrf_gipo, vrf_vnid = check_pim_vrf()
    
    ####
    ####Check for pim enabled l3outs configured in the supplied vrf
    ####
    check_pim_l3outs(vrf_dn)
    
    ####
    ####Get BL List that has deployed pim-enabled loopbacks in the intended vrf
    ####
    lo_dic = check_pim_loopbacks(vrf_dn)
    for k in lo_dic.keys():
        mcast_role[k].append("BL")
    
    ####
    ####Get configured RP info
    ####
    rp_info = get_rp(vrf_dn)
    if len(rp_info) == 0:
        logger.warning(f'''FAILURE - No RP addresses were found configured in vrf {vrf_dn}. This config is required.''')
        logger.info('Exiting')
        sys.exit()
    
    ####
    ####Need to get ssh password for cli commands.
    ####
    logger.info("BEGINNING SWITCH-LEVEL MULTICAST FORWARDING CHECKS!")
    global password
    password = get_password()

    ####
    ####Get fabric-wide pim neighbors within the intended vrf
    ####
    pim_neigh_dic = get_pim_neigh(f'''{param_dic['tenant']}:{param_dic['vrf']}''')

    ####
    ####Get stripe-winner for group
    ####
    logger.info('Determining stripe-winner. The stripe winner is responsible for sending PIM joins back to the source and/or RP.')
    stripe_winner_node = get_stripe_winner(lo_dic)
    stripe_winner_node = stripe_winner_node[0]

    ####
    ####Check if there are external outgoing interfaces for the multicast group
    ####
    global extif_dic, oif_nodes
    logger.info(f'Checking that external outgoing interfaces exist in vrf {vrf_dn}')
    extif_dic = pim_ext_ifs(vrf_dn)
    oif_nodes = []
    for k, v in extif_dic.items():
        for i in v:
            for k2, v2 in i.items():
                oif_nodes.append(k2)
    
    oif_nodes = [*set(oif_nodes)]

    ####
    ####Check if there are external incoming interfaces for the multicast group
    ####
    global inif_nodes
    logger.info(f'Checking that external incoming interfaces exist in vrf {vrf_dn}')
    inif_dic = pim_in_ifs(vrf_dn)
    inif_nodes = []
    for k, v in inif_dic.items():
        for i in v:
            for k2, v2 in i.items():
                inif_nodes.append(k2)
    
    inif_nodes = [*set(inif_nodes)]

    ####
    ####Generic Leaf Checks
    ####
    generic_leaf_checks(lo_dic, pim_neigh_dic, stripe_winner_node)

    ####
    ####Make sure mcast src is programmed on BL(s) as /32 in hardware
    ####
    logger.info('Validating that src is installed as /32 in hardware on BLs with incoming and outgoing external interfaces')
    check_hal_ep(inif_nodes + oif_nodes, stripe_winner_node)
    
    ####
    ####Invoke dataplane check if version is 4.0 or later
    ####
    major_ver = int(my_ver.split(".")[0])
    if major_ver >= 4:
        logger.info('''Current apic version support datapath debugging for L3 Multicast via Ftriage!''')
        r = input("Execute datapath debugging for multicast flow? (Note: This test may take up to 15 mins to complete): (y/n)\n")
        if r == 'y':
            logger.info('''Beginning dataplane testing for flow using ftriage. Ftriage is a tool that orchestrates ELAMs end to end. There is no impact to this test but please be patient''')
            ftriage(param_dic['uname'], inif_nodes, param_dic['src'], param_dic['group'])
        else:
            logger.info("Skipping datapath debugging for this flow")
    else:
        logger.info('''APIC version 4.x or higher is required for datapath testing testing of L3 multicast using Ftriage. Skipping...''')
    
    logger.info('FINISHED!')

def get_rp(vrf_dn):
    #get staticRP
    rp_dic = {}
    obj_query = f'''query-target-filter=wcard(pimStaticRPPol.dn,"{vrf_dn}")&rsp-subtree=children&rsp-subtree-class=pimStaticRPEntryPol&rsp-subtree-include=required,no-scoped'''
    rsp = query_class('pimStaticRPPol', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if e == 'Object was not found':
        logger.info(f'''Static RP not configured in VRF {vrf_dn}.''')
    elif len(e) > 0:
        logger.warning(f'''API call for pimStaticRPPol in VRF {vrf_dn} failed with error: {e}''')
    else:
        rp_list = []
        for rp in rsp['imdata']:
            rp = rp['pimStaticRPEntryPol']['attributes']['rpIp']
            rp_list.append(rp)
        logger.info(f'''Configured static RP address(es) in VRF {vrf_dn}: {rp_list}''')
        rp_dic['staticRP'] = rp_list
    
    #get fabricRP
    obj_query = f'''query-target-filter=wcard(pimFabricRPPol.dn,"{vrf_dn}")&rsp-subtree=children&rsp-subtree-class=pimStaticRPEntryPol&rsp-subtree-include=required,no-scoped'''
    rsp = query_class('pimFabricRPPol', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if e == 'Object was not found':
        logger.info(f'''Fabric RP not configured in VRF {vrf_dn}.''')
    elif len(e) > 0:
        logger.warning(f'''API call for pimFabricRPPol in VRF {vrf_dn} failed with error: {e}''')
    else:
        rp_list = []
        for rp in rsp['imdata']:
            rp = rp['pimStaticRPEntryPol']['attributes']['rpIp']
            rp_list.append(rp)
        logger.info(f'''Configured fabric RP address(es) in VRF {vrf_dn}: {rp_list}''')
        logger.info(f'''IMPORTANT! If external devices point to the fabric RP, be sure to export the route for the fabric rp on the desired l3out.''')
        rp_dic['fabricRP'] = rp_list
    
    #get autoRP
    obj_query = f'''query-target-filter=wcard(pimAutoRPPol.dn,"{vrf_dn}")'''
    rsp = query_class('pimAutoRPPol', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if e == 'Object was not found':
        logger.info(f'''Auto RP not enabled in VRF {vrf_dn}.''')
    elif len(e) > 0:
        logger.warning(f'''API call for pimAutoRPPol in VRF {vrf_dn} failed with error: {e}''')
    else:
        logger.info(f'''Auto RP is enabled in VRF {vrf_dn}''')
        rp_dic['autoRP'] = ['isEnabled']
    
    #get bsr
    obj_query = f'''query-target-filter=wcard(pimBSRPPol.dn,"{vrf_dn}")'''
    rsp = query_class('pimBSRPPol', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if e == 'Object was not found':
        logger.info(f'''BSR RP not enabled in VRF {vrf_dn}.''')
    elif len(e) > 0:
        logger.warning(f'''API call for pimBSRPPol in VRF {vrf_dn} failed with error: {e}''')
    else:
        logger.info(f'''BSR RP is enabled in VRF {vrf_dn}''')
        rp_dic['bsrRP'] = ['isEnabled']
    
    return rp_dic

def get_ep_info(vrf_dn, ip, vrf_vnid, role): #{node : {ip : '', mac : '', bd : '', interface : }}
    ep_dic = {}
    obj_query = f'''query-target-filter=and(and(wcard(epmMacEp.dn,"{vrf_vnid}"))and(wcard(epmMacEp.flags,"local")))&rsp-subtree=children&rsp-subtree-filter=wcard(epmRsMacEpToIpEpAtt.tDn,"{ip}")&rsp-subtree-include=required'''
    rsp = query_class('epmMacEp', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if e == 'Object was not found':
        logger.warning(f'''FAILURE - Endpoint entry not found for {role} {ip}. Is unicast routing enabled on the BD? Is the pbr dataplane learn disable unchecked? Is a bd subnet configured that matches the ip? Is it actually sending traffic?''')
        logger.info('Exiting')
        sys.exit()
    elif len(e) > 0:
        logger.warning(f'''API call for epmMacEp in VRF {vrf_dn} failed with error: {e}''')
        logger.warning(f'''FAILURE - Could not get EP info for {ip}. Exiting...''')
        logger.info('Exiting')
        sys.exit()
    else:
        for ep in rsp['imdata']:
            ep_attr_dic = {}
            ep_mac = ep['epmMacEp']['attributes']['addr']
            ep_dn = ep['epmMacEp']['attributes']['dn']
            ep_bd_vnid = ''.join(re.findall(r"bd\-\[vxlan\-[0-9]+", ep_dn))
            ep_bd_vnid = ''.join(re.findall(r"[0-9]+$", ep_bd_vnid))
            ep_node  = ''.join(re.findall(r"node\-[0-9]+", ep_dn))
            ep_node = ''.join(re.findall(r"[0-9]+$", ep_node))
            ep_int = ep['epmMacEp']['attributes']['ifId']
            ep_attr_dic['ip'] = ip
            ep_attr_dic['mac'] = ep_mac
            ep_attr_dic['bd_vnid'] = ep_bd_vnid
            ep_attr_dic['interface'] = ep_int
            ep_dic[ep_node] = ep_attr_dic
    return ep_dic

def handle_bd(bd_vnid):
    obj_query = f'''query-target-filter=eq(fvBD.seg,"{bd_vnid}")'''
    rsp = query_class('fvBD', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    bd_dn = rsp['imdata'][0]['fvBD']['attributes']['dn']
    bd_name = rsp['imdata'][0]['fvBD']['attributes']['name']
    pim_setting = rsp['imdata'][0]['fvBD']['attributes']['mcastAllow']
    dpl_setting = rsp['imdata'][0]['fvBD']['attributes']['ipLearning']
    if pim_setting == 'no':
        logger.warning(f'''FAILURE - PIM is not enabled on BD {bd_dn}. This is required to participate in l3 mcast flows.''')
    else:
        logger.info(f'''PIM is correctly enabled on BD {bd_dn}.''')
    if dpl_setting == 'no':
        logger.warning(f'''FAILURE - Dataplane learning is disabled on BD {bd_dn}. This is not supported for l3mcast enabled BD's. It can cause mcast sources to not be learned breaking RPF checks.''')
    return bd_dn, bd_name

def parse_mroute_cli(cmd_out, node_dic):
    node_mroute_outputs_dic = {}
    
    for key1, value1 in cmd_out.items():
        nodeID = node_dic[key1]
        for key2, value2 in value1.items():
            group_pairs = re.findall(r'\S+,\s[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/32\)', value2)
            mgroup_list = value2.split("\n\n")
            group_list = []
            for g in group_pairs:
                for m in mgroup_list:
                    if g in m:
                        mroute_outputs_dic = {}
                        oil_list = []
                        group_match = m
                        src = g.lstrip('(').split(',')[0].split('/')[0]
                        group = g.rstrip('(').split(',')[1].split('/')[0].lstrip(" ")
                        in_int = re.findall(r"Incoming\sinterface:\s\S+", m)[0]
                        in_int = re.findall(r"\S+$", in_int)[0].rstrip(',')
                        oil = m.split("Outgoing interface")[1]
                        oil = re.findall(r".*uptime", oil)
                        for i in oil:
                            i = i.lstrip(' ').split(',')[0]
                            oil_list.append(i)
                        rpf_nei = re.findall(r"RPF nbr.*", m)[0]
                        rpf_nei = re.findall(r"\S+$", rpf_nei)[0]
                        
                        mroute_outputs_dic = {"group"   : group,
                                              "src"     : src,
                                              "in_int"  : in_int,
                                              "oil"     : oil_list,
                                              "rpf_nei" : rpf_nei }
                        if src == param_dic['src'] or src == '*':
                            group_list.append(mroute_outputs_dic)
        try:
            node_mroute_outputs_dic[nodeID] = group_list
        except:
            logger.info(f'''Group not found on node {nodeID}''')
    return node_mroute_outputs_dic

def parse_mfdm_cli(cmd_out, node_dic):
    node_mfdm_outputs_dic = {}
    
    for key1, value1 in cmd_out.items():
        nodeID = node_dic[key1]
        for key2, value2 in value1.items():
            group_pairs = re.findall(r'\S+,\s[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/32\)', value2)
            mgroup_list = value2.split("\n\n")
            group_list = []
            for g in group_pairs:
                for m in mgroup_list:
                    if g in m:
                        mfdm_outputs_dic = {}
                        oil_list = []
                        group_match = m
                        src = g.lstrip('(').split(',')[0].split('/')[0]
                        if src == param_dic['src']:
                            group = g.rstrip('(').split(',')[1].split('/')[0].lstrip(" ")
                            oil = m.split("\n")
                            oil = [x for x in oil if x != '']
                            index = 1000
                            for l in oil:
                                if 'Outgoing Interface List Index' in l:
                                    index = oil.index(l)
                                if oil.index(l) > index:
                                    i = l.lstrip(' ').split(',')[0]
                                    oil_list.append(i)
                                
                            mfdm_outputs_dic = {"group"   : group,
                                                  "src"     : src,
                                                  "oil"     : oil_list}
                            group_list.append(mfdm_outputs_dic)
                        else:
                            #skip mfdm mroutes that don't match the source
                            continue
            
        node_mfdm_outputs_dic[nodeID] = group_list
    
    return node_mfdm_outputs_dic

def get_stripe_winner(lo_dic):
    ptep_to_node = param_dic['nd2']
    node_to_ptep = param_dic['nd']
    rev_lo_dic = {}
    for k, v in lo_dic.items():
        for a in v:
            if a in rev_lo_dic.keys():
                rev_lo_dic[a].append(k)
            else:
                rev_lo_dic[a] = [k]
    
    stripe_winner_dic = {}
    command_list  = [f'''vsh -c "show ip pim internal stripe-winner {param_dic['group']} vrf {param_dic['tenant']}:{param_dic['vrf']}"''']
    node_ip_list = []
    for k, v in lo_dic.items():
        node = re.findall(r"[0-9]+$", k)[0]
        node_ip_list.append(param_dic['nd'][k])
    
    cmd_outputs = ssh_conn(self_ip, param_dic['uname'], password, node_ip_list, command_list)
    
    for key1, value1 in cmd_outputs.items():
        nodeID =  ptep_to_node[key1]
        for key2, value2 in value1.items():
            winner = re.findall(r"Winner:\s\S+", value2)[0].lstrip('Winner: ')
            stripe_winner_dic[nodeID] = [rev_lo_dic[winner], winner]
    
    bad_stripe_winner = False
    for k, v in stripe_winner_dic.items():
        if v[1] != winner:
            bad_stripe_winner = True
    
    if bad_stripe_winner is True:
        logger.warning(f'''FAILURE - Border leafs disagree on who the stripe winner is! This is not good!''')
        for k, v in stripe_winner_dic.items():
            print(f'''From the perspective of {k}, the stripe winner is node {v[0]} , loopback {v[1]}''')
        return "unknown"
    else:
        logger.info(f'''Stripe winner for group {param_dic['group']} is node {rev_lo_dic[winner]} , loopback {winner}''')
        return rev_lo_dic[winner]

def get_pim_neigh(vrf):
    neigh_dic = {}
    obj_query = f'''query-target-filter=and(and(wcard(pimAdjEp.dn,"{vrf}"))and(eq(pimAdjEp.operSt,"up")))'''
    rsp = query_class('pimAdjEp', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    for n in rsp['imdata']:
        dn = n['pimAdjEp']['attributes']['dn']
        node = re.findall(r"node\-[0-9]+", dn)[0]
        node = re.findall(r"[0-9]+$", node)[0]
        neigh = n['pimAdjEp']['attributes']['name']
        if node in neigh_dic.keys():
            neigh_dic[node].append(neigh)
        else:
            neigh_dic[node] = [neigh]
    
    return neigh_dic

def fhr_checks(node_list):
    node_ip_list = []
    for n in node_list:
        node_ip_list.append(param_dic['nd'][n])
    
    command_list  = [f'''vsh -c "show forwarding distribution multicast route vrf {param_dic['tenant']}:{param_dic['vrf']} group {param_dic['group']}/32"''']
    #Get mfdm entry
    cmd_outputs = ssh_conn(self_ip, param_dic['uname'], password, node_ip_list, command_list)
    #Parse mfdm output into dictionary in format of {<nodeid>:[{group1 dic},{group2 dic},etc]}
    lf_mfdm = parse_mfdm_cli(cmd_outputs, param_dic['nd2'])
    
    for n in node_list:
        foundTunnel = ''
        for m in lf_mfdm[n]:
            if len(m['oil']) > 0:
                for i in m['oil']:
                    if 'Tunnel' in i:
                        logger.info(f'''Tunnel outgoing interface {i} found for ({param_dic['src']}, {param_dic['group']}) on FHMR node-{n}.''')
                        foundTunnel = 'yes'
                if foundTunnel != 'yes':
                    logger.warning(f'''FAILURE - No outgoing tunnel interface found for ({param_dic['src']}, {param_dic['group']}) on FHMR node-{n}. If multicast traffic originates on this node, it will fail. The later dataplane check in this tool can help confirm.''')
            else:
                logger.warning(f'''FAILURE - No outgoing tunnel interface found for ({param_dic['src']}, {param_dic['group']}) on FHMR node-{n}. If multicast traffic originates on this node, it will fail. The later dataplane check in this tool can help confirm.''')

def generic_leaf_checks(lo_dic, pim_neigh_dic, stripe_winner_node):
    #Get node list containing all nodes that previously had mcast role assigned.
    node_list = []
    if msource == 'transit':
        node_list = oif_nodes + inif_nodes
        all_nodes = node_list
    elif msource == 'internal' and mdest == 'internal':
        s_nodes = [key for key,val in mcast_role.items() if any('SL' in s for s in val)]
        r_nodes = [key for key,val in mcast_role.items() if any('RL' in s for s in val)]
        all_nodes = s_nodes + r_nodes
        all_nodes = [*set(all_nodes)]
        node_list = all_nodes
    else:
        for k, v in mcast_role.items():
            if len(v) > 0:
                node_list.append(k)
        
        #Build role specific lists. Code would be more simple if we just interated through all nodes in node_list BUT
        #combining them is faster from the perspective of multithreading ssh sessions
        s_nodes = [key for key,val in mcast_role.items() if any('SL' in s for s in val)]
        b_nodes = [key for key,val in mcast_role.items() if any('BL' in s for s in val)]
        r_nodes = [key for key,val in mcast_role.items() if any('RL' in s for s in val)]
        all_nodes = s_nodes + b_nodes + r_nodes
        all_nodes = [*set(all_nodes)]
    
    #Get PTEPS of nodes in node_list for checks requiring SSH
    node_ip_list = []
    for n in node_list:
        node_ip_list.append(param_dic['nd'][n])
    
    ####First hop router checks
    if msource == 'internal':
        logger.info(f'Performing First Hop Multicast Router (FHMR) checks on FHMR nodes {s_nodes}')
        fhr_checks(s_nodes)
    
    ####
    ####Check check that every node has an RP installed for the group
    ####
    logger.info(f'''Checking if operational RP exists for group {param_dic['group']} on each node...''')
    command_list  = [f'''show ip pim rp {param_dic['group']} vrf {param_dic['tenant']}:{param_dic['vrf']}''']
    #Get mroute entry
    cmd_outputs = ssh_conn(self_ip, param_dic['uname'], password, node_ip_list, command_list)
    #Parse mroute output into dictionary in format of {<nodeid>:[{group1 dic},{group2 dic},etc]}
    pim_mroute_rp = parse_pim_rp_cli(cmd_outputs, param_dic['nd2'])
    missing_rp = 'no'
    
    for k, v in pim_mroute_rp.items():
        if len(v) == 0:
            logger.warning(f'''FAILURE - Operational RP was not found on node-{k} for group {param_dic['group']}. Verification was done 
            with "show ip pim rp <group> vrf <name>". Does the node have a route to the RP? Are there route-maps that don't allow
            this RP to be used with the specified src/group pair? The flow will fail without an RP.''')
            missing_rp = 'yes'
    
    if missing_rp == 'no':
        logger.info(f'''Operational RP was found on each node for group {param_dic['group']}.''')
    
    ####
    ####Check mroute outputs and parse into dictionaries. Make sure routes all look good
    ####
    command_list  = [f'''show ip mroute {param_dic['group']} vrf {param_dic['tenant']}:{param_dic['vrf']}''']
    #Get mroute entry
    cmd_outputs = ssh_conn(self_ip, param_dic['uname'], password, node_ip_list, command_list)
    #Parse mroute output into dictionary in format of {<nodeid>:[{group1 dic},{group2 dic},etc]}
    lf_mroute = parse_mroute_cli(cmd_outputs, param_dic['nd2'])
    stripe_winner_hit = ''
    sg_on_winner = ''
    found_route = ''
    print('Role Index - SL is Source Leaf, BL is Border Leaf, RL is Receiver Leaf')
    for k, v in lf_mroute.items():
        if k == stripe_winner_node:
            stripe_winner_hit = True
        print('\n')
        print(f'''node-{k} mroute checks: Role - {mcast_role[k]}''')
        if len(lf_mroute[k]) == 0:
            print(f'''      Mroute not found on node-{k}''')
            if k == stripe_winner_node:
                print("      WARNING: FAILURE - This node is the stripe winner and the mroute was not found! This flow will fail!")
        else:
            found_route = 'yes'
            for mroute in v:
                if (mroute['src'] == param_dic['src']) and k == stripe_winner_node:
                    sg_on_winner = True
                    print(f'''    INFO: Found S,G route for source {param_dic['src']} on stripe winner node - {stripe_winner_node}''')
                
                print(f'''    Source: {mroute['src']}    Group: {mroute['group']}    :''')
                if len(mroute['in_int']) == 0:
                    logger.warning('FAILURE - No incoming interfaces found!')
                else:
                    print(f'''      Incoming Interface: {mroute['in_int']}''')
                
                if len(mroute['rpf_nei']) == 0:
                    logger.warning('FAILURE - No rpf neighbor found for tree!')
                else:
                    print(f'''      RPF Neighbor: {mroute['rpf_nei']}''')
                    if mroute['rpf_nei'] in pim_neigh_dic[k]:
                        print(f'''        INFO: External PIM Neighbor found matching RPF neigh {mroute['rpf_nei']}''')
                    else:
                        try:
                            rpf_node = param_dic['nd2'][mroute['rpf_nei']]
                            rpf_lb = lo_dic[rpf_node]
                            for addr in rpf_lb:
                                if addr in pim_neigh_dic[k]:
                                    print(f'''        INFO: Fabric internal PIM neighbor node-{rpf_node}/{addr} found matching RPF neigh {mroute['rpf_nei']}''')
                                else:
                                    if 'pervasive' in mroute['rpf_nei']:
                                        print('''        INFO: RPF was fabric owned BD subnet proxy route (pervasive). Expected if source is internal.''')
                                    else:
                                        logger.warning(f'''FAILURE - No PIM neighbor found for RPF neighbor {mroute['rpf_nei']}!''')
                        except:
                            if 'pervasive' in mroute['rpf_nei']:
                                print('''        INFO: RPF was fabric owned BD subnet proxy route (pervasive). Expected if source is internal.''')
                            else:
                                logger.warning(f'''FAILURE - No PIM neighbor found for RPF neighbor {mroute['rpf_nei']}!''')
                
                if len(mroute['oil']) == 0 and 'SL' not in mcast_role[k]:
                    logger.warning('FAILURE - Mroute exists but no outgoing interfaces found! Is this group still active on this node? Datapath checking may be useful.')
                elif 'SL' in mcast_role[k] and ('BL' not in mcast_role[k] or len(mroute['oil']) == 0):
                    print(f'''      Outgoing Interface(s): ''')
                    print('''        INFO: Skipping OIF check since OIFs were previously checked for FHMRs. For an FHMR the OIF should include the Vrf GIPO Tunnel.''')
                    print(f'''        INFO: Node-{k} is an FHMR so only the VRF GIPO Tunnel has to be installed as an OIF. Continuing...''')
                else:
                    print(f'''      Outgoing Interface(s): {mroute['oil']}''')
    
    print('\n')
    if sg_on_winner is not True and stripe_winner_hit is True:
        logger.warning(f'''FAILURE - No S,G tree matching {param_dic['src']},{param_dic['group']} was found on stripe winner node - {stripe_winner_node}! If source is external this is incorrect. Is the source correct? Is the multicast flow being received by ACI?''')
    print('\n')
    if found_route != 'yes':
        logger.warning(f'''FAILURE - {param_dic['group']} not found on any nodes in list!''')
    
    ####
    ####Check for /32 hal route on all nodes in the flow.
    ####
    else:
        logger.info('Validating that multicast group is installed as /32 in hardware on both internal and border leafs.')
        check_hal_group(all_nodes, stripe_winner_node)

def check_hal_ep(node_list, stripe_winner_node, extif_dic={}):
    ep_bl_list = []
    node_ip_list = []
    for n in node_list:
        node_ip_list.append(param_dic['nd'][n])
    
    command_list  = [f'''vsh_lc -c "show platform internal hal l3 routes vrf {param_dic['tenant']}:{param_dic['vrf']}" | egrep "{param_dic['src']}/\s+32"''']
    #Get hal entry
    cmd_outputs = ssh_conn(self_ip, param_dic['uname'], password, node_ip_list, command_list)
    for k1, v1 in cmd_outputs.items():
        nodeID =  param_dic['nd2'][k1]
        for k2, v2 in v1.items():
            if len(v2) > 0:
                ep_bl_list.append(nodeID)
    
    if len(ep_bl_list) > 0:
        logger.info(f'''Src {param_dic['src']} is installed in hardware on nodes {ep_bl_list}''')
        if msource != "internal": #Don't care about stripe winner so much if source is internal
            if stripe_winner_node not in ep_bl_list:
                logger.warning(f'''FAILURE - Src {param_dic['src']} is NOT installed in hardware on stripe-winner node {stripe_winner_node}. Is dataplane active? Is it making it to ACI? Does the BL have a route to the source? If the RP is external, is it getting a join from ACI?''')
            else:
                logger.info(f'''Src {param_dic['src']} is correctly installed in hardware on stripe-winner node {stripe_winner_node}.''')
        if msource == 'internal': #Make sure that /32 is installed on node that has external oif
            sg_route = f'''({param_dic['src']}, {param_dic['group']})'''
            if sg_route in extif_dic.keys():
                for n in extif_dic[sg_route]:
                    for k, v in n.items():
                        if k in ep_bl_list:
                            logger.info(f'''Src {param_dic['src']} is correctly installed in hardware on node {k} which has external OIFs {v}.''')
                        else:
                            logger.warning(f'''FAILURE - Src {param_dic['src']} is NOT installed in hardware on stripe-winner node node {k} which has external OIFs {v}. This will break this flow due to RPF failures if it egresses the fabric on this node. Time to debug endpoint learning.''')
        
    else:
        logger.warning(f'''FAILURE - Src {param_dic['src']} is NOT installed in hardware on any Border Leaf Nodes. Is dataplane active? Is it making it to ACI? Does the BL have a route to the source?''')

def check_hal_group(node_list, stripe_winner_node, extif_dic={}):
    ep_bl_list = []
    node_ip_list = []
    for n in node_list:
        node_ip_list.append(param_dic['nd'][n])
    
    command_list  = [f'''vsh_lc -c "show platform internal hal l3 routes vrf {param_dic['tenant']}:{param_dic['vrf']}" | egrep "{param_dic['group']}/\s+32"''']
    #Get hal entry
    cmd_outputs = ssh_conn(self_ip, param_dic['uname'], password, node_ip_list, command_list)
    for k1, v1 in cmd_outputs.items():
        nodeID =  param_dic['nd2'][k1]
        for k2, v2 in v1.items():
            if len(v2) > 0:
                ep_bl_list.append(nodeID)
    
    if len(ep_bl_list) > 0:
        logger.info(f'''Group {param_dic['group']} is installed in hardware on nodes {ep_bl_list}''')
        if msource != "internal": #Don't care about stripe winner so much if source is internal
            if stripe_winner_node not in ep_bl_list:
                logger.warning(f'''FAILURE - Group{param_dic['group']} is NOT installed in hardware on stripe-winner node {stripe_winner_node}. Is dataplane active? Is it making it to ACI? Does the BL have a route to the source? If the RP is external, is it getting a join from ACI?''')
            else:
                logger.info(f'''Group {param_dic['group']} is correctly installed in hardware on stripe-winner node {stripe_winner_node}.''')
        if msource == 'internal': #Make sure that /32 is installed on node that has external oif
            sg_route = f'''({param_dic['group']}, {param_dic['group']})'''
            if sg_route in extif_dic.keys():
                for n in extif_dic[sg_route]:
                    for k, v in n.items():
                        if k in ep_bl_list:
                            logger.info(f'''Group {param_dic['group']} is correctly installed in hardware on node {k} which has external OIFs {v}.''')
                        else:
                            logger.warning(f'''FAILURE - Group {param_dic['group']} is NOT installed in hardware on BL node {k} which has external OIFs {v}. This will break this flow! For an internal source, the spines should immediately install the mroute on the BL's via NGMVPN (coop) once a source starts sending traffic!''')
        
    else:
        logger.warning(f'''FAILURE - Group{param_dic['group']} is NOT installed in hardware on any nodes. Is the control plane built? Is the receiver sending joins? Is the source sending traffic? Does the RP have both registers from the source and joins for the group when looking at the mroute table?''')

def check_pim_vrf():
    vrf_dn = f'''uni/tn-{param_dic['tenant']}/ctx-{param_dic['vrf']}'''
    vrf_vnid = get_attribute('seg', obj_dn=vrf_dn)
    pimctx_dn = f'''{vrf_dn}/pimctxp'''
    rsp = query_dn(pimctx_dn)
    e = handle_api_rsp(rsp)
    if len(e) > 0:
        logger.warning(f'''FAILURE - Vrf {vrf_dn} does not exist or PIM is not enabled. Error: {e}''')
        logger.info('Exiting')
        sys.exit()
    else:
        logger.info(f'''Pim is correctly enabled on Vrf {vrf_dn}.''')
    
    vrf_gipo = rsp['imdata'][0]['pimCtxP']['attributes']['vrfGipo']
    logger.info(f'''VRF GIPO used for L3 Multicast Flooding - {vrf_gipo}''')
    
    return vrf_dn, vrf_gipo, vrf_vnid

def check_pim_l3outs(vrf_dn):
    #Get all l3outs in the supplied vrf
    obj_query = f'''query-target-filter=wcard(fvRtEctx.dn,"tn-{param_dic['tenant']}/ctx-{param_dic['vrf']}")'''
    rsp = query_class('fvRtEctx', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if len(e) > 0:
        logger.warning(f'''FAILURE - Vrf {vrf_dn} does not have any l3outs configured. Error: {e}''')
        logger.info('Exiting')
        sys.exit()
    
    vrf_l3out_list = []
    for l in rsp['imdata']:
        vrf_l3out_list.append(l['fvRtEctx']['attributes']['tDn'])
    
    #Get all pim-enabled l3outs
    rsp = query_class('pimExtP')
    pim_l3out_list = []
    for l in rsp['imdata']:
        l = l['pimExtP']['attributes']['dn'].rstrip('pimextp')
        l = l.rstrip('/')
        pim_l3out_list.append(l)
    
    #Build list of pim enabled l3outs in the supplied vrf
    l3out_list = []
    for l in vrf_l3out_list:
        if l in pim_l3out_list:
            l3out_list.append(l)
    
    if len(l3out_list) == 0:
        logger.warning(f'''FAILURE - Vrf {vrf_dn} does not have any Pim-enabled l3outs configured. L3 mcast requires a pim-enabled l3out.''')
        logger.info('Exiting')
        sys.exit()
    
    logger.info(f'''The following PIM-enabled l3outs were found in tn-{param_dic['tenant']}/ctx-{param_dic['vrf']}:''')
    print(l3out_list)

def check_pim_loopbacks(vrf_dn):
    obj_query = f'''query-target-filter=and(and(wcard(pimIf.dn,"{param_dic['tenant']}:{param_dic['vrf']}"))and(wcard(pimIf.id,"lo")))'''
    rsp = query_class('pimIf', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if len(e) > 0:
        logger.warning(f'''FAILURE - No PIM-enabled loopbacks were found on leafs in VRF {vrf_dn}. Error: {e}''')
        print('''Please check the following:
                 Is "Use Router ID as Loopback" configured? If not, is a different loopback configured on each BL?
                 Are any faults raised against the l3out?''')
        logger.info('Exiting')
        sys.exit()
    else:
        logger.info(f'''Pim-enabled loopbacks were found on BL's for Vrf {vrf_dn}.''')
    
    lo_dic = {}
    for r in rsp['imdata']:
        n = r['pimIf']['attributes']['dn']
        n = ''.join(re.findall(r"^.*pod\-[0-9]\/node\-[0-9]+", n))
        n = ''.join(re.findall(r"[0-9]+$", n))
        a = r['pimIf']['attributes']['ipAddr']
        a = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', a)[0]
        if n in lo_dic.keys():
            lo_dic[n].append(a)
        else:
            lo_dic[n] = [a]
    
    logger.info(f'The following pim-enabled loopbacks were found in vrf {vrf_dn}:')
    for k, v in lo_dic.items():
        print(f'''node-{k}            {v}''')
    
    return lo_dic

def check_l3igmp(rcvr_leafs):
    igmp_dic = {}
    obj_query = f'''query-target-filter=and(and(wcard(igmpOif.dn,"{param_dic['tenant']}:{param_dic['vrf']}"))and(wcard(igmpOif.dn,"{param_dic['group']}")))'''
    rsp = query_class('igmpOif', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if len(e) > 0:
        logger.warning(f'''FAILURE - No IGMP groups were found in the fabric for group {param_dic['group']} in vrf {param_dic['tenant']}:{param_dic['vrf']} . Error: {e}''')
        print('''Please validate if the receiver is actually sending IGMP joins for this group to ACI.''')
        logger.info('Exiting')
        sys.exit()
    else:
        for r in rsp['imdata']:
            n = r['igmpOif']['attributes']['dn']
            n = ''.join(re.findall(r"^.*pod\-[0-9]\/node\-[0-9]+", n))
            n = ''.join(re.findall(r"[0-9]+$", n))
            if n in rcvr_leafs:
                o = r['igmpOif']['attributes']['oif']
                if n in igmp_dic.keys():
                    igmp_dic[n].append(o)
                else:
                    igmp_dic[n] = [o]
        
        if len(igmp_dic) > 0:
            for k, v in igmp_dic.items():
                logger.info(f'''On receiver leaf {k}, the following IGMP outgoing interfaces were found for {param_dic['group']}:''')
                print(v)
        else:
            logger.warning(f'''FAILURE - No IGMP outgoing interfaces were found for {param_dic['group']} on receiver leafs {list(rcvr_leafs)}. Continuing but note that this flow will fail until this is corrected''')

def check_igmpsnoop(rcvr_leafs, bd_vnid):
    igmpsnoop_dic = {}
    obj_query = f'''query-target-filter=and(and(wcard(igmpsnoopOIFRec.dn,"vxlan-{bd_vnid}"))and(wcard(igmpsnoopOIFRec.dn,"{param_dic['group']}")))'''
    rsp = query_class('igmpsnoopOIFRec', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if len(e) > 0:
        logger.warning(f'''FAILURE - No IGMP snooping entries were found in the fabric for group {param_dic['group']} in Receiver BD {bd_vnid}. Error: {e}''')
        print('''If igmp-snooing is enabled, please validate if the receiver is actually sending IGMP joins for this group to ACI.''')
    else:
        for r in rsp['imdata']:
            n = r['igmpsnoopOIFRec']['attributes']['dn']
            n = ''.join(re.findall(r"^.*pod\-[0-9]\/node\-[0-9]+", n))
            n = ''.join(re.findall(r"[0-9]+$", n))
            if n in rcvr_leafs:
                o = r['igmpsnoopOIFRec']['attributes']['id']
                if n in igmpsnoop_dic.keys():
                    igmpsnoop_dic[n].append(o)
                else:
                    igmpsnoop_dic[n] = [o]
        
        if len(igmpsnoop_dic) > 0:
            for k, v in igmpsnoop_dic.items():
                logger.info(f'''On receiver leaf {k}, IGMP snooping outgoing interfaces were found for {param_dic['group']} in receiver BD vnid {bd_vnid}:''')
                print(v)
        else:
            logger.warning(f'''FAILURE - No IGMP snooping outgoing interfaces were found for {param_dic['group']} on receiver leafs {list(rcvr_leafs)} in BD vnid {bd_vnid}. Continuing but note that if igmp-snooping is enabled on this BD, this flow will fail until this is corrected''')

def get_fabricForwarder(lo_dic):
    ptep_to_node = param_dic['nd2']
    node_to_ptep = param_dic['nd']
    ff_winner_dic = {}
    s_g = f'''({param_dic['src']}, {param_dic['group']}/32)'''
    star_g = f'''(*, {param_dic['group']}/32)'''
    command_list  = [f'''show ip pim route {param_dic['group']} vrf {param_dic['tenant']}:{param_dic['vrf']}''']
    node_ip_list = []
    for k, v in lo_dic.items():
        node = re.findall(r"[0-9]+$", k)[0]
        node_ip_list.append(param_dic['nd'][node])
    
    cmd_outputs = ssh_conn(self_ip, param_dic['uname'], password, node_ip_list, command_list)
    
    for key1, value1 in cmd_outputs.items():
        nodeID =  ptep_to_node[key1]
        for cmd, mroute in value1.items():
            mroute_list = mroute.split("\n\n")
            for m in mroute_list:
                if param_dic['group'] in m and 'fabricFwder' in m:
                    group_pair = re.findall(r'\S+,\s[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/32\)', m)[0]
                    if group_pair == s_g or group_pair == star_g:
                        if nodeID in ff_winner_dic.keys():
                            ff_winner_dic[nodeID].append(group_pair)
                        else:
                            ff_winner_dic[nodeID] = [group_pair]
    
    star_g_ff_count = 0
    star_g_ff_nodes = []
    s_g_ff_count = 0
    s_g_ff_nodes = []
    for k, v in ff_winner_dic.items():
        if star_g in v:
            logger.info(f'''Fabric-forwarder for {star_g} is node-{k}''')
            star_g_ff_count += 1
            star_g_ff_nodes.append(k)
        
        if s_g in v:
            logger.info(f'''Fabric-forwarder for {s_g} is node-{k}''')
            s_g_ff_count += 1
            s_g_ff_nodes.append(k)
        
    if star_g_ff_count == 0:
        logger.warning(f'''FAILURE - Fabric-forwarder was not found for {star_g}. This will prevent the BL's from flooding external multicast into the overlay!''')
    elif star_g_ff_count >= 2:
        logger.warning(f'''FAILURE - Multiple fabric-forwarders (nodes {star_g_ff_nodes}) were found for {star_g}. This could result in the BL's flooding duplicated copies of external multicast into the overlay!''')
    if s_g_ff_count == 0:
        logger.warning(f'''FAILURE - Fabric-forwarder was not found for {s_g}. This will prevent the BL's from flooding external multicast into the overlay!''')
    elif s_g_ff_count >= 2:
        logger.warning(f'''FAILURE - Multiple fabric-forwarders (nodes {s_g_ff_nodes}) were found for {s_g}. This could result in the BL's flooding duplicated copies of external multicast into the overlay!''')

def pim_ext_ifs(vrf_dn):
    groupoif_dic = {}
    obj_query = f'''query-target-filter=and(and(wcard(pimOif.dn,"{param_dic['tenant']}:{param_dic['vrf']}"))and(wcard(pimOif.dn,"{param_dic['group']}")))'''
    rsp = query_class('pimOif', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if len(e) > 0:
        logger.warning(f'''FAILURE - No external PIM OIFs were were found on leafs in VRF {vrf_dn}. Error: {e} . If the receiver is external, the flow will fail.''')
        print('''Please check the following:
                 If the RP is EXTERNAL, has it received a join from receiver? It won't send a join back towards the source until this is done.
                 If the RP is EXTERNAL, does it have a learn for the mroute source in its mroute table?
                 If the RP is EXTERNAL, does the route back to the source point to ACI?
                 If the RP is EXTERNAL, ensure PIM is enabled on the interface that provides RP service.
                 If the RP is INTERNAL, do external devices have a route to the fabric RP?
                 If the RP is INTERNAL and external devices don't have a route to the RP, is an export route-control subnet configured to advertise the RP?''')
    else:
        #logger.info(f'''External PIM outgoing interfaces found!''')
        group_list = [f'''(0.0.0.0, {param_dic['group']})''', f'''({param_dic['src']}, {param_dic['group']})''']
        for group in group_list:
            oif_dic = {}
            for r in rsp['imdata']:
                dn = r['pimOif']['attributes']['dn']
                n = ''.join(re.findall(r"^.*pod\-[0-9]\/node\-[0-9]+", dn))
                n = ''.join(re.findall(r"[0-9]+$", n))
                oif = r['pimOif']['attributes']['oIf']
                pair = dn.split("db-route/")[1].split("/oif")[0]
                src = re.findall(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", pair.split("]-grp-[")[0])[0]
                dst = re.findall(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", pair.split("]-grp-[")[1])[0]
                pair = f'''({src}, {dst})'''
                
                if pair == group:
                    if n in oif_dic.keys():
                        oif_dic[n].append(oif)
                    else:
                        oif_dic[n] = [oif]
            
            if pair == group:
                if pair in groupoif_dic.keys():
                    groupoif_dic[pair].append(oif_dic)
                else:
                    groupoif_dic[pair] = [oif_dic]
            
        logger.info(f'The following external OUTGOING interfaces interfaces were found in vrf {vrf_dn}:')
        for k, v in groupoif_dic.items():
            if len(v) > 0:
                print(f'''Mroute: {k}''')
                for oif in v:
                    print(f'          {oif}')
    
    return groupoif_dic

def pim_in_ifs(vrf_dn):
    groupiif_dic = {}
    obj_query = f'''query-target-filter=and(and(wcard(pimRoute.dn,"{param_dic['tenant']}:{param_dic['vrf']}"))and(wcard(pimRoute.dn,"{param_dic['group']}")))'''
    rsp = query_class('pimRoute', obj_query=obj_query)
    e = handle_api_rsp(rsp)
    if len(e) > 0:
        logger.warning(f'''FAILURE - No mroutes were found for {param_dic['group']} on any border leafs. Error - {e}''')
        logger.info('Exiting')
        sys.exit()
    
    pimRouteList = []
    for i in rsp['imdata']:
        if 'tunnel' not in i['pimRoute']['attributes']['iif']:
            pimRouteList.append(i['pimRoute']['attributes'])
    
    if len(pimRouteList) == 0:
        logger.warning(f'''FAILURE - No external incoming interfaces were were found on border leafs in VRF {vrf_dn}. Error: {e} . If the source is external, the flow will fail.''')
        print('''Please check the following:
                 If the RP is EXTERNAL, has it received a join from receiver? It won't send a join back towards the source until this is done.
                 If the RP is EXTERNAL, does it have an mroute for the source,group pair in its mroute table?
                 If the RP is EXTERNAL, does the route back to the source point to an external PIM neighbor?
                 If the RP is INTERNAL, do external devices have a route to the fabric RP?
                 If the RP is INTERNAL and external devices don't have a route to the RP, is an export route-control subnet configured to advertise the RP?''')
    else:
        #logger.info(f'''External PIM incoming interfaces found!''')
        group_list = [f'''(0.0.0.0, {param_dic['group']})''', f'''({param_dic['src']}, {param_dic['group']})''']
        for group in group_list:
            iif_dic = {}
            for r in pimRouteList:
                dn = r['dn']
                n = ''.join(re.findall(r"^.*pod\-[0-9]\/node\-[0-9]+", dn))
                n = ''.join(re.findall(r"[0-9]+$", n))
                iif = r['iif']
                pair = dn.split("db-route/")[1]
                src = re.findall(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", pair.split("]-grp-[")[0])[0]
                dst = re.findall(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", pair.split("]-grp-[")[1])[0]
                pair = f'''({src}, {dst})'''
                #print(pair)
                if pair == group:
                    #print(pair)
                    if n in iif_dic.keys():
                        iif_dic[n].append(iif)
                    else:
                        iif_dic[n] = [iif]
            
            if len(iif_dic) > 0:
                if group in groupiif_dic.keys():
                    groupiif_dic[group].append(iif_dic)
                else:
                    groupiif_dic[group] = [iif_dic]
            
        logger.info(f'The following external INCOMING interfaces were found in vrf {vrf_dn}:')
        for k, v in groupiif_dic.items():
            if len(v) > 0:
                print(f'''Mroute: {k}''')
                for iif in v:
                    print(f'          {iif}')
    
    return groupiif_dic

def parse_pim_rp_cli(cmd_out, node_dic):
    node_rp_outputs_dic = {}
    
    for key1, value1 in cmd_out.items():
        nodeID = node_dic[key1]
        for key2, value2 in value1.items():
            oper_rp = re.findall(r'RP.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*uptime', value2)[0]
            oper_rp = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', oper_rp)[0]
            node_rp_outputs_dic[nodeID] = oper_rp
    
    return node_rp_outputs_dic
