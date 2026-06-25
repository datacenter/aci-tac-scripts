#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SSD Lifetime Validation Script - Python 2.7 and 3.x compatible

Context
-------
Starting in ACI version 6.1(5e) and later, smartctl Attribute 202 was incorrectly
added to SSD fault monitoring. As a result, switches with Micron SSDs raise SSD
lifetime faults (F3074 / F3073) even when actual SSD usage has NOT crossed 80%
when evaluated from the P/E, GBB, and RRE threshold perspective.

This script:
  1. Collects all switches and their eqptFlash (SSD) data from the APIC.
  2. Performs a P/E-based lifetime calculation:
         lifetime_pct = (peCycles / pe_max) * 100
  3. Checks whether minorAlarm (maps to F3074) or majorAlarm (maps to F3073)
     are raised on each switch.
  4. Flags switches that are hitting defect CSCwt38698:
         Micron SSD + alarm raised + P/E lifetime < 80 %
     CSCwt38698 public URL: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwt38698
  5. Exports all findings to a CSV file for customer review.

Author: joelebla@cisco.com
Version: 1.2
Date: June 25, 2026
"""

from __future__ import print_function, division, absolute_import, unicode_literals

import os
import re
import sys
import csv
import time
import logging
import argparse
import subprocess
import traceback
from datetime import datetime
from getpass import getpass
from logging.handlers import RotatingFileHandler

# ---------------------------------------------------------------------------
# Python 2 / 3 compatibility
# ---------------------------------------------------------------------------
PY2 = sys.version_info[0] == 2
if PY2:
    string_types = basestring  # noqa: F821
    def iteritems(d): return d.iteritems()  # noqa: E704
    range = xrange  # noqa: F821
else:
    string_types = str
    def iteritems(d): return d.items()

try:
    import json
except ImportError:
    import simplejson as json  # type: ignore

if PY2:
    reload(sys)                        # noqa: F821
    sys.setdefaultencoding('utf-8')   # noqa: F821

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging():
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except Exception:
            import tempfile
            log_dir = tempfile.gettempdir()

    log_file = os.path.join(
        log_dir,
        'ssd-lifetime-validation-{0}.log'.format(datetime.now().strftime('%Y-%m-%d'))
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    try:
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        root.addHandler(fh)
    except Exception as e:
        print('Warning: could not create log file: {0}'.format(e))

    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    ch.setLevel(logging.CRITICAL)
    root.addHandler(ch)

    return logging.getLogger(__name__)

logger = setup_logging()

# ---------------------------------------------------------------------------
# SSD threshold definitions  (P/E attribute used for lifetime calculation)
# ---------------------------------------------------------------------------
SSD_THRESHOLDS = [
    {'vendor': 'Micron', 'model': 'M550-64G',   'pattern': 'Micron_M550_MTFDDAT064',      'attributes': [
        {'name': 'GBB', 'id': 5,   'max_value': 15,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 15000, 'value_type': 'RAW_VALUE'},
        {'name': 'TBW', 'id': 246, 'max_value': 108,   'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M550-256G',  'pattern': 'Micron_M550_MTFDDAT256',      'attributes': [
        {'name': 'GBB', 'id': 5,   'max_value': 60,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 15000, 'value_type': 'RAW_VALUE'},
        {'name': 'TBW', 'id': 246, 'max_value': 216,   'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M600-64G',   'pattern': 'Micron_M600_MTFDDAT064',      'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 5,     'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 5000,  'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M600-64G-MBF', 'pattern': 'Micron_M600_MTFDDAT064MBF', 'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 5,     'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 5000,  'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M600-256G',  'pattern': 'Micron_M600_MTFDDAT256',      'attributes': [
        {'name': 'GBB', 'id': 5,   'max_value': 8,     'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 24000, 'value_type': 'RAW_VALUE'},
        {'name': 'TBW', 'id': 246, 'max_value': 600,   'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M1100-256G', 'pattern': 'Micron_1100_MTFDDAV256TBN',   'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 15,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 6000,  'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M500IT-64G', 'pattern': 'Micron_M500IT_MTFDDAT064SBD', 'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 15,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 35000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M500IT-256G', 'pattern': 'Micron_M500IT_MTFDDAT256MBD', 'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 15,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 35000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M5100-240G', 'pattern': 'Micron_5100_MTFDDAV240TCB',   'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 20,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 10000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M5300-240G', 'pattern': 'Micron_5300_MTFDDAV240TDS',   'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 20,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 10000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Micron', 'model': 'M5400-240G', 'pattern': 'Micron_5400_MTFDDAV240TGA',   'attributes': [
        {'name': 'RRE', 'id': 1,   'max_value': 1000,  'value_type': 'RAW_VALUE'},
        {'name': 'GBB', 'id': 5,   'max_value': 15,    'value_type': 'RAW_VALUE'},
        {'name': 'P/E', 'id': 173, 'max_value': 8500,  'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Hynix',         'model': 'HFS064G3AMNC-3310A DX', 'pattern': 'HFS064G3AMNC-3310A', 'attributes': [
        {'name': 'WLC', 'id': 177, 'max_value': 100, 'value_type': 'VALUE', 'calculation': 'decrement'},
    ]},
    {'vendor': 'Smart Modular', 'model': 'SHMST064G3FECTLP51',    'pattern': 'SHMST064G3FECTLP51', 'attributes': [
        {'name': 'P/E', 'id': 175, 'max_value': 30000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Smart Modular', 'model': 'SHMST064G3FDCTL121',    'pattern': 'SHMST064G3FDCTL121', 'attributes': [
        {'name': 'P/E', 'id': 175, 'max_value': 3600,  'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Smart Modular', 'model': 'SR9MST6D064BQF71C',     'pattern': 'SR9MST6D064BQF71C',  'attributes': [
        {'name': 'P/E', 'id': 175, 'max_value': 10000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Smart Modular', 'model': 'SR9MST6D240GQF71C',     'pattern': 'SR9MST6D240GQF71C',  'attributes': [
        {'name': 'P/E', 'id': 175, 'max_value': 10000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Smart Modular', 'model': 'SRM28128AF1M2BC2C',     'pattern': 'SRM28128AF1M2BC2C',  'attributes': [
        {'name': 'P/E', 'id': 175, 'max_value': 10000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Smart Modular', 'model': 'SMART128',              'pattern': 'SRM2SH6Q128AQT51C', 'attributes': [
        {'name': 'P/E', 'id': 175, 'max_value': 3600,  'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Smart Modular', 'model': 'SMART60',               'pattern': 'SA9MST6060GKP21C',  'attributes': [
        {'name': 'P/E', 'id': 175, 'max_value': 30000, 'value_type': 'RAW_VALUE'},
    ]},
    {'vendor': 'Intel', 'model': 'SSDSCKJB150G7',    'pattern': 'SSDSCKJB150G7',    'attributes': [
        {'name': 'WLC', 'id': 233, 'max_value': 100, 'value_type': 'VALUE', 'calculation': 'decrement'},
    ]},
    {'vendor': 'Intel', 'model': 'SSDSCKKB240G8K',   'pattern': 'SSDSCKKB240G8K',   'attributes': [
        {'name': 'WLC', 'id': 233, 'max_value': 100, 'value_type': 'VALUE', 'calculation': 'decrement'},
    ]},
]

# ---------------------------------------------------------------------------
# Defect reference
# ---------------------------------------------------------------------------
CSCWT38698_URL = 'https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwt38698'

# ---------------------------------------------------------------------------
# APIC API helper
# ---------------------------------------------------------------------------
class ApiRequest(object):
    """Thin wrapper around icurl for APIC REST API calls."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.response = None

    def __enter__(self):
        logger.debug('ApiRequest: GET {0}'.format(self.endpoint))
        cmd = "icurl -gs '{0}'".format(self.endpoint)
        try:
            raw = subprocess.check_output(cmd, shell=True)
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', 'replace')
            self.response = raw
        except subprocess.CalledProcessError as e:
            logger.error('icurl returned non-zero exit code: {0}'.format(e.returncode))
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False  # do not suppress exceptions

    def json(self):
        if not self.response:
            return None
        try:
            return json.loads(self.response)
        except ValueError as e:
            logger.error('JSON parse error: {0}'.format(e))
            logger.debug('Response snippet: {0}'.format(self.response[:300]))
            return None

# ---------------------------------------------------------------------------
# Fabric helpers
# ---------------------------------------------------------------------------
def get_fabric_name():
    try:
        cmd = ("icurl -gs 'http://127.0.0.1:7777/api/class/topSystem.json"
               "?query-target-filter=eq(topSystem.dn,\"topology/pod-1/node-1/sys\")""'")
        output = subprocess.check_output(cmd, shell=True)
        if isinstance(output, bytes):
            output = output.decode('utf-8', 'replace')
        data = json.loads(output)
        if data.get('imdata'):
            fabric_name = data['imdata'][0]['topSystem']['attributes'].get('fabricDomain', 'Unknown')
            logger.debug('Fabric name retrieved: {0}'.format(fabric_name))
            return fabric_name
    except Exception as e:
        logger.warning('Could not retrieve fabric name: {0}'.format(e))
    return 'Unknown'


def get_apic_version():
    try:
        cmd = "icurl -gs 'http://127.0.0.1:7777/api/class/firmwareCtrlrRunning.json?query-target-filter=eq(firmwareCtrlrRunning.type,\"controller\")'"
        raw = subprocess.check_output(cmd, shell=True)
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', 'replace')
        data = json.loads(raw)
        for item in data.get('imdata', []):
            if 'firmwareCtrlrRunning' in item:
                return item['firmwareCtrlrRunning']['attributes'].get('version', 'Unknown')
    except Exception as e:
        logger.warning('Could not retrieve APIC version: {0}'.format(e))
    return 'Unknown'


def get_appliance_address():
    """Return the management IP of the local APIC."""
    try:
        verify_out = subprocess.check_output(['acidiag', 'verifyapic'])
        if isinstance(verify_out, bytes):
            verify_out = verify_out.decode('utf-8', 'replace')
        sn_match = re.search(r'SN:([A-Za-z0-9]+)', verify_out)
        if not sn_match:
            raise RuntimeError('Cannot extract serial from acidiag verifyapic')
        local_sn = sn_match.group(1)

        avread_out = subprocess.check_output(['acidiag', 'avread'])
        if isinstance(avread_out, bytes):
            avread_out = avread_out.decode('utf-8', 'replace')
        addr_match = re.search(
            r'appliance id=\d+\s+address=([^\s]+).*' + local_sn, avread_out
        )
        if not addr_match:
            raise RuntimeError('Cannot find APIC address for SN {0}'.format(local_sn))
        return addr_match.group(1)
    except subprocess.CalledProcessError:
        raise RuntimeError('acidiag command failed - are you running on an APIC?')

# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
def get_fabric_nodes():
    """Return a dict keyed by node_id with switch metadata."""
    nodes = {}
    try:
        with ApiRequest('http://127.0.0.1:7777/api/class/fabricNode.json') as api:
            data = api.json()
            if not data:
                logger.warning('fabricNode API returned empty data')
                return nodes
            raw_count = len(data.get('imdata', []))
            logger.debug('fabricNode API: {0} total records received'.format(raw_count))
            skipped_controllers = 0
            skipped_inactive = 0
            for item in data.get('imdata', []):
                attrs = item.get('fabricNode', {}).get('attributes', {})
                role = attrs.get('role', '')
                if role == 'controller':
                    skipped_controllers += 1
                    logger.debug('Skipping controller: id={0} name={1}'.format(
                        attrs.get('id'), attrs.get('name')))
                    continue
                node_id = attrs.get('id')
                fabric_st = attrs.get('fabricSt', 'Unknown')
                if node_id:
                    if fabric_st != 'active':
                        logger.debug('fabricNode id={0} name={1} skipped - fabricSt={2} (not active)'.format(
                            attrs.get('id'), attrs.get('name'), fabric_st))
                        skipped_inactive += 1
                        continue
                    entry = {
                        'name':     attrs.get('name', 'node-{0}'.format(node_id)),
                        'ip':       attrs.get('address', 'Unknown'),
                        'platform': attrs.get('model',   'Unknown'),
                        'serial':   attrs.get('serial',  'Unknown'),
                        'state':    fabric_st,
                    }
                    nodes[node_id] = entry
                    logger.debug('fabricNode id={0} name={1} ip={2} platform={3} state={4} role={5}'.format(
                        node_id, entry['name'], entry['ip'],
                        entry['platform'], entry['state'], role))
            logger.debug('fabricNode summary: {0} active switches collected, {1} controllers skipped, {2} inactive skipped'.format(
                len(nodes), skipped_controllers, skipped_inactive))
    except Exception as e:
        logger.error('Failed to retrieve fabricNode data: {0}'.format(e))
        raise
    return nodes


def get_eqpt_flash():
    """Return a dict keyed by node_id with eqptFlash attributes."""
    flash = {}
    try:
        with ApiRequest('http://127.0.0.1:7777/api/class/eqptFlash.json') as api:
            data = api.json()
            if not data:
                logger.warning('eqptFlash API returned empty data')
                return flash
            raw_count = len(data.get('imdata', []))
            logger.debug('eqptFlash API: {0} total records received'.format(raw_count))
            skipped_no_dn = 0
            for item in data.get('imdata', []):
                attrs = item.get('eqptFlash', {}).get('attributes', {})
                dn = attrs.get('dn', '')
                match = re.search(r'topology/pod-(\d+)/node-(\d+)/', dn)
                if match:
                    pod_id    = match.group(1)
                    node_id   = match.group(2)
                    sup_match = re.search(r'supslot-(\d+)', dn)
                    attrs['_sup_slot'] = sup_match.group(1) if sup_match else '1'
                    flash.setdefault(node_id, []).append(attrs)
                    logger.debug(
                        'eqptFlash node={0} pod={1} supslot={2} model={3} vendor={4} '
                        'peCycles={5} lifetime={6} minorAlarm={7} majorAlarm={8} operSt={9}'.format(
                            node_id, pod_id, attrs['_sup_slot'],
                            attrs.get('model',      'N/A'),
                            attrs.get('vendor',     'N/A'),
                            attrs.get('peCycles',   'N/A'),
                            attrs.get('lifetime',   'N/A'),
                            attrs.get('minorAlarm', 'N/A'),
                            attrs.get('majorAlarm', 'N/A'),
                            attrs.get('operSt',     'N/A'),
                        )
                    )
                else:
                    skipped_no_dn += 1
                    logger.debug('eqptFlash record skipped - could not parse node from dn={0}'.format(dn))
            total_stored = sum(len(v) for v in flash.values())
            logger.debug('eqptFlash summary: {0} records stored across {1} nodes, {2} skipped (no DN match)'.format(
                total_stored, len(flash), skipped_no_dn))
    except Exception as e:
        logger.error('Failed to retrieve eqptFlash data: {0}'.format(e))
        raise
    return flash

def get_eqpt_supc():
    """Return a dict keyed by (node_id, sup_slot) with supervisor model and serial."""
    supc = {}
    try:
        with ApiRequest('http://127.0.0.1:7777/api/class/eqptSupC.json') as api:
            data = api.json()
            if not data:
                logger.warning('eqptSupC API returned empty data')
                return supc
            raw_count = len(data.get('imdata', []))
            logger.debug('eqptSupC API: {0} total records received'.format(raw_count))
            skipped = 0
            for item in data.get('imdata', []):
                attrs = item.get('eqptSupC', {}).get('attributes', {})
                dn = attrs.get('dn', '')
                match     = re.search(r'topology/pod-(?:\d+)/node-(\d+)/', dn)
                sup_match = re.search(r'supslot-(\d+)', dn)
                if match and sup_match:
                    node_id  = match.group(1)
                    sup_slot = sup_match.group(1)
                    supc[(node_id, sup_slot)] = {
                        'sup_model':  attrs.get('model', ''),
                        'sup_serial': attrs.get('ser',   ''),
                    }
                    logger.debug('eqptSupC node={0} supslot={1} model={2} serial={3}'.format(
                        node_id, sup_slot, attrs.get('model', 'N/A'), attrs.get('ser', 'N/A')))
                else:
                    skipped += 1
                    logger.debug('eqptSupC record skipped - could not parse node/supslot from dn={0}'.format(dn))
            logger.debug('eqptSupC summary: {0} records stored, {1} skipped'.format(len(supc), skipped))
    except Exception as e:
        logger.error('Failed to retrieve eqptSupC data: {0}'.format(e))
        # Non-fatal: SUP model/serial will be empty strings if this fails
    return supc

# ---------------------------------------------------------------------------
# SSD model / threshold helpers
# ---------------------------------------------------------------------------
def identify_ssd_model(device_model):
    """Return the matching SSD_THRESHOLDS entry or None."""
    if not device_model:
        logger.debug('identify_ssd_model: empty model string')
        return None
    for entry in SSD_THRESHOLDS:
        if re.search(entry['pattern'], device_model):
            logger.debug('identify_ssd_model: "{0}" matched vendor={1} model={2} pattern={3}'.format(
                device_model, entry['vendor'], entry['model'], entry['pattern']))
            return entry
    logger.debug('identify_ssd_model: "{0}" did not match any known threshold entry'.format(device_model))
    return None


def get_pe_max(model_def):
    """Extract the P/E max_value from a model definition, or None."""
    if not model_def:
        return None
    for attr in model_def.get('attributes', []):
        if attr.get('name') == 'P/E':
            return attr.get('max_value')
    return None


def calculate_pe_lifetime(pe_cycles, pe_max):
    """
    Return the P/E-based lifetime percentage (0-100+).
    Returns None if either value is unavailable.
    """
    if pe_cycles is None or pe_max is None or pe_max == 0:
        return None
    return (float(pe_cycles) / float(pe_max)) * 100.0


# Map SSD_THRESHOLDS attribute names → (eqptFlash field name, is_float)
_ATTR_TO_FLASH = {
    'P/E': ('peCycles', False),
    'GBB': ('gbb',      False),
    'RRE': ('readErr',  False),
    'TBW': ('tbw',      True),
}


def calculate_micron_lifetime(flash_attrs, model_def):
    """
    Replicate pfm_main.c update_ssd_overall_lifetime_percentage for Micron drives:

        lifetime = max(pe_pct, gbb_pct, rre_pct)   -- M600 / M5100 / M5300 / M500IT / M1100 / M5400
        lifetime = max(pe_pct, gbb_pct, tbw_pct)   -- M550 and others

    The attributes to include are determined by the SSD_THRESHOLDS entry (model_def)
    so the function works for all Micron models without additional branching.

    Returns (lifetime_pct, component_pcts) where component_pcts is a dict
    {attr_name: pct} for each attribute that had usable data.
    Returns (None, {}) when the model is not in SSD_THRESHOLDS or no raw data.
    """
    if not model_def or not flash_attrs:
        return None, {}

    component_pcts = {}
    for attr in model_def.get('attributes', []):
        attr_name = attr.get('name')
        max_val = attr.get('max_value', 0)
        if attr_name not in _ATTR_TO_FLASH or max_val == 0:
            continue
        field, is_float = _ATTR_TO_FLASH[attr_name]
        raw_str = flash_attrs.get(field, '')
        try:
            raw_val = float(raw_str) if is_float else int(raw_str)
        except (ValueError, TypeError):
            continue
        component_pcts[attr_name] = (float(raw_val) / float(max_val)) * 100.0

    if not component_pcts:
        return None, {}

    return max(component_pcts.values()), component_pcts

# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------
def process_switches(fabric_nodes, flash_data, supc_data):
    """
    Build a result list containing one entry per switch SUP slot.
    Single-SUP switches produce one row; dual-SUP spines produce two rows.

    Each entry includes:
      - Switch metadata
      - SSD model / vendor
      - peCycles (raw value from eqptFlash)
      - pe_max  (from SSD_THRESHOLDS)
      - pe_lifetime_pct  (peCycles / pe_max * 100)
      - apic_lifetime_pct  (the 'lifetime' field APIC reports - potentially wrong)
      - minor_alarm  (yes / no / Unknown)
      - major_alarm  (yes / no / Unknown)
      - alarm_raised  (True if either alarm is 'yes')
      - is_micron  (True if vendor == Micron)
      - cscwt38698_hit  (True if Micron + alarm + pe_lifetime < 80%)
      - notes
    """
    results = []

    for node_id, node in sorted(iteritems(fabric_nodes), key=lambda x: x[0]):
        flash_list = flash_data.get(node_id, [{}])
        for flash in flash_list:
            sup_slot = flash.get('_sup_slot', '1')

            # ---- Supervisor metadata (eqptSupC) -----------------------------
            supc_entry = supc_data.get((node_id, sup_slot), {})
            sup_model  = supc_entry.get('sup_model',  '')
            sup_serial = supc_entry.get('sup_serial', '')

            # ---- SSD metadata -----------------------------------------------
            ssd_model   = flash.get('model',  'Unknown')
            raw_vendor  = flash.get('vendor', 'Unknown')
            vendor      = 'Hynix' if raw_vendor == 'Hyinx' else raw_vendor
            firmware    = flash.get('rev',    'Unknown')
            ssd_serial  = flash.get('ser',    'Unknown')

            # ---- Alarm fields -----------------------------------------------
            minor_alarm = flash.get('minorAlarm', 'Unknown')  # 'yes' or 'no'
            major_alarm = flash.get('majorAlarm', 'Unknown')  # 'yes' or 'no'
            alarm_raised = (
                minor_alarm.lower() == 'yes' or major_alarm.lower() == 'yes'
            ) if flash else False

            # ---- APIC-reported lifetime (the field that may be wrong) --------
            apic_lifetime_raw = flash.get('lifetime', '')
            try:
                apic_lifetime_pct = float(apic_lifetime_raw)
            except (ValueError, TypeError):
                apic_lifetime_pct = None

            # ---- P/E cycles -------------------------------------------------
            pe_cycles_raw = flash.get('peCycles', '')
            try:
                pe_cycles = int(pe_cycles_raw)
            except (ValueError, TypeError):
                pe_cycles = None

            # ---- Identify model and P/E max threshold -----------------------
            model_def = identify_ssd_model(ssd_model)
            pe_max    = get_pe_max(model_def)

            # If vendor is known from flash but model is not in thresholds,
            # let the model_def vendor take precedence when available.
            if model_def:
                vendor = model_def.get('vendor', vendor)

            # ---- Determine vendor type first --------------------------------
            is_micron = 'micron' in vendor.lower()

            # ---- P/E-only lifetime (preserved for CSV reference column) -----
            pe_lifetime_pct = calculate_pe_lifetime(pe_cycles, pe_max) if is_micron else None

            # ---- Multi-metric lifetime (PE + GBB + RRE/TBW) ----------------
            # Replicates pfm_main.c monitor_ssd_health /
            # update_ssd_overall_lifetime_percentage (line 4323):
            #   lifetime = max(pe_pct, gbb_pct, rre_pct)   M600/M5100/M5300/M500IT/M1100/M5400
            #   lifetime = max(pe_pct, gbb_pct, tbw_pct)   M550 and others
            # Each pct = (raw_value / max_value) * 100.
            # Using only PE here causes nodes whose GBB or RRE exceed 80% to be
            # misclassified as CSCwt38698 false positives even when the alarm
            # is genuinely warranted.
            if is_micron:
                effective_lifetime_pct, component_pcts = calculate_micron_lifetime(flash, model_def)
            else:
                effective_lifetime_pct = apic_lifetime_pct
                component_pcts = {}

            # ---- CSCwt38698 detection ---------------------------------------
            # Only applicable to Micron drives

            if is_micron and alarm_raised and effective_lifetime_pct is not None:
                cscwt38698_hit = effective_lifetime_pct < 80.0
            else:
                cscwt38698_hit = False

            # ---- Debug log for this switch ----------------------------------
            logger.debug(
                'process node={0} ({1}) sup={2}: vendor={3} model={4} '
                'peCycles={5} pe_max={6} pe_lifetime={7} apic_lifetime={8} effective_lifetime={9} '
                'components={10} '
                'minorAlarm={11} majorAlarm={12} alarm_raised={13} '
                'is_micron={14} cscwt38698_hit={15}'.format(
                    node_id, node['name'], sup_slot,
                    vendor, ssd_model,
                    pe_cycles, pe_max,
                    '{0:.2f}%'.format(pe_lifetime_pct) if pe_lifetime_pct is not None else 'N/A',
                    '{0:.2f}%'.format(apic_lifetime_pct) if apic_lifetime_pct is not None else 'N/A',
                    '{0:.2f}%'.format(effective_lifetime_pct) if effective_lifetime_pct is not None else 'N/A',
                    {k: '{0:.1f}%'.format(v) for k, v in iteritems(component_pcts)},
                    minor_alarm, major_alarm, alarm_raised,
                    is_micron, cscwt38698_hit,
                )
            )

            # ---- Build notes ------------------------------------------------
            notes_parts = []
            if not flash:
                notes_parts.append('No eqptFlash data')
            if pe_max is None and is_micron:
                notes_parts.append('P/E max not found in thresholds - model may be unrecognized')
            if cscwt38698_hit:
                notes_parts.append(
                    'Wrongly raised fault (CSCwt38698): effective lifetime is {0:.1f}% but alarm is active. '
                    'See {1}'.format(effective_lifetime_pct, CSCWT38698_URL)
                )
            notes = '; '.join(notes_parts) if notes_parts else ''

            results.append({
                'node_id':                node_id,
                'sup_slot':               sup_slot,
                'sup_model':              sup_model,
                'sup_serial':             sup_serial,
                'switch_name':            node['name'],
                'switch_ip':              node['ip'],
                'platform':               node['platform'],
                'switch_serial':          node['serial'],
                'node_state':             node['state'],
                'ssd_model':              ssd_model,
                'vendor':                 vendor,
                'ssd_serial':             ssd_serial,
                'firmware':               firmware,
                'pe_cycles':              pe_cycles,
                'pe_max':                 pe_max,
                'pe_lifetime_pct':        pe_lifetime_pct,        # Micron P/E only (reference)
                'apic_lifetime_pct':      apic_lifetime_pct,      # raw eqptFlash.lifetime
                'effective_lifetime_pct': effective_lifetime_pct, # max(PE/GBB/RRE) for Micron; apic for others
                'component_pcts':         component_pcts,         # {attr: pct} breakdown for Micron
                'minor_alarm':            minor_alarm,
                'major_alarm':            major_alarm,
                'alarm_raised':           alarm_raised,
                'is_micron':              is_micron,
                'cscwt38698_hit':         cscwt38698_hit,
                'notes':                  notes,
            })

    return results

# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------
FIELDNAMES = [
    'Fabric Name',
    'Fabric Version',
    'Switch Name',
    'Switch IP',
    'Node ID',
    'SUP Slot',
    'SUP Model',
    'SUP Serial',
    'Platform',
    'Switch Serial',
    'Node State',
    'SSD Vendor',
    'SSD Model',
    'SSD Serial',
    'Firmware',
    'P/E Cycles (current)',
    'P/E Max (threshold)',
    'Actual Lifetime %',
    'P/E Lifetime %',
    'GBB Lifetime %',
    'RRE/TBW Lifetime %',
    'APIC Reported Lifetime %',
    'Minor Alarm - F3074 (yes/no)',
    'Major Alarm - F3073 (yes/no)',
    'Alarm Raised',
    'CSCwt38698 Hit',
    'CSCwt38698 URL',
    'Notes',
]


def _fmt(value, precision=2):
    """Format a float to a fixed-precision string, or return empty string."""
    if value is None:
        return ''
    if isinstance(value, float):
        return '{0:.{1}f}'.format(value, precision)
    return str(value)


def generate_csv(results, fabric_name, fabric_version, filename):
    try:
        if PY2:
            csvfile = open(filename, 'wb')
        else:
            csvfile = open(filename, 'w', newline='', encoding='utf-8')

        try:
            if PY2:
                writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES)
            else:
                writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES)

            writer.writeheader()

            def _sort_key(r):
                v = r.get('effective_lifetime_pct')
                return v if v is not None else -1.0

            for r in sorted(results, key=_sort_key, reverse=True):
                row = {
                    'Fabric Name':                    fabric_name,
                    'Fabric Version':                 fabric_version,
                    'Switch Name':                    r['switch_name'],
                    'Switch IP':                      r['switch_ip'],
                    'Node ID':                        r['node_id'],
                    'SUP Slot':                       r['sup_slot'],
                    'SUP Model':                      r['sup_model'],
                    'SUP Serial':                     r['sup_serial'],
                    'Platform':                       r['platform'],
                    'Switch Serial':                  r['switch_serial'],
                    'Node State':                     r['node_state'],
                    'SSD Vendor':                     r['vendor'],
                    'SSD Model':                      r['ssd_model'],
                    'SSD Serial':                     r['ssd_serial'],
                    'Firmware':                       r['firmware'],
                    'P/E Cycles (current)':           _fmt(r['pe_cycles'], 0),
                    'P/E Max (threshold)':            _fmt(r['pe_max'],    0),
                    'Actual Lifetime %':              _fmt(r['effective_lifetime_pct']),
                    'P/E Lifetime %':                 _fmt(r['pe_lifetime_pct']),
                    'GBB Lifetime %':                 _fmt(r['component_pcts'].get('GBB')),
                    'RRE/TBW Lifetime %':             _fmt(r['component_pcts'].get('RRE', r['component_pcts'].get('TBW'))),
                    'APIC Reported Lifetime %':       _fmt(r['apic_lifetime_pct']),
                    'Minor Alarm - F3074 (yes/no)':   r['minor_alarm'],
                    'Major Alarm - F3073 (yes/no)':   r['major_alarm'],
                    'Alarm Raised':                   'Yes' if r['alarm_raised'] else 'No',
                    'CSCwt38698 Hit':                 'Yes' if r['cscwt38698_hit'] else 'No',
                    'CSCwt38698 URL':                 CSCWT38698_URL if r['cscwt38698_hit'] else '',
                    'Notes':                          r['notes'],
                }

                if PY2:
                    encoded = {}
                    for k, v in iteritems(row):
                        if isinstance(v, unicode):  # noqa: F821
                            encoded[k] = v.encode('utf-8')
                        else:
                            encoded[k] = v
                    writer.writerow(encoded)
                else:
                    writer.writerow(row)

        finally:
            csvfile.close()

        return True

    except Exception as e:
        logger.error('Failed to write CSV: {0}'.format(e))
        logger.debug(traceback.format_exc())
        return False

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
def print_summary(results, fabric_name, fabric_version, csv_filename):
    total         = len(results)
    micron_count  = sum(1 for r in results if r['is_micron'])
    alarm_count   = sum(1 for r in results if r['alarm_raised'])
    csc_hit_count = sum(1 for r in results if r['cscwt38698_hit'])

    # Switches genuinely over 80% lifetime (true positives – any vendor)
    # Uses effective_lifetime_pct: P/E-based for Micron, APIC lifetime for others
    truly_over_80 = [
        r for r in results
        if r['effective_lifetime_pct'] is not None and r['effective_lifetime_pct'] >= 80.0
    ]
    truly_over_80_sorted = sorted(truly_over_80, key=lambda x: x['effective_lifetime_pct'], reverse=True)

    print('')
    print('=' * 70)
    print(' SSD Lifetime Validation Summary')
    print(' Fabric : {0}  |  Version : {1}'.format(fabric_name, fabric_version))
    print(' Run at : {0}'.format(datetime.now()))
    print('=' * 70)
    print('  Total SUP entries processed    : {0}'.format(total))
    print('  Switches with Micron SSD       : {0}'.format(micron_count))
    print('  *** SSDs actually over 80%     : {0} ***'.format(len(truly_over_80)))
    print('  Switches with active alarm     : {0}'.format(alarm_count))
    print('  CSCwt38698 affected (false +ve): {0}'.format(csc_hit_count))
    print('=' * 70)

    # ------------------------------------------------------------------
    # Section 1 – TRUE positives: P/E lifetime >= 80% (needs action)
    # ------------------------------------------------------------------
    print('')
    print('  +' + '=' * 65 + '+')
    print('  |  SWITCH SSDs ACTUALLY OVER 80% USAGE  -  ACTION REQUIRED        |')
    print('  |  These switches have a genuine lifetime >= 80%.                 |')
    print('  |  They are NOT hitting CSCwt38698; the fault is valid.           |')
    print('  +' + '=' * 65 + '+')

    if truly_over_80_sorted:
        print('  {:<22} {:<15} {:<9} {:<5} {:<20} {:<14} {:<13} {:<8} {:<8} {:<8}'.format(
            'Switch', 'IP', 'Node ID', 'Slot', 'SUP Model', 'SSD Model', 'Actual Life%', 'Vendor', 'F3074', 'F3073'))
        print('  ' + '-' * 127)
        for r in truly_over_80_sorted:
            pe_str = '{0:.1f}%'.format(r['effective_lifetime_pct'])
            print('  {:<22} {:<15} {:<9} {:<5} {:<20} {:<14} {:<13} {:<8} {:<8} {:<8}'.format(
                r['switch_name'][:21],
                r['switch_ip'],
                r['node_id'],
                r['sup_slot'],
                (r['sup_model'] or r['platform'])[:19],
                r['ssd_model'][:13],
                pe_str,
                r['vendor'][:7],
                r['minor_alarm'],
                r['major_alarm'],
            ))
    else:
        print('  No switches have a genuine lifetime at or above 80%. No immediate action required.')

    # ------------------------------------------------------------------
    # Section 2 – FALSE positives: CSCwt38698 (alarm raised, P/E < 80%)
    # ------------------------------------------------------------------
    print('')
    print('  +' + '-' * 65 + '+')
    print('  |  SWITCHES HITTING CSCwt38698  -  ALARM IS WRONG                 |')
    print('  |  Micron SSD + alarm raised + P/E lifetime < 80%.                |')
    print('  |  The fault (F3073/F3074) is a false positive due to CSCwt38698. |')
    print('  +' + '-' * 65 + '+')

    if csc_hit_count:
        print('  {:<22} {:<15} {:<9} {:<5} {:<20} {:<14} {:<13} {:<8} {:<8}'.format(
            'Switch', 'IP', 'Node ID', 'Slot', 'SUP Model', 'SSD Model', 'Actual Life%', 'F3074', 'F3073'))
        print('  ' + '-' * 119)
        for r in sorted(results, key=lambda x: x['effective_lifetime_pct'] if x['effective_lifetime_pct'] is not None else -1.0, reverse=True):
            if r['cscwt38698_hit']:
                pe_str = '{0:.1f}%'.format(r['effective_lifetime_pct']) if r['effective_lifetime_pct'] is not None else 'N/A'
                print('  {:<22} {:<15} {:<9} {:<5} {:<20} {:<14} {:<10} {:<8} {:<8}'.format(
                    r['switch_name'][:21],
                    r['switch_ip'],
                    r['node_id'],
                    r['sup_slot'],
                    (r['sup_model'] or r['platform'])[:19],
                    r['ssd_model'][:13],
                    pe_str,
                    r['minor_alarm'],
                    r['major_alarm'],
                ))
        print('\n  Defect URL: {0}'.format(CSCWT38698_URL))
    else:
        print('  No switches are hitting CSCwt38698.')

    print('\n  Full CSV report for all switches : {0}'.format(csv_filename))
    print('=' * 70)
    print('')

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    script_start = time.time()

    parser = argparse.ArgumentParser(
        description='ACI SSD Lifetime Validation - CSCwt38698 detection'
    )
    parser.add_argument('--csv', default=None,
                        help='Output CSV filename (default: auto-generated with timestamp)')
    args = parser.parse_args()

    print('======================================================')
    print(' ACI SSD Lifetime Validation Script')
    print(' {0}'.format(datetime.now()))
    print('======================================================')
    print()

    # ------------------------------------------------------------------
    # Step 1 – collect fabric metadata
    # ------------------------------------------------------------------
    print('Collecting fabric information...')
    try:
        fabric_name    = get_fabric_name()
        fabric_version = get_apic_version()
        print('  Fabric     : {0}'.format(fabric_name))
        print('  ACI version: {0}'.format(fabric_version))
    except Exception as e:
        print('Warning: could not retrieve fabric metadata: {0}'.format(e))
        fabric_name    = 'Unknown'
        fabric_version = 'Unknown'

    # ------------------------------------------------------------------
    # Step 2 – collect node and SSD data from APIC
    # ------------------------------------------------------------------
    print('\nCollecting switch (fabricNode) data...')
    try:
        fabric_nodes = get_fabric_nodes()
        print('  Found {0} switches.'.format(len(fabric_nodes)))
    except Exception as e:
        print('\033[1;31mFailed to retrieve fabric nodes: {0}\033[0m'.format(e))
        return 1

    print('Collecting SSD (eqptFlash) data...')
    try:
        flash_data = get_eqpt_flash()
        total_flash_records = sum(len(v) for v in flash_data.values())
        print('  Found {0} eqptFlash records across {1} nodes.'.format(total_flash_records, len(flash_data)))
    except Exception as e:
        print('\033[1;31mFailed to retrieve eqptFlash data: {0}\033[0m'.format(e))
        return 1

    print('Collecting supervisor (eqptSupC) data...')
    supc_data = get_eqpt_supc()
    print('  Found {0} eqptSupC records.'.format(len(supc_data)))

    # ------------------------------------------------------------------
    # Step 3 – process: calculate P/E lifetime, detect alarms, flag CSC
    # ------------------------------------------------------------------
    print('\nProcessing switches...')
    results = process_switches(fabric_nodes, flash_data, supc_data)
    print('  Processed {0} SUP entries across {1} switches.'.format(len(results), len(fabric_nodes)))

    # ------------------------------------------------------------------
    # Step 4 – export CSV
    # ------------------------------------------------------------------
    if args.csv:
        csv_filename = args.csv
    else:
        prefix = fabric_name if fabric_name != 'Unknown' else 'fabric'
        csv_filename = '{0}_ssd-lifetime-validation-{1}.csv'.format(
            prefix, datetime.now().strftime('%Y-%m-%d_%H%M')
        )

    print('\nGenerating CSV report: {0}'.format(csv_filename))
    ok = generate_csv(results, fabric_name, fabric_version, csv_filename)
    if not ok:
        print('\033[1;31mFailed to generate CSV report.\033[0m')
        return 1

    # ------------------------------------------------------------------
    # Step 5 – console summary
    # ------------------------------------------------------------------
    print_summary(results, fabric_name, fabric_version, csv_filename)

    elapsed = time.time() - script_start
    print('Completed in {0:.1f} seconds.'.format(elapsed))
    return 0


if __name__ == '__main__':
    sys.exit(main())