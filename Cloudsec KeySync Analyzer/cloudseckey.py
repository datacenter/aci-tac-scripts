#!/usr/bin/python3
import requests
import json
import urllib3
import argparse
import logging.handlers
import logging
import sys
import re
import threading
import time
import getpass
import logging.handlers

urllib3.disable_warnings()

site_id_reg = r'uni/tn-infra/fabricExtConnP-(?P<magic>\d+)/siteConnP-(?P<peersite>\d+)/'
local_policy_remote_policy = {}
audit_analysis_result = {}



logger = logging.getLogger(__name__)


def setup_logger(logger, level):
    logging_level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
    }.get(level, logging.DEBUG)
    logger.setLevel(logging_level)
    logger_handler = logging.StreamHandler(sys.stdout)
    fmt = "%(asctime)s.%(msecs).03d||%(levelname)s||"
    fmt += "(%(lineno)d)||%(message)s"
    logger_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt="%Z %Y-%m-%dT%H:%M:%S"))
    logger.addHandler(logger_handler)
    filehandler = logging.FileHandler("./log.txt")
    filehandler.setLevel(logging.DEBUG)
    filehandler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%dT%H:%M:%S")
    )
    logger.addHandler(filehandler)


def syslog(msg, server="localhost", server_port=514, severity="crit", process="EPT",
        facility=logging.handlers.SysLogHandler.LOG_LOCAL7):
    """ send a syslog message to remote server.  return boolean success
        for acceptible facilities see:
            https://docs.python.org/2/library/logging.handlers.html
            15.9.9. SysLogHandler
    """
    if msg is None:

        return False
    if server is None:

        return False
    try:
        if(isinstance(server_port, int)):
            port = int(server_port)
        else:
            port = 514
    except ValueError as e:
        return False

    if isinstance(severity, str): severity = severity.lower()
    severity = {
        "alert"     : logging.handlers.SysLogHandler.LOG_ALERT,
        "crit"      : logging.handlers.SysLogHandler.LOG_CRIT,
        "debug"     : logging.handlers.SysLogHandler.LOG_DEBUG,
        "emerg"     : logging.handlers.SysLogHandler.LOG_EMERG,
        "err"       : logging.handlers.SysLogHandler.LOG_ERR,
        "info"      : logging.handlers.SysLogHandler.LOG_INFO,
        "notice"    : logging.handlers.SysLogHandler.LOG_NOTICE,
        "warning"   : logging.handlers.SysLogHandler.LOG_WARNING,
        0           : logging.handlers.SysLogHandler.LOG_EMERG,
        1           : logging.handlers.SysLogHandler.LOG_ALERT,
        2           : logging.handlers.SysLogHandler.LOG_CRIT,
        3           : logging.handlers.SysLogHandler.LOG_ERR,
        4           : logging.handlers.SysLogHandler.LOG_WARNING,
        5           : logging.handlers.SysLogHandler.LOG_NOTICE,
        6           : logging.handlers.SysLogHandler.LOG_INFO,
        7           : logging.handlers.SysLogHandler.LOG_DEBUG,
    }.get(severity, logging.handlers.SysLogHandler.LOG_INFO)

    facility_name = {
        logging.handlers.SysLogHandler.LOG_AUTH: "LOG_AUTH",
        logging.handlers.SysLogHandler.LOG_AUTHPRIV: "LOG_AUTHPRIV",
        logging.handlers.SysLogHandler.LOG_CRON: "LOG_CRON",
        logging.handlers.SysLogHandler.LOG_DAEMON: "LOG_DAEMON",
        logging.handlers.SysLogHandler.LOG_FTP: "LOG_FTP",
        logging.handlers.SysLogHandler.LOG_KERN: "LOG_KERN",
        logging.handlers.SysLogHandler.LOG_LPR: "LOG_LPR",
        logging.handlers.SysLogHandler.LOG_MAIL: "LOG_MAIL",
        logging.handlers.SysLogHandler.LOG_NEWS: "LOG_NEWS",
        logging.handlers.SysLogHandler.LOG_SYSLOG: "LOG_SYSLOG",
        logging.handlers.SysLogHandler.LOG_USER: "LOG_USER",
        logging.handlers.SysLogHandler.LOG_UUCP: "LOG_UUCP",
        logging.handlers.SysLogHandler.LOG_LOCAL0: "LOG_LOCAL0",
        logging.handlers.SysLogHandler.LOG_LOCAL1: "LOG_LOCAL1",
        logging.handlers.SysLogHandler.LOG_LOCAL2: "LOG_LOCAL2",
        logging.handlers.SysLogHandler.LOG_LOCAL3: "LOG_LOCAL3",
        logging.handlers.SysLogHandler.LOG_LOCAL4: "LOG_LOCAL4",
        logging.handlers.SysLogHandler.LOG_LOCAL5: "LOG_LOCAL5",
        logging.handlers.SysLogHandler.LOG_LOCAL6: "LOG_LOCAL6",
        logging.handlers.SysLogHandler.LOG_LOCAL7: "LOG_LOCAL7",
    }.get(facility, "LOG_LOCAL7")

    old_handlers = []
    syslogger = logging.getLogger("syslog")
    syslogger.setLevel(logging.DEBUG)
    fmt = "%(asctime)s %(message)s"
    remote_syslog = logging.handlers.SysLogHandler(address=(server,port),facility=facility)
    remote_syslog.setFormatter(logging.Formatter(fmt=fmt,datefmt=": %Y %b %d %H:%M:%S %Z:"))
    syslogger.addHandler(remote_syslog)

    s = "%%%s-%s-%s: %s" % (facility_name, severity, process, msg)
    method = {
        0: syslogger.critical,
        1: syslogger.critical,
        2: syslogger.critical,
        3: syslogger.error,
        4: syslogger.warning,
        5: syslogger.warning,
        6: syslogger.info,
        7: syslogger.debug,
    }.get(severity, syslogger.info)

    method(s)
    syslogger.removeHandler(remote_syslog)
    for h in old_handlers: logger.addHandler(h)
    return True


def batch_work(work):
    threads = []
    for (target, args) in work:
        t = threading.Thread(target=target, args=args)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return


class MSO:
    def __init__(self, host_ip, username, password):
        self.auth = {
            'username': username,
            'password': password
        }
        self.MSO_URL = "https://" + host_ip + "/mso/api/v1"
        self.ND_URL = "https://" + host_ip + "/api/v1"
        self.head = self.authenticate()

    def authenticate(self):
        url = self.ND_URL + '/auth/login'
        try:
            resp = requests.post(url, json=self.auth, headers={'Content-type': 'application/json'}, verify=False)
        except Exception as e:
            logger.error('Failed to authenticate: {}'.format(e))
            sys.exit("")

        if resp.ok:
            attributes = resp.json()

            token = attributes.get('token')
            head = {
                "Accept": "application/json",
                "Authorization": "Bearer " + token
            }
            return head
        else:
            logger.error('Incorrect Credential,Failed to authenticate')
            sys.exit("")

    def get_policy(self, url):
        r = requests.get(self.MSO_URL + url, headers=self.head, verify=False)
        if r.status_code == requests.codes.ok:
            return r.json()
        return None

    def get_sites_apic(self, site_apic):

        sites = self.get_policy("/sites")

        for site in sites.get("sites"):
            apicSiteId = str(site.get("apicSiteId"))
            if apicSiteId in site_apic.keys():
                site_name = site.get('name')
                site_urls = site.get("urls")[0].split("//")[1]
                site_apic[apicSiteId]['name'] = site_name
                site_apic[apicSiteId]['apic'] = site_urls

    def get_site_fabric(self):

        site_apic = {}
        sites = self.get_policy("/sites/fabric-connectivity")

        for site in sites.get("sites"):
            apic_siteId = str(site.get("apicSiteId"))
            cloudsec = site.get('cloudSecEnabled')
            platform = site.get('platform')

            # Make sure the sites is on-premise with cloudsec enable
            if cloudsec and platform == 'on-premise':
                site_apic[apic_siteId] = {}
        self.get_sites_apic(site_apic)
        logger.debug(site_apic)
        return site_apic


class APIC:
    def __init__(self, site, site_name, apic, user_id, user_passwd,running_mode):
        self.local_site = site
        self.apic_ip = apic
        self.site_name = site_name
        self.auth_result = None

        self.auth = {
            'aaaUser': {
                'attributes': {
                    'name': user_id,
                    'pwd': user_passwd
                }
            }
        }
        self.api_url = "https://" + apic + "/api/"
        self.running_mode = running_mode

    def work(self):
        self.auth_result = self.authenticate()
        if self.running_mode=="Triage":
            self.get_sakeypremote_audit()
        self.get_sakeyp_local()
        self.get_sakeyp_remote()

    def authenticate(self):
        url = self.api_url + '/aaaLogin.json?gui-token-request=yes'

        try:
            resp = requests.post(url, json=self.auth, headers={'Content-type': 'application/json'}, verify=False)
            logger.debug("Authentication Response: {}".format(resp))
        except Exception as e:
            logger.debug('Failed to authenticate: {}'.format(e))
            sys.exit("")

        if resp.ok:
            apic_cookies = resp.cookies
            attributes = resp.json()['imdata'][0]['aaaLogin']['attributes']
            devcookie = attributes['token']
            apic_challenge = attributes['urlToken']
            return apic_cookies, devcookie, apic_challenge
        else:
            logger.error('Incorrect Credential,Failed to authenticate')
            sys.exit("")

    def get_policy(self, url):
        if len(self.auth_result) == 3:
            auth_result = self.auth_result
            saved_cookies = auth_result[0]
            devcookie = auth_result[1]
            apic_challenge = auth_result[2]
            head = {
                "Accept": "*/*",
                "DevCookie": devcookie,
                "APIC-challenge": apic_challenge
            }
            r = requests.get('%s/%s' % (self.api_url, url), cookies=saved_cookies, headers=head, verify=False)
            if r.status_code == requests.codes.ok:
                return r.json()
            else:
                logger.error("fail to get policy for %s/%s" % (self.api_url, url))
        return None

    def get_sakeypremote_audit(self):
        logger.info("Analyzing site "+ self.site_name + " Audit Log for sequenceNumber out of order")
        if self.local_site not in audit_analysis_result:
            audit_analysis_result[self.local_site] = []
        remotesakeyp_audit = self.get_policy('class/aaaModLR.json?&order-by=aaaModLR.created|desc&page-size=1000&'
                        'page=0&query-target-filter=wcard(aaaModLR.dn,"uni/tn-infra/fabricExtConnP.*sakeypremote")')
        if remotesakeyp_audit is None:
            logger.info("Failed to Get Audit for RemoteKey Policy")
            return
        else:
            remotesakeyp_audit = remotesakeyp_audit.get('imdata')
            for r_audit in remotesakeyp_audit:
                attr = r_audit.get("aaaModLR").get("attributes")
                peersiteid = 0
                peersite = re.search(site_id_reg,attr.get("affected"))
                if peersite:
                    peersiteid = peersite.group("peersite")
                created = attr.get("created")
                changeset = attr.get("changeSet")
                if "sequenceNumber" in changeset and "Old" in changeset:
                    changeset = attr.get("changeSet").split("sequenceNumber")[1]
                    #(Old: 11, New: 12)
                    old_seq = int(changeset.split(",")[0].split(":")[1].strip(")").strip())
                    new_seq = int(changeset.split(",")[1].split(":")[1].strip(")").strip())
                    if new_seq - old_seq !=1 and self.local_site != peersite:
                        audit_analysis_result[self.local_site].append(created + ", Local Site ID: " +
                            self.local_site + " , "  + "Peer Site ID: " + peersiteid + " , sequenceNumber " + changeset)

    def get_sakeyp_local(self):
        logger.info("Analyzing site " + self.site_name + " Share Key Policy for Matching")
        local_sakeyp = self.get_policy("class/cloudsecSaKeyPLocal.json")
        if local_sakeyp is None:
            logger.info("Failed to Get Sites Sa Key")
            return
        else:
            local_sakeyp = local_sakeyp.get('imdata')
            for lsakeyp in local_sakeyp:
                attr = lsakeyp.get("cloudsecSaKeyPLocal").get("attributes")
                assocNum = attr.get('assocNum')
                sequenceNumber = attr.get("sequenceNumber")
                peer_siteId = attr.get("siteId")
                local_siteId = self.local_site
                if local_siteId not in local_policy_remote_policy:
                    local_policy_remote_policy[local_siteId] = {}
                    local_policy_remote_policy[local_siteId]['sitename'] = self.site_name
                    local_policy_remote_policy[local_siteId]['peer'] = {}
                if peer_siteId not in local_policy_remote_policy[local_siteId]['peer']:
                    local_policy_remote_policy[local_siteId]['peer'][peer_siteId] = {}
                local_policy_remote_policy[local_siteId]['peer'][peer_siteId]['TX'] = {}
                local_policy_remote_policy[local_siteId]['peer'][peer_siteId]['TX']['sequenceNumber'] = sequenceNumber
                local_policy_remote_policy[local_siteId]['peer'][peer_siteId]['TX']['assocNum'] = assocNum

    def get_sakeyp_remote(self):
        remote_sakey_status = self.get_policy("class/cloudsecSaKeyPRemote.json")
        if remote_sakey_status is None:
            logger.info("Failed to Get Sites Sa Key")
            return
        else:
            remote_sakey_status = remote_sakey_status.get('imdata')
            for rsakeystatus in remote_sakey_status:
                attr = rsakeystatus.get("cloudsecSaKeyPRemote").get("attributes")
                assocNum = attr.get('assocNum')
                sequenceNumber = attr.get("sequenceNumber")
                peer_siteId = '0'
                peersite_reg = re.search(site_id_reg, attr.get("dn"))
                if peersite_reg:
                    peer_siteId = peersite_reg.group('peersite')
                local_siteId = self.local_site
                if local_siteId not in local_policy_remote_policy:
                    local_policy_remote_policy[local_siteId] = {}
                    local_policy_remote_policy[local_siteId]['sitename'] = self.site_name
                    local_policy_remote_policy[local_siteId]['peer'] = {}
                if peer_siteId not in local_policy_remote_policy[local_siteId]['peer']:
                    local_policy_remote_policy[local_siteId]['peer'][peer_siteId] = {}
                local_policy_remote_policy[local_siteId]['peer'][peer_siteId]['RX'] = {}
                local_policy_remote_policy[local_siteId]['peer'][peer_siteId]['RX']['sequenceNumber'] = sequenceNumber
                local_policy_remote_policy[local_siteId]['peer'][peer_siteId]['RX']['assocNum'] = assocNum


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Triage/Monitor cloudsec shared key', usage=" ")
    parser.add_argument('-n', dest="host", required=True, help='ND hostname', default=None)
    parser.add_argument("-d", dest="debug", choices=["debug", "info", "warn"], default="info")
    parser.add_argument("-u", dest="user", help="admin user id ", default="admin")
    parser.add_argument("-s", dest="syslog_server", help="syslog server IP ", default=None)
    parser.add_argument("-i", dest="interval", help="monitor frequency ", default="180")
    parser.add_argument("-m", dest="mon", action="store_true", default=False, help="monitor mode")

    args = parser.parse_args()
    monitor_mode = args.mon
    interval = int(args.interval)
    setup_logger(logger, args.debug)
    running_mode = None
    try:
        nd_ip = args.host
        user_id = args.user
        nd_user_passwd = getpass.getpass("Enter ND/MSO password for %s:" % user_id)
        logger.info("Retrieving Sites Info from ND/MSO")
        mso = MSO(nd_ip, user_id, nd_user_passwd)
        site_apic_dict = mso.get_site_fabric()
        if len(site_apic_dict) < 2:
            logger.info("Exit! Cloudsec enabled sites are less than two\n")
            sys.exit("")
        work = []
        apic_user_passwd = getpass.getpass("Enter APIC password for %s:" % user_id)
        logger.info("Retrieving Key Policy Info from APIC")
        syslog_server=None
        if monitor_mode is True:
            logger.info("Running in Monitor Mode for every " + str(interval) + ' seconds')
            running_mode = "Monitor"
            if args.syslog_server is not None:
                syslog_server = args.syslog_server
        else:
            logger.info("Running in Triage Mode")
            running_mode = "Triage"

        while (True):
            local_policy_remote_policy.clear()
            work.clear()

            for site in site_apic_dict.keys():
                siteid = site
                apic = site_apic_dict.get(siteid).get('apic')
                site_name = site_apic_dict.get(siteid).get('name')

                apic_mo = APIC(siteid, site_name, apic, user_id, apic_user_passwd,running_mode)
                work.append((apic_mo.work, ()))

            batch_work(work)

            logger.debug(json.dumps(local_policy_remote_policy, indent=4, separators=(",", ":")))
            if len(audit_analysis_result)>=1:
                for site in audit_analysis_result.keys():
                    if len(audit_analysis_result[site])>=1:
                        logger.warning(" Site " + site + " used to received remote key with sequenceNumber out of order")
                        for entry in audit_analysis_result[site]:
                            logger.warning(entry)
            if (len(local_policy_remote_policy) == 0):
                sys.exit("")
            if len(local_policy_remote_policy) >= 2:
                logger.info("Cross site validation for shared keys in using")
                for local in local_policy_remote_policy.keys():
                    local_site_name = local_policy_remote_policy.get(local).get('sitename')
                    if len(local_site_name)>=8:
                        local_site_name=local_site_name+"\t"
                    else:
                        local_site_name = local_site_name + "\t\t"
                    logger.debug(local_policy_remote_policy)
                    for peer in local_policy_remote_policy.get(local).get('peer'):
                        peer_site_name = local_policy_remote_policy.get(peer).get('sitename')
                        if len(peer_site_name) >= 8:
                            peer_site_name = peer_site_name + "\t"
                        else:
                            peer_site_name = peer_site_name + "\t\t"
                        tx_seq = local_policy_remote_policy[local]['peer'][peer]['TX']['sequenceNumber']
                        rx_seq = local_policy_remote_policy[peer]['peer'][local]['RX']['sequenceNumber']
                        tx_an = local_policy_remote_policy[local]['peer'][peer]['TX']['assocNum']
                        rx_an = local_policy_remote_policy[peer]['peer'][local]['RX']['assocNum']
                        if tx_seq == rx_seq and tx_an == rx_an:
                            logger.info(local_site_name + ' id ' + local + ' --> ' + peer_site_name + ' id ' + peer +
                                        ' , keys synced at sequenceNumber: ' + tx_seq + ' , assocNum: ' + tx_an)
                            logger.debug(local_site_name + ' id ' + local + ' --> ' + peer_site_name + ' id ' + peer +
                                ',\t' + local_site_name + ' TX Key :  sequenceNumber: ' + tx_seq + ',assocNum: ' + tx_an)
                            logger.debug(local_site_name + ' id ' + local + ' --> ' + peer_site_name + ' id ' + peer +
                                ',\t' + peer_site_name + ' RX Key :  sequenceNumber: ' + rx_seq + ',assocNum: ' + rx_an)

                        else:
                            syslog_message = local_site_name + ' id ' + local + ' --> ' + peer_site_name + ' id ' + peer +\
                                ' , keys are NOT sync, TX sequenceNumber ' + tx_seq + ' ,RX sequenceNumber: ' + rx_seq
                            logger.warning(syslog_message)
                            if syslog_server:
                                syslog(msg=syslog_message, server=syslog_server)
                            logger.debug(local_site_name + ' id ' + local + ' --> ' + peer_site_name + ' id ' + peer + ',\t'
                                    + local_site_name + ' TX Key Policy:  sequenceNumber: ' + tx_seq + ',\tassocNum: ' + tx_an)
                            logger.debug(local_site_name + ' \tid ' + local + ' --> ' + peer_site_name + ' id ' + peer +',\t'
                                    + peer_site_name + ' RX Key Policy:  sequenceNumber: ' + rx_seq + ',\tassocNum: ' + rx_an)
            else:
                logger.warning("Less than 2 sites have cloudsec policy found, not cross check found")
            if monitor_mode is not True:
                break
            else:
                time.sleep(interval)
                logger.info("")

    except KeyboardInterrupt as e:
        sys.exit("\Ctrl-c Pressed,Bye\n")
