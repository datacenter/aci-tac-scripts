#!/usr/bin/python

import subprocess, sys, traceback, logging, os
import time, re, json

# ensure check_output is available
if not hasattr(subprocess, "check_output"):
    m = """
    When executing from the APIC, you must use the python2.7 library:
        /usr/bin/python2.7 %s
    """ % __file__
    sys.exit(m)

# import natsorted if available
try: from natsort import natsorted
except: natsorted = sorted

logger = logging.getLogger(__name__)

OFFLINE_OBJECTS = [ "fabricNode", "fmcastTreeEp", "isisFmcastTree",
    "isisOifListLeaf", "isisOifListSpine", "isisAdjEp", "isisDom", 
    "l3extRsPathL3OutAtt", "lldpAdjEp", "topSystem"]
OFFLINE_FILES = {}
OFFLINE_MODE = False

###############################################################################
# lib functions
###############################################################################

def setup_logger(**kwargs):
    global logger
    logging_level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARN,
        "error": logging.ERROR,
        logging.DEBUG: logging.DEBUG,
        logging.INFO: logging.INFO,
        logging.WARN: logging.WARN,
        logging.ERROR: logging.ERROR
    }.get(kwargs.get("logging_level", logging.DEBUG), logging.DEBUG)
    logger.setLevel(logging_level)
    logger_handler = logging.StreamHandler(sys.stdout)

    fmt ="%(asctime)s.%(msecs).03d||%(levelname)s||"
    fmt+="(%(lineno)d)||%(message)s"
    logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%dT%H:%M:%S")
    )
    logger.addHandler(logger_handler)

    # remove previous handlers if present
    for h in list(logger.handlers): logger.removeHandler(h)
    logger.addHandler(logger_handler)


def offline_extract(tgz, **kwargs):
    """ 
    extract files in tar bundle to tmp directory.  Only files matching
    provided offline_keys dict (which is also used as key in returned dict)
    """
    offline_files = {}
    offline_dir = kwargs.get("offline_dir", "/tmp/")
    offline_keys = kwargs.get("offline_keys", {})
    import tarfile
    # force odir to real directory (incase 'file' is provided as offline_dir)
    odir = os.path.dirname(offline_dir)
    try:
        t = tarfile.open(tgz, "r:gz")
        for m in t.getmembers():
            # check for files matching offline_keys
            for tn in offline_keys:
                if "%s." % tn in m.name:
                    offline_files[tn] = "%s/%s" % (odir, m.name)
                    t.extract(m, path=odir)
                    logger.debug("extracting %s/%s" % (odir, m.name))
                    break

    except Exception as e:
        logger.error("Failed to extract content from offline tar file")
        import traceback
        traceback.print_exc()
        sys.exit()
    
    return offline_files

def get_cmd(cmd):
    """ return output of shell command, return None on error"""
    try:
        logger.debug("get_cmd: %s" % cmd)
        return subprocess.check_output(cmd, shell=True, 
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        logger.warn("error executing command: %s" % e)
        return None

def pretty_print(js):
    """ try to convert json to pretty-print format """
    try:
        return json.dumps(js, indent=4, separators=(",", ":"))
    except Exception as e:
        print(traceback.print_exc())
        return "%s" % js

def icurl(url, **kwargs):
    """ perform icurl for object/class based on relative dn and 
        return json object.  Returns None on error
    """    
    
    # default page size handler and timeouts
    page_size = kwargs.get("page_size", 75000)
    page = 0
    
    # build icurl command
    url_delim = "?"
    if "?" in url: url_delim="&"

    # walk through pages until return count is less than page_size
    results = []
    while 1:
        turl = "%s%spage-size=%s&page=%s" % (url, url_delim, page_size, page)
        logger.debug("icurl: %s" % turl)
        tstart = time.time()
        try:
            resp = get_cmd("icurl -s http://127.0.0.1:7777/%s" % turl)
        except Exception as e:
            logger.warn("exception occurred in get request: %s" % (
                traceback.format_exc()))
            return None
        logger.debug("response time: %f" % (time.time() - tstart))
        if resp is None:
            logger.warn("failed to get data: %s" % url)
            return None
        try:
            js = json.loads(resp)
            if "imdata" not in js or "totalCount" not in js:
                logger.error("failed to parse js reply: %s" % pretty_print(js))
                return None
            results+=js["imdata"]
            logger.debug("results count: %s/%s"%(len(results),js["totalCount"]))
            if len(js["imdata"])<page_size or \
                len(results)>=int(js["totalCount"]):
                logger.debug("all pages received")
                return results
            page+= 1
        except ValueError as e:
            logger.error("failed to decode resp: %s" % resp)
            return None
    return None

def get_dn(dn, **kwargs):
    # get a single dn
    opts = build_query_filters(**kwargs)
    url = "/api/mo/%s.json%s" % (dn,opts)
    results = icurl(url, **kwargs)
    if results is not None:
        if len(results)>0: return results[0]
        else: return {} # empty non-None object implies valid empty response
    return None

def get_class(classname, **kwargs):
    # perform class query

    # support offline for class query only for now
    if OFFLINE_MODE:
        if classname not in OFFLINE_FILES: 
            logger.error("%s not found in offline files" % classname)
            return None
        fname = OFFLINE_FILES[classname]
        try:
            logger.debug("reading file %s" % fname)
            with open(fname, "r") as f:
                js = json.loads(f.read())
                if "imdata" not in js or "totalCount" not in js:
                    logger.error("failed to parse js reply: %s" % (
                        pretty_print(js)))
                    return None
                return js["imdata"]
        except ValueError as e:
            logger.error("failed to decode resp: %s" % f.read())
        except Exception as e:
            logger.error("unabled to read %s: %s" % (fname,e))
            return None
    
    opts = build_query_filters(**kwargs)
    url = "/api/class/%s.json%s" % (classname, opts)
    return icurl(url, **kwargs)

def build_query_filters(**kwargs):
    """
        queryTarget=[children|subtree]
        targetSubtreeClass=[mo-class]
        queryTargetFilter=[filter]
        rspSubtree=[no|children|full]
        rspSubtreeInclude=[attr]
        rspPropInclude=[all|naming-only|config-explicit|config-all|oper]
    """
    queryTarget         = kwargs.get("queryTarget", None)
    targetSubtreeClass  = kwargs.get("targetSubtreeClass", None)
    queryTargetFilter   = kwargs.get("queryTargetFilter", None)
    rspSubtree          = kwargs.get("rspSubtree", None)
    rspSubtreeInclude   = kwargs.get("rspSubtreeInclude", None)
    rspPropInclude      = kwargs.get("rspPropInclude", None)
    opts = ""
    if queryTarget is not None:
        opts+= "&query-target=%s" % queryTarget
    if targetSubtreeClass is not None:
        opts+= "&target-subtree-class=%s" % targetSubtreeClass
    if queryTargetFilter is not None:
        opts+= "&query-target-filter=%s" % queryTargetFilter
    if rspSubtree is not None:
        opts+= "&rsp-subtree=%s" % rspSubtree
    if rspSubtreeInclude is not None:
        opts+= "&rsp-subtree-include=%s" % rspSubtreeInclude
    if rspPropInclude is not None:
        opts+= "&rsp-prop-include=%s" % rspPropInclude

    if len(opts)>0: opts = "?%s" % opts.strip("&")
    return opts

def ipv4_to_int(oipv4):
    """ convert ipv4 address to integer 
        return None on error
    """
    # strip prefix if present
    ipv4 = re.sub("/[0-9]+","",oipv4) 
    ipv4 = ipv4.split(".")
    if len(ipv4)!=4:
        logger.debug("invalid ipv4 address: %s" %oipv4)
        return None
    for x in xrange(0,4):
        ipv4[x] = int(ipv4[x])
        i = ipv4[x]
        if i<0 or i>255:
            logger.debug("invalid octect %s in %s" % (i, opiv4))
            return None
    return (ipv4[0]<<24) + (ipv4[1]<<16) + (ipv4[2]<<8) + ipv4[3]

def ipv4_to_str(ipv4):
    """ convert ipv4 integer to string """
    return "%s.%s.%s.%s" % (
        (ipv4 & 0xff000000) >> 24,
        (ipv4 & 0x00ff0000) >> 16,
        (ipv4 & 0x0000ff00) >> 8,
        (ipv4 & 0x000000ff)
    )
    
###############################################################################

class NodeFtag(object):
    """ track ftag root port and OIF on per-node basis """
    port_reg = re.compile("eth(?P<port>[0-9]+/[0-9]+)")
    def __init__(self, tree_id):
        self.tree_id = tree_id
        self.state = ""
        self.root_port = None
        self.oif = []

    def add_root_port(self, root_port):
        # add root port to this ftag.  
        # Return boolean success flag

        if root_port == "" or root_port == "unspecified":
            root_port = "unspecified"
        else:
            r1 = NodeFtag.port_reg.search(root_port)
            if r1 is not None: root_port = r1.group("port")
            else:
                logger.warn("failed to parse root port: %s" % root_port)
                return False

        if self.root_port is None: 
            self.root_port = root_port
        elif self.root_port != root_port:
            logger.warn("duplicate root port %s != %s on tree %s" % (
                self.root_port, root_port, self.tree_id))
            return False
        return True
            
    def add_oif_list(self, oif_list):
        # add one or more interfaces (excluding 'unspecified') to oif list
        for oif in oif_list:
            r1 = NodeFtag.port_reg.search(oif)
            if r1 is not None:
                if r1.group("port") not in self.oif:
                    self.oif.append(r1.group("port"))

    def __repr__(self):
        return "tree:%s(%s), root:%s, oif:%s" % (self.tree_id, self.state,
            self.root_port, "%s" % self.oif)
        
class NodeAdj(object):
    """ track lldp/isis adjacencies for node interface """
    def __init__(self):
        self.sideA = None
        self.sideB = None
        self.complete = False

    def add(self, local_node, local_port, remote_node, remote_port):
        # add an adjacency to this object
        side = {
                "local": {"node":local_node, "port": local_port},
                "remote": {"node":remote_node, "port": remote_port}
                }
        if self.sideA is None: self.sideA = side
        elif self.sideB is None: 
            self.sideB = side
            if self.sideA["local"]["node"] > self.sideB["local"]["node"]:
                t1 = self.sideA
                t2 = self.sideB
                self.sideA = t2
                self.sideB = t1
            if self.sideA["local"]["node"] != self.sideB["remote"]["node"] \
                or self.sideA["local"]["port"]!=self.sideB["remote"]["port"] \
                or self.sideB["local"]["node"]!=self.sideA["remote"]["node"] \
                or self.sideB["local"]["port"]!=self.sideA["remote"]["port"]:
                logger.warn("Invalid adj\n%s\n%s" % (pretty_print(self.sideA),
                    pretty_print(self.sideB)))
            else:
                self.complete = True
        else:   
            t = NodeAdj()
            t.add(local_node, local_port, remote_node, remote_port)
            logger.warn("can't add %s to existing adj %s" % (t, self))

    def get_remote_side(self, node_id):
        # for provided node_id, determine if it is local on sideA or sideB
        # and return the opposite site.  Return None if not found or not 
        # completed objet
        if not self.complete: 
            logger.warn("can't get remote adj for incomplete NodeAdj: %s"%self)
            return None
        if self.sideA["local"]["node"] == node_id:
            return self.sideB
        elif self.sideB["local"]["node"] == node_id:
            return self.sideA
        logger.warn("node_id %s not part of NodeAdj: %s" % (node_id, self))
        return None

    def __repr__(self):
        if self.sideA is None: return "[empty]"
        elif self.sideB is None: return "%s,%s (I)> %s,%s " % (
            self.sideA["local"]["node"], self.sideA["local"]["port"],
            self.sideA["remote"]["node"], self.sideA["remote"]["port"])
        else:
            if self.sideA["local"]["node"] != self.sideB["remote"]["node"] \
                or self.sideA["local"]["port"]!=self.sideB["remote"]["port"] \
                or self.sideB["local"]["node"]!=self.sideA["remote"]["node"] \
                or self.sideB["local"]["port"]!=self.sideA["remote"]["port"]:
                return "%s,%s (E)-> %s,%s" % (
                    self.sideA["local"]["node"], self.sideA["local"]["port"],
                    self.sideB["local"]["node"], self.sideB["local"]["port"])
            else:
                return "%s,%s -> %s,%s" % (
                    self.sideA["local"]["node"], self.sideA["local"]["port"],
                    self.sideB["local"]["node"], self.sideB["local"]["port"])

class LldpAdjEp(object):
    """ track lldp peer info """
    def __init__(self, lldp):
        # only grab what we care about for now
        self.mgmt_ip = lldp.get("mgmtIp", "")
        self.mgmt_port_mac = lldp.get("mgmtPortMac", "")
        self.chassis_id_type = lldp.get("chassisIdT", "")
        self.chassis_id = lldp.get("chassisIdV", "")
        self.port_type = lldp.get("portIdT", "")
        self.port = lldp.get("portIdV", "")
        self.port_vlan = lldp.get("portVlan", "")
        self.sys_name = lldp.get("sysName", "")
        self.sys_desc = lldp.get("sysDesc", "")

class Node(object):
    """ aci node """
    def __init__(self, **kwargs):
        self.node_id = kwargs.get("node_id", None)
        self.pod_id = kwargs.get("pod_id", None)
        self.address = kwargs.get("address", None)
        self.role = kwargs.get("role", None)
        self.name = kwargs.get("name", "")
        self.system_id = None
        self.lldp_adj = {}      # indexed by interface number
        self.isis_adj = {}      # indexed by interface number
        self.ftags = {}         # indexed by ftag number
        self.l3_ext_intfs = []  # spines external interfaces on overlay-1
        self.lldp_adj_ep = {}   # lldp info per local port (not necessarily a
                                # valid two-adjacency)

        # sanity, ensure all attributes are set
        assert self.node_id is not None
        assert self.pod_id is not None
        assert self.address is not None
        assert self.role is not None

    def add_external_interface(self, local_port):
        # add external interface filtering on spines role only
        if self.role != "spine": return
        if local_port not in self.l3_ext_intfs:     
            logger.debug("adding external interface %s: %s" % (self.node_id,
                local_port))
            self.l3_ext_intfs.append(local_port)

    def is_external_interface(self, local_port):
        # return true if interface is in l3_ext_intfs list
        return local_port in self.l3_ext_intfs

    def add_lldp_neighbor_info(self, local_port, lldp_adj_ep):
        # add lldp adjacency info to node
        if local_port not in self.lldp_adj_ep:
            self.lldp_adj_ep[local_port] = lldp_adj_ep

    def add_lldp_neighbor(self, local_port, adj):
        # add lldp adjacency to node
        if local_port not in self.lldp_adj:
            self.lldp_adj[local_port] = adj
        else:
            logger.warn("can't add second lldp adj to %s (curr:%s, new:%s)"%(
                self, self.lldp_adj[local_port], adj))

    def add_isis_neighbor(self, local_port, adj):
        # add isis adjacency to node
        if local_port not in self.isis_adj:
            self.isis_adj[local_port] = adj
        else:
            logger.warn("can't add second isis adj to %s (curr:%s, new:%s)"%(
                self, self.isis_adj[local_port], adj))

    def add_ftag_state(self, tree_id, state):
        # set ftag's operState
        if tree_id not in self.ftags: self.ftags[tree_id] = NodeFtag(tree_id)
        self.ftags[tree_id].state = state

    def add_ftag_root_port(self, tree_id, root_port):
        # add ftag root_port to tree
        if tree_id not in self.ftags: self.ftags[tree_id] = NodeFtag(tree_id)
        if not self.ftags[tree_id].add_root_port(root_port):
            logger.warn("failed to add root port %s on node %s tree %s"%(
                root_port, self, tree_id))

    def add_ftag_oif_list(self, tree_id, oif_list):
        # add oif list to ftag
        if tree_id not in self.ftags: self.ftags[tree_id] = NodeFtag(tree_id)
        self.ftags[tree_id].add_oif_list(oif_list)

    def walk_tree(self, nodes, tree_id, members, tree):
        # recursive function that walks provided ftag tree and returns
        # discovered list of nodes. 
        if tree_id not in self.ftags:
            logger.warn("unknown tree %s on %s" % (tree_id, self))
            return 
        if self.ftags[tree_id].state == "inactive":
            logger.warn("tree %s is inactive on %s" % (tree_id, self))
            return 
        tree["node"] = self.node_id
        if len(self.ftags[tree_id].oif)==0: return 
        for port in self.ftags[tree_id].oif:
            remote_node_id = "?"
            remote_port = "?"
            valid_oif = True
            is_external = False
            # verify adj exists for local port
            if port not in self.isis_adj or not self.isis_adj[port].complete:
                valid_oif = False
                # check if this is an external spine interface
                if self.is_external_interface(port):
                    logger.debug("oif for external port %s in tree %s of %s"%(
                        port, tree_id, self))
                    is_external = True
                else:
                    logger.warn("invalid isis adj on port %s in tree %s of %s"%(
                        port, tree_id, self))
            # should never happen since isis_adj built after successful lldp
            elif port not in self.lldp_adj or not self.lldp_adj[port].complete:
                logger.warn("invalid lldp adj on port %s in tree %s of %s"%s(
                    port, tree_id, self))
                valid_oif = False
            else:
                sideB = self.lldp_adj[port].get_remote_side(self.node_id)
                if sideB is None:
                    logger.warn("invalid link adj on port %s in tree %s of %s"%(
                        port, tree_id, self))
                    valid_oif = False
                else:
                    remote_node_id = sideB["local"]["node"]
                    remote_port = sideB["local"]["port"]
                    if remote_node_id not in nodes:
                        logger.warn("node %s not found in nodes"%remote_node_id)
                        logger.warn("invalid adj on port %s in tres %s of %s"%(
                            port, tree_id, self))
                        valid_oif = False
            
            # next checks only if oif is still valid
            remote_role = ""
            if valid_oif:
                remote_node = nodes[remote_node_id]
                remote_role = remote_node.role
                # validate neighbor on this link by verifying it has 
                # corresponding port in it's oif for this tree
                if tree_id not in remote_node.ftags or \
                    remote_port not in remote_node.ftags[tree_id].oif:
                    logger.warn("FTAG %s on pod %s invalid  (%s:%s-%s:%s) %s"%(
                        tree_id, self.pod_id, self.node_id,port,remote_node_id,
                        remote_port, "neighbor does not have port in OIF list"))
                    valid_oif = False
                # double check that the remote node is part of the same pod
                elif remote_node.pod_id != self.pod_id:
                    logger.warn("FTAG %s on pod %s invalid  (%s:%s-%s:%s) %s"%(
                        tree_id, self.pod_id,self.node_id,port,remote_node_id,
                        remote_port, "neighbor is not member of same pod"))
                    valid_oif = False


            subtree = {"node":None, "oif":[], "invalid_oif":[]}
            # if still valid, extend tree
            if valid_oif:
                # neighbor has been validated. don't recursive check if already
                # present in members list
                if remote_node_id not in members:
                    members.append(remote_node_id)
                    remote_node.walk_tree(nodes, tree_id, members, subtree)
                    tree["oif"].append({
                        "subtree":subtree,
                        "local_node": self.node_id,
                        "local_port": port,
                        "remote_port": remote_port,
                        "remote_node": remote_node_id,
                        "remote_role": remote_role,
                    })
            # add invalid link but do not continue walking subtree
            else:
                # for external interfaces, encode lldp info for remote
                # port and node if present
                if port in self.lldp_adj_ep and is_external:
                    lldp_info = self.lldp_adj_ep[port]
                    remote_port = lldp_info.port
                    remote_node_id = lldp_info.sys_name
                tree["invalid_oif"].append({
                    "subtree":subtree,
                    "local_node": self.node_id,
                    "local_port": port,
                    "remote_port": remote_port,
                    "remote_node": remote_node_id,
                    "is_external": is_external,
                    "remote_role": remote_role,
                })
            
    def __repr__(self):
        return "pod:%s,node:%s,addr:%s,sysid:%s"%(self.pod_id, self.node_id, 
            self.address, self.system_id)
        

def build_nodes():
    # build dict of nodes indexed by node_id with lldp/isis adjacencies
    # returns None on error
    nodes = {}

    # build info from topSystem
    fnodes = get_class("topSystem")
    if fnodes is None:
        logger.error("failed to get topSystem")
        return None 
    for obj in fnodes:
        if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]
            for a in ["role", "id", "podId", "state", "name", "address"]:
                if a not in attr:
                    logger.warn("object missing %s: %s" % (a, 
                        pretty_print(obj)))
                    continue
            if attr["role"] != "leaf" and attr["role"] != "spine":
                logger.debug("skipping %s with role %s"%(attr["id"],
                    attr["role"]))
                continue
            if attr["state"] != "in-service":
                logger.info("skipping analysis for %s node %s"%(
                    attr["state"],attr["id"]))
                continue
            if attr["id"] in nodes:
                logger.error("duplicate node id:%s,\n%s\n%s" % ( 
                    attr["id"], nodes[attr["id"]], pretty_print(obj)))
                continue
            nodes[attr["id"]] = Node(node_id=attr["id"],name=attr["name"],
                role=attr["role"],address=attr["address"],pod_id=attr["podId"])

    # add isis system_id from isisDom
    isisDom = get_class("isisDom")
    if isisDom is None:
        logger.error("failed to get isisDom")
        return None
    reg_node = re.compile("topology/pod-(?P<pod>[0-9]+)/node-(?P<node>[0-9]+)")
    for obj in isisDom:
        if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]
            for a in ["name","dn","sysId"]:
                if a not in attr:
                    logger.warn("object missing %s: %s" % (a, 
                        pretty_print(obj)))
                    continue
            if attr["name"] != "overlay-1":
                logger.debug("skipping isis %s != overlay-1 for %s" % (
                    attr["name"], pretty_print(obj)))
                continue
            r1 = reg_node.search(attr["dn"])
            if r1 is None:
                logger.warn("failed to parse dn for object: %s" % attr["dn"])
                continue
            node_id = r1.group("node")
            pod_id = r1.group("pod")
            if node_id not in nodes:
                logger.warn("skipping unknown node: %s, system-id:%s" % (
                    node_id, attr["sysId"]))
                continue
            nodes[node_id].system_id = attr["sysId"]

    # verify we have the system_id for all nodes, if not then we hit an issue
    for node_id in nodes:
        if nodes[node_id].system_id is None:
            logger.warn("system ID not found for node %s" % nodes[node_id])
            return None

    # add l3ext interfaces for spines
    l3extRsPathL3OutAtt = get_class("l3extRsPathL3OutAtt")
    if l3extRsPathL3OutAtt is None:
        logger.error("failed to get l3extRsPathL3OutAtt")
        l3extRsPathL3Out = []
    _r = "topology/pod-(?P<pod>[0-9]+)/paths-(?P<node>[0-9]+)"
    reg_port = re.compile("%s/pathep-\[eth(?P<port>[0-9]+/[0-9]+)\]" % _r)
    for obj in l3extRsPathL3OutAtt:
       if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]
            for a in ["dn", "encap", "addr", "tDn"]:
                if a not in attr:
                    logger.warn("object missing %s: %s" % (a, 
                        pretty_print(obj)))
                    continue
                r1 = reg_port.search(attr["tDn"])
            if r1 is None:  
                logger.debug("failed to parse dn for object: %s" % attr["dn"])
                continue
            node_id = r1.group("node")
            local_port = r1.group("port")
            if node_id not in nodes:
                logger.warn("skipping unknown node: %s" % node_id)
                continue
            nodes[node_id].add_external_interface(local_port)

    # get LLDP adjacency to build fabric graph
    lldpAdjEp = get_class("lldpAdjEp")
    if lldpAdjEp is None:
        logger.error("failed to get lldpAdjEp")
        return None
    _r = "topology/pod-(?P<pod>[0-9]+)/node-(?P<node>[0-9]+)"
    reg_port = re.compile("%s/sys/lldp/inst/if-\[eth(?P<port>[^\]]+)\]/"%_r)
    sub_reg_port = re.compile("eth(?P<port>[0-9]+/[0-9]+)", re.IGNORECASE)
    for obj in lldpAdjEp:
       if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]
            for a in ["dn", "sysDesc", "sysName", "portIdV"]: 
                if a not in attr:
                    logger.warn("object missing %s: %s" % (a, 
                        pretty_print(obj)))
                    continue
            r1 = reg_port.search(attr["dn"])
            if r1 is None:  
                logger.warn("failed to parse dn for object: %s" % attr["dn"])
                continue
            local_node_id = r1.group("node")
            local_pod_id = r1.group("pod")
            local_port = r1.group("port")
            if local_node_id not in nodes:
                logger.warn("skipping unknown node: %s" % local_node_id)
                continue
            nodes[local_node_id].add_lldp_neighbor_info(local_port, 
                                                            LldpAdjEp(attr))
            r2 = reg_node.search(attr["sysDesc"])
            if r2 is None:  
                # ok to fail to parse sysDesc, would imply neighbor is not ACI
                #logger.debug("skipping lldp neighbor (%s:%s) %s" % (
                #    local_node_id, local_port, attr["sysDesc"]))
                continue
            r3 = sub_reg_port.search(attr["portIdV"])
            if r3 is None:
                # skip non ethernet portIdV (i.e., apic ports)
                logger.debug("skipping lldp neight port (%s:%s)" % (
                    r2.group("node"), attr["portIdV"]))
                continue
            remote_node_id = r2.group("node")
            remote_pod_id = r2.group("pod")
            remote_port = r3.group("port")
            if remote_pod_id != local_pod_id:
                logger.warn("skipping connection local %s to remote %s" % (
                    "pod-%s:node-%s:if-%s" % (local_pod_id, local_node_id,
                        local_port),
                    "pod-%s:node-%s:if-%s" % (remote_pod_id, remote_node_id,
                        remote_port)))
                continue
            if remote_node_id not in nodes:
                logger.warn("skipping unknown pod-%s:node-%s:if-%s" % (
                    remote_pod_id, remote_node_id, remote_port))
                continue 
            logger.debug("neighbor local %s to remote %s" % (
                    "pod-%s:node-%s:if-%s" % (local_pod_id, local_node_id,
                        local_port),
                    "pod-%s:node-%s:if-%s" % (remote_pod_id, remote_node_id,
                        remote_port)))

            local_node = nodes[local_node_id]
            remote_node = nodes[remote_node_id]
            local_lldp_adj = None
            remote_lldp_adj = None
            if local_port in local_node.lldp_adj: 
                local_lldp_adj = local_node.lldp_adj[local_port]
            if remote_port in remote_node.lldp_adj:
                remote_lldp_adj = remote_node.lldp_adj[remote_port]
            if local_lldp_adj is None and remote_lldp_adj is None:
                # new adjacency - create only under local and set sideA
                lldp_adj = NodeAdj()
                lldp_adj.add(local_node_id, local_port, remote_node_id, 
                    remote_port)
                local_node.add_lldp_neighbor(local_port, lldp_adj)
                logger.debug("added sideA: %s" % lldp_adj)
            elif local_lldp_adj is None:
                # use existing adj from remote node and set sideB
                lldp_adj = remote_lldp_adj
                lldp_adj.add(local_node_id, local_port, remote_node_id, 
                    remote_port)
                local_node.add_lldp_neighbor(local_port, lldp_adj)
                logger.debug("added sideB: %s" % lldp_adj)
            else:
                logger.warn("unexpected duplicate adjacency for %s and %s" % (
                    local_lldp_adj, remote_lldp_adj))

    # walk through each lldp adj and ensure each lldp adj is complete
    for node_id in nodes:
        node = nodes[node_id]
        for port in node.lldp_adj:
            if not node.lldp_adj[port].complete:
                logger.error("incomplete adj: %s" % node.lldp_adj[port])
                return None

    # using the lldp adjacencies to map remote port id, build isis adjacencies
    isisAdjEp = get_class("isisAdjEp")
    _r = "topology/pod-(?P<pod>[0-9]+)/node-(?P<node>[0-9]+)/sys/isis"
    _r+="/inst-default/dom-overlay-1/if-\[eth(?P<port>[0-9]+/[0-9]+)[^\]+]"
    reg_isis_port = re.compile(_r)
    if isisAdjEp is None:
        logger.error("failed to get isisAdjEp")
        return None
    for obj in isisAdjEp:
       if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]
            for a in ["dn", "sysId", "operSt"]:
                if a not in attr:
                    logger.warn("object missing %s: %s" % (a, 
                        pretty_print(obj)))
                    continue
            r1 = reg_isis_port.search(attr["dn"])
            if r1 is None:  
                logger.warn("failed to parse dn for object: %s" % attr["dn"])
                continue
            local_node_id = r1.group("node")
            local_port = r1.group("port")
            if local_node_id not in nodes:
                logger.warn("skipping unknown node: %s, object:%s" % (
                    local_node_id, pretty_print(attr)))
                continue
            local_node = nodes[local_node_id]
            if attr["operSt"] != "up":
                logger.info("skipping isisAdj on %s port %s, operSt %s" % (
                    local_node, local_port, attr["operSt"]))
                continue
            if local_port not in local_node.lldp_adj:
                logger.warn("skipping isisAdj on %s port %s, no lldp adj\n%s"%(
                    local_node,local_port, attr))
                continue
            lldp_adj = local_node.lldp_adj[local_port]
            if lldp_adj.sideA["local"]["node"] == local_node_id:
                remote_node_id = lldp_adj.sideA["remote"]["node"]
                remote_port = lldp_adj.sideA["remote"]["port"]
            else:
                remote_node_id = lldp_adj.sideB["remote"]["node"]
                remote_port = lldp_adj.sideB["remote"]["port"]
            if remote_node_id not in nodes:
                logger.error("unknown remote_node_id: %s from lldpAdj %s" % (
                    remote_node_id, lldp_adj))
                return None
            remote_node = nodes[remote_node_id]

            # we have local node and port along with remote node and port from
            # lldp, ensure remote system-id matches sysId in isisAdjEp
            if attr["sysId"] != remote_node.system_id:
                logger.warn("sysId(%s) doesn't match lldp sysId(%s) from %s" % (
                    attr["sysId"], remote_node.system_id, lldp_adj))
                continue

            # add isis adj
            local_isis_adj = None
            remote_isis_adj = None
            if local_port in local_node.isis_adj: 
                local_isis_adj = local_node.isis_adj[local_port]
            if remote_port in remote_node.isis_adj:
                remote_isis_adj = remote_node.isis_adj[remote_port]
            if local_isis_adj is None and remote_isis_adj is None:
                # new adjacency - create only under local and set sideA
                isis_adj = NodeAdj()
                isis_adj.add(local_node.system_id, local_port, 
                    remote_node.system_id, remote_port)
                local_node.add_isis_neighbor(local_port, isis_adj)
                logger.debug("added sideA: %s" % isis_adj)
            elif local_isis_adj is None:
                # use existing adj from remote node and set sideB
                isis_adj = remote_isis_adj
                isis_adj.add(local_node.system_id, local_port, 
                    remote_node.system_id, remote_port)
                local_node.add_isis_neighbor(local_port, isis_adj)
                logger.debug("added sideB: %s" % isis_adj)
            else:
                logger.warn("unexpected duplicate adjacency for %s and %s" % (
                    local_isis_adj, remote_isis_adj))

    # walk through each isis adj and ensure each isis adj is complete
    for node_id in nodes:
        node = nodes[node_id]
        for port in node.isis_adj:
            if not node.isis_adj[port].complete:
                logger.error("incomplete adj: %s" % node.isis_adj[port])
                return None

    return nodes 

def build_ftags(nodes):
    # get list of ftags roots (per-pod) from apics and add to each node.  
    # add oif for each tree (including rootPort) for all nodes
    roots = {}  # indexed by pod-id and then tree

    # get apic's view of tree
    fmcastTreeEp = get_class("fmcastTreeEp")
    if fmcastTreeEp is None:
        logger.error("failed to get fmcastTreeEp")
        return None
    tree_reg = re.compile("treepol/node-(?P<node>[0-9]+)/tree-(?P<tree>[0-9]+)")
    for obj in fmcastTreeEp:
        if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]  
            if "dn" not in attr:
                logger.warn("object missing dn: %s" % (a,pretty_print(obj)))
                continue
            r1 = tree_reg.search(attr["dn"])
            if r1 is None:
                logger.warn("failed to parse dn for object: %s" % attr["dn"])
                continue
            node_id = r1.group("node")
            tree_id = r1.group("tree")
            if node_id not in nodes:
                logger.warn("skipping unknown node: %s, object:%s" % (
                    node_id, pretty_print(attr)))
                continue
            node = nodes[node_id]
            if node.pod_id not in roots: roots[node.pod_id] = {}    
            if tree_id not in roots[node.pod_id]:
                roots[node.pod_id][tree_id] = node_id
            elif node_id != roots[node.pod_id][tree_id]:
                logger.warn("duplicate root detected (%s!=%s tree %s)" % (
                    node_id, roots[node.pod_id][tree_id], tree_id))
                continue

    # get/update each node's view of the tree
    isisFmcastTree = get_class("isisFmcastTree")
    if isisFmcastTree is None:
        logger.error("failed to get isisFmcastTree")
        return None
    reg_node = re.compile("topology/pod-(?P<pod>[0-9]+)/node-(?P<node>[0-9]+)")
    for obj in isisFmcastTree:
        if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]  
            for a in ["dn", "root", "rootPort", "operSt", "id"]:
                if a not in attr:
                    logger.warn("object missing %s: %s" % (a, 
                        pretty_print(obj)))
                    continue
            r1 = reg_node.search(attr["dn"])
            if r1 is None:
                logger.warn("failed to parse dn for object: %s" % attr["dn"])
                continue
            node_id = r1.group("node")
            pod_id = r1.group("pod")
            tree_id = attr["id"]
            if node_id not in nodes:
                logger.warn("skipping unknown node: %s, object:%s" % (
                    node_id, pretty_print(attr)))
                continue
            node = nodes[node_id]
            # for the root itself, root port should be unspecified and 
            # root should point to local address OR can be 0.0.0.0 with operSt
            # set to active
            if attr["root"] == node.address or (attr["root"] == "0.0.0.0" and \
                attr["operSt"]=="active" and node.role=="spine"):
                logger.debug("%s claiming root for tree %s" % (node, tree_id))
                if attr["rootPort"]!="" and attr["rootPort"]!="unspecified":
                    # print warning but continue with operation
                    msg= "root %s for tree %s with bad rootPort:%s"%(
                        node, tree_id, attr["rootPort"])
                    msg+= ", expected 'unspecified'"
                    logger.debug(msg)   # debug only, sometimes expected
                if pod_id not in roots: roots[pod_id]= {}
                if tree_id not in roots[pod_id]: roots[pod_id][tree_id]=node_id
                elif roots[pod_id][tree_id] != node_id:
                    logger.warn("duplicate root detected (%s!=%s tree %s)"% (
                        node_id, roots[pod_id][tree_id], tree_id))

            node.add_ftag_root_port(tree_id, attr["rootPort"])
            node.add_ftag_state(tree_id, attr["operSt"])

    isisOifListLeaf = get_class("isisOifListLeaf")
    isisOifListSpine = get_class("isisOifListSpine")
    if isisOifListLeaf is None or isisOifListSpine is None:
        logger.error("failed to get isisOifList for leaf/spine")
        return None
   
    _r = "topology/pod-(?P<pod>[0-9]+)/node-(?P<node>[0-9]+)/"
    _r+= "sys/isis/inst-default/dom-overlay-1/fmtree-(?P<tree>[0-9]+)/"
    reg_oif_list = re.compile(_r)
    for obj in isisOifListLeaf+isisOifListSpine:
        if "attributes" in obj[list(obj.keys())[0]]:
            attr = obj[list(obj.keys())[0]]["attributes"]  
            for a in ["dn", "oifList"]:
                if a not in attr:
                    logger.warn("object missing %s: %s" % (a, 
                        pretty_print(obj)))
                    continue
            r1 = reg_oif_list.search(attr["dn"])
            if r1 is None:
                # dn's will fail to parse if they are GiPo instead of ftags
                #logger.debug("failed to parse dn for object: %s" % attr["dn"])
                continue
            node_id = r1.group("node")
            tree_id = r1.group("tree")
            if node_id not in nodes:
                logger.warn("skipping unknown node: %s, object:%s" % (
                    node_id, pretty_print(attr)))
                continue
            node = nodes[node_id]
            node.add_ftag_oif_list(tree_id, attr["oifList"].split(","))

    return roots

def get_tree_str(tree, root=None, combine_rows=True):
    # receive tree built from walk_tree and print in user-friendly format
    # tree in format:
    #   "node": "",
    #   "oif": [{
    #       "remote_role": "spine|leaf" or empty
    #       "remote_node":"", "remote_port":"", "local_node":"",
    #       "local_port":"", "subtree":{}
    #   }],
    #   "invalid_oif": [{
    #       "remote_role":"spine|leaf" or empty
    #       "remote_node":"", "remote_port":"", "local_node":"",
    #       "local_port":"", "subtree":{},  <-- subtree should always be empty
    #       "is_external":bool (True for external spine interfaces)
    #   }],

    rows = []
    if combine_rows is True:
        # on first non-recursive call, add top node to first row
        role = "node"
        if root is not None: role = root.role
        rows.append("%s-%s" % (role, tree["node"]))
    if len(tree["oif"])>0 or len(tree["invalid_oif"])>0:
        oif_count = 0
        # valid oifs
        for oif in sorted(tree["oif"], key=lambda k: int(k["remote_node"])):
            oif_count+=1
            pad_len = 15 - len(oif["local_port"]) - len(oif["remote_port"])
            if pad_len < 0: pad_len = 0
            role = oif.get("remote_role", "node")
            rows.append("  +- %s %s %s %s-%s" % (
                oif["local_port"],
                "-"*pad_len,
                oif["remote_port"],
                role,
                oif["remote_node"]
                ))
            subtree_rows = get_tree_str(oif["subtree"], combine_rows=False)
            if len(subtree_rows)>0:
                if oif_count < len(tree["oif"]): 
                    for r in subtree_rows: rows.append("  |%s%s" % (" "*20, r))
                    rows.append("  |")
                else:
                    for r in subtree_rows: rows.append("   %s%s" % (" "*20, r))
        # invalid oifs
        oif_count = 0
        for oif in sorted(tree["invalid_oif"], key=lambda k: k["remote_node"]):
            oif_count+=1
            if oif["is_external"]:
                pad_len = 10 - len(oif["local_port"]) 
                if pad_len < 0: pad_len = 0
                node_str = "%s %s" % (oif["remote_port"], oif["remote_node"])
                node_str = "(EXT) %s" % node_str
                pad_char = "."
            else:
                pad_len = 15 - len(oif["local_port"]) - len(oif["remote_port"])
                if pad_len < 0: pad_len = 0
                pad_char = "x"
                node_str = "%s %s-%s"%(
                    oif["remote_port"],
                    oif.get("remote_role", "node"),
                    oif["remote_node"]
                )
            rows.append("  +- %s %s %s" % (
                oif["local_port"],
                pad_char*pad_len,
                node_str,
                ))
            
       
    if combine_rows:
        return "\n".join(rows)
    else:
        return rows 
        

def main(args):

    # build lists of nodes, then add adjacencies to build graph
    nodes = build_nodes()
    if nodes is None:
        logger.error("failed to build nodes")
        return    
    roots = build_ftags(nodes)
    if roots is None:
        logger.error("failed to build ftags/roots")
        return

    # first check that provided pod exists
    if args.pod is not None and "%s"%args.pod not in roots:
        print("Pod %s not found" % args.pod)
        return 

    # for each pod and each ftag, need to walk full tree and ensure that
    # we're able to hit every node in the fabric that's in the pod AND
    # for each link - neighbor has link in it's OIF 
    for pod_id in natsorted(roots.keys()):
        if args.pod is not None and int(pod_id) != args.pod:
            logger.debug("skipping pod %s" % pod_id)
            continue
        
        tree_ids = [int(t) for t in roots[pod_id].keys()]

        # first check that provided ftag exists in pod
        if args.ftag is not None and args.ftag not in tree_ids:
            print("Pod %s FTAG %s not found" % (pod_id, args.ftag))
            continue
        for tree_id in sorted(tree_ids):
            if args.ftag is not None and tree_id != args.ftag:
                logger.debug("skipping ftag %s" % tree_id)
                continue
            # start at the root and work our way through the tree
            tree_id = "%s" % tree_id
            root_node_id = roots[pod_id][tree_id]
            if root_node_id not in nodes:
                logger.error("unknown root node id %s for pod %s tree %s" % (
                    root_node_id, pod_id, tree_id))
                continue
            root_node = nodes[root_node_id]
            if tree_id not in root_node.ftags:
                logger.error("unknown tree %s for root node %s"%(tree_id,
                    root_node))
                continue
            # if it's inactive on the root then don't analyze
            if root_node.ftags[tree_id].state == "inactive":
                logger.info("skipping analysis for pod %s inactive tree %s"%(
                    pod_id, tree_id))
                continue
            # ensure this node is part of the pod we're checking
            if root_node.pod_id != pod_id:
                logger.warn("skipping invalid pod %s on node %s for tree %s"%(
                    pod_id, root_node, tree_id))
                continue
            
            member_nodes = [root_node_id] 
            tree = {"node":None, "oif":[], "invalid_oif":[]}
            root_node.walk_tree(nodes, tree_id, member_nodes, tree)
  
            # check member_nodes and ensure that all nodes in the pod where
            # discovered on the tree
            missing_nodes = []
            active_nodes = 0
            for node_id in nodes:
                node = nodes[node_id]
                if node.pod_id != pod_id: continue
                active_nodes+= 1
                if node_id not in member_nodes:
                    missing_nodes.append(node_id)

            print("\n")
            print("#"*80)
            print("#  Pod %s FTAG %s" % (pod_id, tree_id))
            print("#  Root %s-%s" % (root_node.role, root_node.node_id))
            print("#  active nodes: %s, inactive nodes: %s" % (
                active_nodes-len(missing_nodes), len(missing_nodes)))
            print("#"*80)
            print(get_tree_str(tree, root=root_node)) 
            print("\n")

            if len(missing_nodes)>0:
                msg = ["  %s node(s) unreachable on tree"%(len(missing_nodes))]
                msg.append("\tNodes isolated from root")
                for m_id in missing_nodes:
                    if m_id not in nodes: msg.append("\t\tnode-id: %s" % m_id)
                    msg.append("\t\t%s" % nodes[m_id])
                print("\n".join(msg))
            else:
                print("Pod %s FTAG %s: all nodes reachable on tree" % (
                    pod_id, tree_id))
     


if __name__ == "__main__":

    import argparse
    desc = """
    Check the FTAG topology in an ACI fabric
    """

    offlineHelp="""
    Use this option when executing the script on offline data. 
    If not set, this script assumes it is executing on a live 
    system and will query objects directly.
    """

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--debug", action="store", help="debug level",
        dest="debug", default="info", choices=["debug","info","warn","error"])
    parser.add_argument("--offline", action="store", dest="offline",
        help=offlineHelp, default=None)
    parser.add_argument("--offlineHelp", action="store_true", dest="ohelp",
        help="print further offline help instructions")
    parser.add_argument("--ftag", action="store", dest="ftag",
        help="tree/ftag to verify (default all)", type=int, default=None)
    parser.add_argument("--pod", action="store", dest="pod",
        help="pod to verify (default all)", type=int, default=None)
    args = parser.parse_args()
    setup_logger(logging_level=args.debug)



    #offline-help
    if args.ohelp:
        cmds = []
        for o in OFFLINE_OBJECTS:
            c = "icurl http://127.0.0.1:7777/api/class/%s.json " % o
            c+= " > /tmp/off_%s.json" % o
            cmds.append(c)

        offlineOptionDesc="""
  Offline mode expects a .tgz file.  For example:
  %s --offline ./offline_data.tgz

  When executing in offline mode, ensure that all required data is present in
  input tar file. For best results, collect information for all tables using
  the filenames used below. Once all commands have completed, the final tar 
  file can be found at:
    /tmp/offline_data.tgz

  bash -c '
   %s
  rm /tmp/offline_data.tgz
  tar -zcvf /tmp/offline_data.tgz /tmp/off_*
  rm /tmp/off_*
  '""" % (__file__, "\n   ".join(cmds))
        print(offlineOptionDesc)
        sys.exit()

    else:
        if args.offline: 
            OFFLINE_MODE = True
            OFFLINE_FILES = offline_extract(args.offline, 
                offline_keys=OFFLINE_OBJECTS)
        elif get_dn("/uni") is None:
                msg = "\nError: Trying to execute on an unsupported device. "
                msg = "This script is intended to run on the apic or on"
                msg+= " offline data.  Use -h for help.\n"
                sys.exit(msg)
       
    # execute main function
    main(args)
