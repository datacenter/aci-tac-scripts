#!/opt/cisco/system-venv3/bin/python3

import sys
version = f'''{sys.version_info[0]}.{sys.version_info[1]}'''
dirs = [f'/opt/cisco/system-venv3/lib64/python{version}/site-packages', f'/opt/cisco/system-venv3/lib/python{version}/site-packages']
sys.path = sys.path + dirs
import os, re, json
import socket, paramiko
import concurrent.futures
import logging
import getpass
import subprocess
import shlex

#Not actually needed but it can be used if ishell python path causes issues with any needed packages
#regex = re.compile(r'^\/controller\/yaci.*')
#full = sys.path
#sys.path = [i for i in full if not regex.match(i)]

#Also not needed, but if a newer version of a package that already exists in apic libraries exists,
#this code can be used to prepend the desired package dir to sys.path so it gets preference
#cwd = os.getcwd() + '/'
#newPath = []
#newPath.append(cwd + "paramiko-3.1.0")
#sys.path = newPath + sys.path

def setup_logger(logger, level):
    logging_level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
    }.get(level, logging.DEBUG)
    logger.setLevel(logging_level)
    logger_handler = logging.StreamHandler(sys.stdout)
    fmt ="%(asctime)s.%(msecs).03d||%(levelname)s||"
    fmt+="%(message)s"
    logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%dT%H:%M:%S")
    )
    logger.addHandler(logger_handler)
    # remove previous handlers if present
    for h in list(logger.handlers): logger.removeHandler(h)
    logger.addHandler(logger_handler)

logger = logging.getLogger(__name__)
setup_logger(logger, "debug")

def handle_api_rsp(rsp):
    if rsp['totalCount'] == '0':
        error_string = 'Object was not found'
    elif 'error' in rsp['imdata'][0].keys():
        error_string = rsp['imdata'][0]['error']['attributes']['text']
    else:
        error_string = ''
    return error_string

def run_ssh_commands(self_ip, host, command_list, username, password):
    cmd_result = {}
    host_result = {}
    sockoroo = socket.socket()
    sockoroo.bind((self_ip, 0))
    sockoroo.connect((host, 22))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=username, password=password, look_for_keys=False, allow_agent=False, sock=sockoroo)
        for c in command_list:
            stdin, stdout, stderr = ssh.exec_command(c)
            cmd_result[c] = stdout.read().decode()
        host_result[host] = cmd_result
        #print(host_result)
    except Exception as e:
        logger.warning(e)
        cmd_result['CONNECTION'] = 'FAILED'
        host_result[host] = cmd_result

    ssh.close()
    return host_result

def ssh_conn(self_ip, uname, pswd, host_list, command_list):
    futures = []
    cmd_results = {}
    #command_list = ['date', 'vsh -c "show version"', 'ls -al /bootflash', 'vsh_lc -c "show platform internal hal l2 port gpd"']
    #command_list = ['echo $HOSTNAME']
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        for host in host_list:
            futures.append(executor.submit(run_ssh_commands, self_ip, host, command_list, uname, pswd))
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            cmd_results.update(result)

    return(cmd_results)

def get_obj_count(url):
    count_url = url + """&rsp-subtree-include=count' 2>/dev/null"""
    #get object count to verify query only returns one object
    try:
        count = json.loads(os.popen(count_url).read())['imdata'][0]['moCount']['attributes']['count']
    except Exception as e:
        logger.warning("URL is invalid")

    return count

def query_class(obj_class, obj_query=None):
    if obj_query is None:
        url = """icurl 'http://localhost:7777/api/class/""" + obj_class + """.json?"""
    else:
        url = """icurl 'http://localhost:7777/api/class/""" + obj_class + """.json?""" + obj_query

    class_url = url + """' 2>/dev/null"""

    try:
        class_query_result = json.loads(os.popen(class_url).read())
        return class_query_result
    except Exception as e:
        logger.warning(e)
        logger.warning("Couldn't query class.")

def query_dn(obj_dn, obj_query=None):
    if obj_query is None:
        url = """icurl 'http://localhost:7777/api/mo/""" + obj_dn + """.json?"""
    else:
        url = """icurl 'http://localhost:7777/api/mo/""" + obj_dn  + """.json?""" + obj_query

    dn_url = url + """' 2>/dev/null"""

    try:
        dn_query_result = json.loads(os.popen(dn_url).read())
        return dn_query_result
    except Exception as e:
        logger.warning(e)
        logger.warning("Couldn't query class.")

#Returns specific attribute from specific object. The query itself must return object count 1 in order for this def to be used.
def get_attribute(attribute, obj_class=None, obj_dn=None, obj_query=None):
    if (obj_class is not None and obj_dn is not None) or (obj_class is None and obj_dn is None):
        raise Exception("get_attribute requires either an obj_class or obj_dn. Not both or neither.")

    if obj_class is not None and obj_dn is None:
        if obj_query is None:
            url = """icurl 'http://localhost:7777/api/class/""" + obj_class + """.json?"""
        else:
            url = """icurl 'http://localhost:7777/api/class/""" + obj_class + """.json?""" + obj_query
    
    if obj_dn is not None and obj_class is None:
        if obj_query is None:
            url = """icurl 'http://localhost:7777/api/mo/""" + obj_dn + """.json?"""
        else:
            url = """icurl 'http://localhost:7777/api/mo/""" + obj_dn  + """.json?""" + obj_query

    #get object count to verify query only returns one object
    if url is not None:
        count = get_obj_count(url)
    else:
        raise Exception("No valid url for query.")

    if count == "1":
        att_url = url + """' 2>/dev/null"""
        try:
            attr_value = json.loads(os.popen(att_url).read())['imdata'][0]
            #If obj_class wasn't provided, need to figure out the class of the dn for the purpose of json parsing
            for k, v in attr_value.items():
                klass = k
                break
            attr_value = json.loads(os.popen(att_url).read())['imdata'][0][klass]['attributes'][attribute]
            return attr_value
        except Exception as e:
            logger.warning("Could not get attribute " + attribute)
    elif count == "0":
        logger.warning("No matching objects were found.")
    else:
        logger.warning("Query returned more than one object. get_attribute requires the query to only return one object.")

def get_fab_details():
    #self ip used for ssh socket
    myTopSys = json.loads(os.popen('''icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.name,"'"$HOSTNAME"'")' 2>/dev/null''').read())
    self_ip   = myTopSys['imdata'][0]['topSystem']['attributes']['address']
    self_node = myTopSys['imdata'][0]['topSystem']['attributes']['id']
    
    ver_dic = {}
    rsp = query_class('topSystem')
    for node in rsp['imdata']:
        n = node['topSystem']['attributes']['dn']
        n = ''.join(re.findall(r"^.*pod\-[0-9]\/node\-[0-9]+", n))
        n = ''.join(re.findall(r"[0-9]+$", n))
        try:
            v = node['topSystem']['attributes']['version']
            ver_dic[n] = v
        except:
            ver_dic[n] = ''
        
        myTopSys = json.loads(os.popen('''icurl 'http://localhost:7777/api/class/topSystem.json?query-target-filter=eq(topSystem.name,"'"$HOSTNAME"'")' 2>/dev/null''').read())
        myAddr   = myTopSys['imdata'][0]['topSystem']['attributes']['address']
    
    return ver_dic, self_ip, self_node

def get_password():
    password = getpass.getpass(prompt='Enter password used for remote connections: ')
    return password

def ftriage(uname, ileaf_list, src_ip, dst_ip):
    ileafs = ','.join(ileaf_list)
    ftriage_cmd = f'''ftriage -user {uname} route -ii LEAF:{ileafs} -dip {dst_ip} -sip {src_ip}'''
    ftriage_cmd = shlex.split(ftriage_cmd)
    subprocess.run(ftriage_cmd)
