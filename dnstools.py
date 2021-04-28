#!/usr/local/bin/python3.9
# -*- coding: UTF-8 -*

import os
import requests
import urllib3
import base64
import random
import pexpect
import getpass
import json
import time
import string
from configparser import ConfigParser

urllib3.disable_warnings()


config = ConfigParser()
config.read('dnstest.conf', encoding='UTF8')
client_ip = config['server']['client_ip']
server_ip = config['server']['server_ip']
client_ipv6 = config['server']['client_ipv6']
server_ipv6 = config['server']['server_ipv6']
root_passwd = config['server']['server_root_passwd']
view_num = int(config['data']['view_number'])
zone_num = int(config['data']['zone_number_perview'])
rrs_num = int(config['data']['rrs_number_perzone'])
label = int(config['data']['label_number'])
cname_num = int(config['data']['cname_number'])
acl_addr = int(config['data']['acl_addr_perview'])
rrs_limit_num = int(config['data']['domain_limit_number'])
ip_limit_num = int(config['data']['ip_limit_number'])
policy_num = int(config['data']['localpolicy_number'])
qps_num = int(config['data']['qps_base'])
match_view = config['perf_params']['match_view'].split(',')
test_type =  config['perf_params']['test_type']
batch_add = int(config['interface']['batch_add'])
add = int(config['interface']['add_by_one'])
rrs_base = int(config['interface']['rrs_base'])
qps_base = int(config['interface']['qps_base'])
domainlimit_end = 'domainlimit_tmp'
iplimit_end = '192.168.1.1'
localdata_end = 'localdata_tmp'

class QpsPerformanceTools:
    def __init__(self, client_ip, server_ip, client_ipv6, server_ipv6, root_passwd, view_num, zone_num, rrs_num, label, cname_num, acl_addr, rrs_limit_num, ip_limit_num, policy_num, qps_num, match_view, test_type):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_ipv6 = client_ipv6
        self.server_ipv6 = server_ipv6
        self.root_passwd = root_passwd
        self.view_num = view_num
        self.zone_num = zone_num
        self.rrs_num = rrs_num
        self.label = label
        self.cname_num = cname_num
        self.acl_addr = acl_addr
        self.rrs_limit_num = rrs_limit_num
        self.ip_limit_num = ip_limit_num
        self.policy_num = policy_num
        self.qps_num = qps_num
        self.match_view = match_view
        self.test_type = test_type
        self.domain = {}
        self.cname_domain = []
        
    def countNum(self, model, num=1, total=1, opt=''):
        info = "=====" + opt + ' add ' + model + str(num) + '...' + "===="
        print(info, end = '')
        if num != total:
            print("\b" * (len(info) * 2), end = "",flush=True)
        else:
            print('')

    def datacenterAdd(self):
        print("begin add datacenter...")
        url = 'https://%s:20120/dc' % self.server_ip
        data = {
            "name": ''.join(random.sample(string.ascii_letters,6)).lower(),
            "devices": ["local.master"],
            "synserver": "local.master"
        }
        r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "id" in response:
            if response["id"] == data["name"]:
                return data["name"]
        else:
            return response
        self.countNum('datacenter ')

    def datacenterDel(self):
        print("begain delete datacenter...")
        self.idslist = []
        url = 'https://%s:20120/dc' % self.server_ip
        data = {}
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    self.idslist.append(ids["id"])
                data = {
                    "ids": self.idslist,
                    "current_user": "admin"
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def memberAdd(self):
        print("begin add dc member...")
        self.dc_name = self.datacenterAdd()
        url = 'https://%s:20120/dc/%s/gmember' % (self.server_ip, self.dc_name)
        data = {
            "gmember_name": ''.join(random.sample(string.ascii_letters,5)).lower(),
            "ip": "%d.%d.%d.%d" % (random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255)),
            "port": "80",
            "linkid": "",
            "enable": "yes"
        }
        r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        self.add_rrs_ip = data["ip"]
        if "id" in response:
            if response["id"] == data["gmember_name"]:
                return data["gmember_name"]
        else:
            return response
        time.sleep(0.2)
        self.countNum('dc member ')

    def syncgroup(self):
        print("begin add sync group...")
        self.gmember = self.memberAdd()
        url = 'https://%s:20120/syngroup' % self.server_ip
        data = {
            "name": ''.join(random.sample(string.ascii_letters,5)).lower(),
            "dcs": self.dc_name
        }
        r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "id" in response:
            if response["id"] == data["name"]:
                return data["name"]
        else:
            return response
        time.sleep(0.2)
        self.countNum('sync group ')

    def syncgroupDel(self):
        print("begin delete sync group...")
        self.syncgrouplist = []
        url = 'https://%s:20120/syngroup' % self.server_ip
        data = {
            "current_user": "admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    self.syncgrouplist.append(ids["id"])
                data = {
                    "ids": self.syncgrouplist
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def pool(self):
        print("begin add addrpool...")
        self.group = self.syncgroup()
        url = 'https://%s:20120/gpool' % self.server_ip
        data = {
            "name": ''.join(random.sample(string.ascii_letters,5)).lower(),
            "ttl": "86400",
            "type": "A/AAAA",
            "max_addr_ret": "1",
            "hms": [],
            "warning": "yes",
            "first_algorithm": "rr",
            "second_algorithm": "none",
            "enable": "yes",
            "gmember_list": [{"dc_name": self.dc_name, "gmember_name": self.gmember, "ratio": "1"}]
        }
        r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "id" in response:
            if response["id"] == data["name"]:
                return data["name"]
        else:
            return response
        time.sleep(0.2)
        self.countNum('addrpool ')

    def poolDel(self):
        print("begin delete addrpool...")
        self.poollist = []
        url = 'https://%s:20120/gpool' % self.server_ip
        data = {
            "current_user": "admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    self.poollist.append(ids["id"])
                data = {
                    "ids": self.poollist,
                    "current_user": "admin"
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def addzoneAdd(self):
        print("begin add zone(add)...")
        self.addzone = []
        self.addrpool = self.pool()
        url = 'https://%s:20120/views/ADD/dzone' % self.server_ip
        for addzone in range(self.zone_num):
            data = {
                "name": "addzone%d." % addzone,
                "syngroup": self.group
            }
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response = json.loads(r.text)
            if "id" in response:
                if response["id"] == data["name"]:
                    self.addzone.append(data["name"])
            else:
                return response
            time.sleep(0.2)
            self.countNum('zone(add) ', (addzone + 1), self.zone_num)

    def addzoneDel(self):
        print("begin delete zone(add)...")
        self.adds = 1
        url = 'https://%s:20120/views' % self.server_ip
        data = {
            "with_add": "yes",
            "current_user":"admin"
        } 
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        for view in response["resources"]:
            if view["id"] == "ADD":
                break
            else:
                self.adds = 0
                return self.adds
        self.addzonelist = []
        url = 'https://%s:20120/views/ADD/dzone' % self.server_ip
        data = {
            "current_user": "admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    self.addzonelist.append(ids["id"])
                data = {
                    "ids": self.addzonelist,
                    "current_user": "admin"
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def addrrsAdd(self):
        print("begin add rrs(add)...")
        self.rrs_qname = ''
        resource_content = []
        self.addzones = self.addzoneAdd()
        if self.label > 2:
            for label in range(self.label - 2):
                self.rrs_qname = self.rrs_qname + 'label%d.' % (label + 1)
        else:
            self.rrs_qname = ''
        self.rrs_qname = self.rrs_qname + 'gslb'
        for zones in self.addzone:
            for rrs in range(self.rrs_num):
                url = 'https://%s:20120/views/ADD/dzone/%s/gmap' % (self.server_ip, zones)
                self.domain["add"] = "%s%d.%s 3600 IN A %s" % (self.rrs_qname, (self.rrs_num - 1), self.addzone[-1], self.add_rrs_ip)
                resource_content.append({"name": "%s%d.%s" % (self.rrs_qname, rrs, zones),"algorithm": "rr","gpool_list": [{"gpool_name": self.addrpool, "ratio":"1"}],"last_resort_pool": "","persist_enable": "","persist_time": 60,"enable": "yes"})
            data = {
                "resource_content": resource_content
            }
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response = json.loads(r.text)
            if "resource_content" in response:
                pass
            else:
                return response
            resource_content = []
            time.sleep(0.2)
            self.countNum('rrs(%s) ' % zones, (zones + 1), len(self.addzone))

    def aclAdd(self):
        print("begin add acl...")
        acllist = []
        for acl in range(self.acl_addr):
            acllist.append('%s.%s.%s.%s' % (random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255)))
        url = 'https://%s:20120/acls' % self.server_ip
        data = {
            "name": "acl",
            "networks": acllist,
            "time_strategies": [],
            "exclude_time_strategies": []
        }
        for times in range(2):
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response = json.loads(r.text)
            if "id" in response:
                if response["id"] == data["name"]:
                    data["name"] = "match_acl"
                    acllist[self.acl_addr - 1] = self.client_ip
                    if self.client_ipv6 != '':
                        acllist[self.acl_addr - 2] = self.client_ipv6
                    data["networks"] = acllist
            else:
                return response
            time.sleep(0.2)

    def aclDel(self):
        print("begin delete acl...")
        acldellist = []
        url = 'https://%s:20120/acls' % self.server_ip
        data = {
            "current_user": "admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    acldellist.append(ids["id"])
                data = {
                    "ids": acldellist,
                    "current_user": "admin"
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def viewAdd(self, acls):
        print("begin add view...")
        self.viewlist = []
        for view in range(self.view_num):
            url = 'https://%s:20120/views' % self.server_ip
            data = {
                "name": "view%d" % view,
                "owners": ["local.master"],
                "filter_aaaa": "no",
                "recursion_enable": "yes",
                "non_recursive_acls": [],
                "bind_ips": ["0.0.0.0"],
                "fail_forwarder": "",
                "dns64s": [],
                "need_tsig_key": "no",
                "acls": acls,
                "black_acls": [],
                "filter_aaaa_ips": ["any"],
                "try_final_after_forward": "no",
                "limit_ips": [],
                "current_user":"admin"
            }
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response = json.loads(r.text)
            if "id" in response:
                if response["id"] == data["name"]:
                    self.viewlist.append(data["name"])
            else:
                return response
            time.sleep(0.2)
            self.countNum('view ', (view + 1), self.view_num)
        self.viewlist.append('default')

    def viewDel(self):
        print("begin delete view...")
        viewdellist = []
        url = 'https://%s:20120/views' % self.server_ip
        data = {
            "current_user":"admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    viewdellist.append(ids["id"])
                viewdellist.remove("default")
                data = {
                    "ids": viewdellist,
                    "current_user":"admin"
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def viewEdit(self, viewname, acls):
        print("begin edit view...")
        url = 'https://%s:20120/views' % self.server_ip
        data = {
            "ids": [viewname],
            "acls": [acls],
            "current_user":"admin"
        }
        r = requests.put(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "id" in response:
             if response["id"] == data["ids"][0]:
                pass
        else:
            return response

    def zoneAdd(self):
        print("begin add zone...")
        self.zonelist = []
        for view in self.viewlist:
            for zone in range(self.zone_num):
                url = 'https://%s:20120/views/%s/zones' % (self.server_ip, view)
                data = {
                    "name":"com%d" % zone,
                    "owners": ["local.master"],
                    "server_type": "master",
                    "default_ttl": "3600",
                    "slaves":[],
                    "ad_controller": [],
                    "current_user": "admin"
                }
                r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "id" in response:
                    if response["id"] == data["name"]:
                        if data["name"] not in self.zonelist:
                            self.zonelist.append(data["name"])
                else:
                    return response
                time.sleep(0.2)
                self.countNum('zone ', (zone + 1), self.zone_num, view)

    def zoneDel(self):
        print("begin delete zone...")
        zonedellist = []
        url = 'https://%s:20120/views/default/zones' % self.server_ip
        data = {
            "current_user":"admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    zonedellist.append(ids["id"])
                data = {
                    "ids": zonedellist,
                    "current_user": "admin"
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response = json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def rrsAdd(self):
        print("begin add rrs...")
        self.qname = ''
        if self.label > 2:
            for label in range(self.label - 2):
                self.qname = self.qname + 'label%d.' % (label + 1)
        else:
            self.qname = ''
        self.qname = self.qname + 'rr'
        zone_content = ''
        for view in self.viewlist:
            count = 0
            for zone in self.zonelist:
                for rrs in range(self.rrs_num):
                    tmp = '%s%d.%s. 3600 IN A %d.%d.%d.%d\n' % (self.qname, rrs, zone, random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255))
                    zone_content = zone_content + tmp
                    if zone == self.zonelist[-1] and rrs == self.rrs_num - 1:
                        self.domain[view] = tmp
                url = 'https://%s:20120/views/%s/zones/%s/rrs' % (self.server_ip, view, zone)
                data = {
                    "zone_content": str(base64.b64encode(zone_content.encode("utf-8")), encoding='utf-8'),
                    "is_enable": "yes",
                    "current_user": "admin"
                }
                r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                zone_content = ''
                response =  json.loads(r.text)
                if response == []:
                    pass
                else:
                    return response
                time.sleep(0.2)
                count += 1
                self.countNum('rrs in com', count, len(self.zonelist), '%s' % view)

    def cnameAdd(self):
        print("begin add cname...")
        for view in self.viewlist:
            for zone in self.zonelist:
                for cname in range(self.cname_num):
                    url = 'https://%s:20120/views/%s/zones/%s/rrs' % (self.server_ip, view, zone)
                    data = {
                        "name": "%scname%d.%s." % (self.qname, cname, zone),
                        "type": "CNAME",
                        "ttl": "3600",
                        "rdata": "%scname%d.%s." % (self.qname, (cname + 1), zone),
                        "is_enable": "yes",
                        "expire_is_enable": "no",
                        "current_user": "admin"
                    }
                    if cname == 0:
                        self.cname_domain.append(data["name"])
                    if cname == self.cname_num - 1:
                        data["rdata"] = self.domain[view].replace('\n', '').split(' ')[0]
                    if zone == self.zonelist[-1] and cname == 0:
                        self.cname_sur = data["name"]
                    r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                    response =  json.loads(r.text)
                    if "name" in response:
                        if response["name"] == data["name"]:
                            pass
                    else:
                        return response
                    time.sleep(0.2)
                    self.countNum('cname ',(cname + 1), self.cname_num, '%s %s' % (view, zone))

    def domainlimitAdd(self, rrsview):
        print("begin add domainlimit...")
        for domainlimit in range(self.rrs_limit_num):
            url = 'https://%s:20120/name-rrls' % self.server_ip
            data = {
                "comment": "",
                "name" : "%s.%s" % (''.join(random.sample(string.ascii_letters,5)).lower(),''.join(random.sample(string.ascii_letters,5)).lower()),
                "owners": ["local.master"],
                "rate_limit": "100",
                "current_user": "admin",
                "view": rrsview
            }
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response =  json.loads(r.text)
            if "name" in response:
                if response["name"] == data["name"]:
                    pass
            else:
                return response
            global domainlimit_end
            domainlimit_end = data["name"]
            time.sleep(0.2)
            self.countNum('domainlimit ', (domainlimit + 1), self.rrs_limit_num)

    def domainlimitDel(self):
        print("begin delete domainlimit...")
        rrslimit_list = []
        url = 'https://%s:20120/name-rrls' % self.server_ip
        data = {
            "current_user":"admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response =  json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for rrslimit in response['resources']:
                    rrslimit_list.append(rrslimit["id"])
                data = {
                    "ids": rrslimit_list
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response =  json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def iplimitAdd(self):
        print("begin add iplimit...")
        for iplimit in range(self.ip_limit_num):
            url = 'https://%s:20120/ip-rrls' % self.server_ip
            data = {
                "comment": "",
                "network": "%d.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)),
                "owners": ["local.master"],
                "rate_limit":"100",
                "current_user": "admin"
            }
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response =  json.loads(r.text)
            if "network" in response:
                if response["network"] == "%s/32" % data["network"]:
                    pass
            else:
                return response
            time.sleep(0.2)
            global iplimit_end
            iplimit_end = data["network"]
            self.countNum('iplimit ', (iplimit + 1), self.ip_limit_num)

    def iplimitDel(self):
        print("begin delete iplimit...")
        iplimitlist = []
        url = 'https://%s:20120/ip-rrls' % self.server_ip
        data = {
            "current_user":"admin"
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response =  json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for ids in response["resources"]:
                    iplimitlist.append(ids["id"])
                data = {
                    "ids": iplimitlist,
                    "current_user": "admin"
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response =  json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def localpolicyAdd(self, localview):
        print("begin add local policy...")
        url = 'https://%s:20120/local-policies' % self.server_ip
        zone_content = ''
        switch = ''
        if self.adds == 1:
            switch = ''
        else:
            switch = 'N/A '
        for localpolicy in range(self.policy_num):
            tmp = '%s %s domain nxdomain ANY N/A N/A %syes N/A\n' % (localview, (''.join(random.sample(string.ascii_letters,6)).lower()), switch)
            zone_content = zone_content + tmp
            global localdata_end
            localdata_end = tmp.split(' ')[1]
        data = {
            "zone_content": str(base64.b64encode(zone_content.encode("utf-8")), encoding='utf-8')
        }
        r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        if response == []:
            pass
        else:
            return response
        time.sleep(0.2)
        self.countNum('local policy ', self.policy_num, self.policy_num, '%s' % localview)

    def localpolicyDel(self):
        print("begin delete local policy...")
        localpolicylist = []
        url = 'https://%s:20120/local-policies' % self.server_ip
        data = {
            "search_attrs": [["domain_name", "in", "", "and"]]
        }
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response =  json.loads(r.text)
        if "resources" in response:
            if response["resources"] == []:
                pass
            else:
                for data in response['resources']:
                    localpolicylist.append(data["id"])
                data = {
                    "ids": localpolicylist
                }
                r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response =  json.loads(r.text)
                if "result" in response:
                    pass
                else:
                    return response
        else:
            return response

    def generateFile(self, testtype):
        if testtype == "A":
            if os.path.exists('dnsperf.txt'):
                os.system('rm -rf dnsperf.txt')
            for zone in self.zonelist:
                for rrs in range(self.rrs_num):
                    with open('dnsperf.txt', 'a') as f:
                        f.write('%s%d.%s A\n' % (self.qname, rrs, zone))
        elif testtype == "CNAME":
            if os.path.exists('dnsperf_cname.txt'):
                os.system('rm -rf dnsperf_cname.txt')
            for cname_domain in self.cname_domain:
                with open('dnsperf_cname.txt', 'a') as f:
                    f.write('%s A\n' % cname_domain)
        elif testtype == 'ADD':
            if os.path.exists('dnsperf_add.txt'):
                os.system('rm -rf dnsperf_add.txt')
            for add_zone in self.addzone:
                for add_rrs in range(self.rrs_num):
                    with open('dnsperf_add.txt', 'a') as f:
                        f.write('%s%d.%s A\n' % (self.rrs_qname, add_rrs, add_zone))
        elif testtype == "CACHE":
            if os.path.exists('dnsperf_cache.txt'):
                os.system('rm -rf dnsperf_cache.txt')
            with open('dnsperf_cache.txt', 'a') as f:
                f.write('baidu.com A')

    def dnsperf(self, perffile, qps=0, cache=False, pro='v4'):
        print("begin testing...")
        recursive_result = ''
        dnsperf_cmd = ''
        if qps == 0:
            if cache == True:
                if pro == 'v6':
                    recursive_result = os.popen('dig @%s baidu.com +short' % self.server_ipv6)
                else:
                    recursive_result = os.popen('dig @%s baidu.com +short' % self.server_ip)
                if recursive_result == '':
                    return "ERROR: cannot reursive, please check dns config"
                if pro == 'v6':
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -c 128' % (self.server_ipv6, perffile)
                else:
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -c 128' % (self.server_ip, perffile)
            else:
                if pro == 'v6':
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -c 128' % (self.server_ipv6, perffile)
                else:
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -c 128' % (self.server_ip, perffile)
        else:
            if cache == True:
                if pro == 'v6':
                    recursive_result = os.popen('dig @%s baidu.com +short' % self.server_ipv6)
                else:
                    recursive_result = os.popen('dig @%s baidu.com +short' % self.server_ip)
                if recursive_result == '':
                    return "ERROR: cannot reursive, please check dns config"
                if pro == 'v6':
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -Q %d -q 1000000 -c 128' % (self.server_ipv6, perffile, qps)
                else:
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -Q %d -q 1000000 -c 128' % (self.server_ip, perffile, qps)
            else:
                if pro == 'v6':
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -Q %d -q 1000000 -c 128' % (self.server_ipv6, perffile, qps)
                else:
                    dnsperf_cmd = './dnsperf -s %s -d %s -l 60 -Q %d -q 1000000 -c 128' % (self.server_ip, perffile, qps)
        result = os.popen(dnsperf_cmd).read()
        return result

    def checkFile(self, checkpoint, isexist):
        print("begin check operation is successful...")
        cmd = 'scp root@%s:/usr/local/zddi/dns/etc/zdns.conf .' % self.server_ip
        conffile = []
        while True:
            child = pexpect.spawn(cmd)
            index = child.expect(['yes/no', 'password:'])
            if index == 0:
                child.sendline('yes')
                child.expect('password:')
                child.sendline('%s' % self.root_passwd)
                child.read()
            elif index == 1:
                child.sendline('%s' % self.root_passwd)
                child.read()
            else:
                pass
            with open('zdns.conf', 'r') as f:
                conffile = f.readlines()
            if isexist == 'exist':
                for check in conffile:
                    if checkpoint in check:
                        os.system('rm -rf zdns.conf')
                        return check
            elif isexist == 'noexist':
                for check in conffile:
                    if checkpoint not in check:
                        os.system('rm -rf zdns.conf')
                        return check
            time.sleep(3)

    def suivey(self, putview, suivey_type):
        print("begin check view is change succeed")
        domaininfo = self.domain[putview].replace('\n', '').split(' ')
        while True:
            if suivey_type == 'A':
                suivey_result = os.popen('dig @%s %s +short' % (self.server_ip, domaininfo[0])).read().replace('\n', '')
            elif suivey_type == 'CNAME':
                suivey_result = os.popen('dig @%s %s +short' % (self.server_ip, self.cname_sur)).read().split('\n')
                if len(suivey_result) >= self.cname_num + 1:
                    suivey_result = suivey_result[self.cname_num]
            time.sleep(1)
            if suivey_result == domaininfo[4].strip():
                break

    def writeFile(self, fileinfo, filetext):
        print("begin generate result...")
        with open('result.txt', 'a') as file:
            file.write("================================%s================================\n" % fileinfo)
            file.write(filetext)

    def envinit(self):
        zondel = self.addzoneDel()
        if zondel == 0:
            pass
        else:
            pooldel = self.poolDel()
            syncgdel = self.syncgroupDel()
            dcdel = self.datacenterDel()
            adderror = pooldel or syncgdel or dcdel
            if adderror != None:
                return adderror
        viewdel = self.viewDel()
        zondel = self.zoneDel()
        acldel = self.aclDel()
        rrsdel = self.domainlimitDel()
        ipdel = self.iplimitDel()
        localpolicydel = self.localpolicyDel()
        errorinfo = viewdel or zondel or acldel or rrsdel or ipdel or localpolicydel
        if errorinfo != None:
            return errorinfo

    def run(self, editview):
        if self.rrs_limit_num > 0:
            rrsl_del = self.domainlimitDel()
            if rrsl_del != None:
                return rrsl_del
            self.checkFile(domainlimit_end,'noexist')
            rrsl_add = self.domainlimitAdd(editview)
            if rrsl_add != None:
                return rrsl_add
            self.checkFile(domainlimit_end,'exist')
        if self.policy_num > 0:
            localdata_del = self.localpolicyDel()
            if localdata_del != None:
                return localdata_del
            self.checkFile(localdata_end,'noexist')
            localdata_add = self.localpolicyAdd(editview)
            if localdata_add != None:
                return localdata_add
            self.checkFile(domainlimit_end,'exist')

class InterfaceTimeTools:
    def __init__(self, server_ip, server_ipv6, batch_add, add, rrs_base, qps_base):
        self.server_ip = server_ip
        self.server_ipv6 = server_ipv6
        self.batch_add = batch_add
        self.add = add
        self.rrs_base = rrs_base
        self.qps_base = qps_base

    def interfaceResult(self, interface_type, timeused):
        with open('result.txt', 'a') as f:
           f.write("================================Interface %s result1================================\n\n" % interface_type)
           f.write("batch add rrs number: %d\n" % self.batch_add)
           f.write("add rrs one by one number: %d\n" % self.add)
           f.write("base rrs number before add: %d\n" % self.rrs_base)
           f.write("base qps number when add rrs: %d\n" % self.qps_base)
           f.write("Effective time: %.2f s" % timeused)
        
    def rrsBachRrs(self):
        zone_content = ''
        qname = ''
        time_start = 0
        time_end = 0
        url = 'https://%s:20120/views/default/zones' % self.server_ip
        data = {
            "name": "com1",
            "owners": ["local.master"],
            "server_type": "master",
            "default_ttl": "3600",
            "slaves":[],
            "ad_controller":[],
            "current_user":"admin"
        }
        r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
        response =  json.loads(r.text)
        if "id" in response:
            pass
        else:
            return response
        if self.rrs_base != 0:
            print("create base rrs...")
            for baserrs in range(self.rrs_base):
                base = 'baserr%d.com1. 3600 IN A %d.%d.%d.%d\n' % (baserrs, random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255))
                zone_content = zone_content + base
                qname = base
            url = 'https://%s:20120/views/default/zones/com1/rrs' % self.server_ip
            data = {
                "zone_content": str(base64.b64encode(zone_content.encode("utf-8")), encoding='utf-8'),
            }
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response =  json.loads(r.text)
            if response == []:
                pass
            else:
                return response
            zone_content = ''
            while True:
                cmd = 'dig @%s %s +short' % (self.server_ip, qname.split(' ')[0])
                if os.popen(cmd).read() == qname.split(' ')[4]:
                    qname = ''
                    break
        if self.qps_base != 0:
            print("create base qps...")
            if os.path.exists('dnsperf_base.txt'):
                os.system('rm -rf dnsperf_base.txt')
            with open('dnsperf_base.txt', 'a') as f:
                f.write('a.com1 A')
            cmd = 'nohup ./dnsperf -s %s -d dnsperf_base.txt -l 60 -c 128 -Q %s -q 100000 &' % (self.server_ip, self.qps_base)
            os.system(cmd)
        if self.batch_add != 0:
            print("batch add rrs...")
            for rrs in range(self.batch_add):
                tmp = 'rr%d.com1. 3600 IN A %d.%d.%d.%d\n' % (rrs, random.randint(0, 255),random.randint(0, 255),random.randint(0, 255),random.randint(0, 255))
                qname = tmp
                zone_content = zone_content + tmp
            url = 'https://%s:20120/views/default/zones/com1/rrs' % self.server_ip
            data = {
                "zone_content": str(base64.b64encode(zone_content.encode("utf-8")), encoding='utf-8'),
            }
            time_start = time.time()
            r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
            response =  json.loads(r.text)
            if response == []:
                pass
            else:
                return response 
            while True:
                cmd = 'dig @%s %s +short' % (self.server_ip, qname.split(' ')[0])
                if os.popen(cmd).read().replace("\n", '').strip() == qname.split(' ')[4].strip():
                    time_end = time.time()
                    self.interfaceResult("batch_add", (time_end - time_start))
                    if self.qps_base != 0:
                        os.system('killall -9 dnsperf')
                    break
        if self.add != 0:
            print("add rrs one by one...")
            time_start = time.time()
            for add_bye_one in range(self.add):
                url = 'https://%s:20120/views/default/zones/com1/rrs' % self.server_ip
                data = {
                    "name": "rr%d" % add_bye_one,
                    "type": "A",
                    "ttl": "3600",
                    "rdata":["%d.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))],
                    "is_enable": "yes",
                    "expire_is_enable": "no",
                    "current_user": "admin"
                }
                r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("admin", "admin"),verify=False, params={"lang": "en"})
                response =  json.loads(r.text)
                qname = data["name"]
                rrset = data["rdata"][0]
                if "id" in response:
                    pass
                else:
                    return response
                loginfo = "add rrs %d" % (add_bye_one + 1)
                print(loginfo, end = "")
                if (add_bye_one + 1) != self.add:
                    print("\b" * (len(loginfo)*2),end = "",flush=True)
                else:
                    print('')
            while True:
                cmd = 'dig @%s %s.com1 +short' % (self.server_ip, qname)
                if os.popen(cmd).read().replace('\n','') == rrset:
                    time_end = time.time()
                    self.interfaceResult("add", (time_end - time_start))
                    if self.qps_base != 0:
                        os.system('killall -9 dnsperf')
                    break
        return "\nEffective time %f\n" % (time_end - time_start)

def main():
    while True:
        continue_check = input("This operation will clear the data on your device, do you want to continue? (yes/no):\n")
        if continue_check == "yes":
            print("Test begaining\n")
            break
        elif continue_check == "no":
            return "Stop test"
        else:
            print("ERROR: Input wrong words (yes/no)")
    if batch_add != 0 and add != 0:
        print("ERROR: must select only one of batch_add and add_by_one to test")
        return
    if os.path.exists('result.txt'):
        os.system('rm -rf result.txt')
    if batch_add or add or rrs_base or qps_base:
        tools = QpsPerformanceTools(client_ip, server_ip,client_ipv6,server_ipv6,root_passwd, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 'auth')
        print("begaining init...")
        tools.envinit()
        interface = InterfaceTimeTools(server_ip, server_ipv6, batch_add, add, rrs_base, qps_base)
        timeuse = interface.rrsBachRrs()
        print(timeuse)
        return
    else:
        pass
    if server_ip == '' and client_ip == '':
        return "ERROR: server_ip and client_ip cannot be null"
    if root_passwd == '':
        return "ERROR: server_root_passwd cannot be null"
    if all([zone_num, rrs_num, label, test_type]):
        if label < 2:
            return "ERROR: label_number can not less than 2"
    else:
        return "Error: client_ip, server_ip, zone_number_perview, rrs_number_perzone, label_number, match_view, test_type can not be None or 0"
    if rrs_limit_num > 998 or ip_limit_num > 998:
        return "ERROR: domain_limit_number or ip_limit_number cannot more than 998"
    for i in match_view:
        if acl_addr == 0 and int(i) > view_num + 1:
            print("ERROR: you have no acl address, cannot match view except default")
            return
        elif int(i) > view_num + 1:
            print("ERROR: view match out range of view_num")
            return
        elif test_type == "add" and int(i) !=0 :
            print("ERROR: test_type is add, match_view must be 0")
            return
        elif int(i) == 0 and test_type != "add":
            print("ERROR: test_type is not add, match_view cannot be 0")
            return
            
    if test_type == "add" and view_num != 0:
        print("ERROR: test_type is add, view_number must be 0")
        return
    tools = QpsPerformanceTools(client_ip, server_ip, client_ipv6, server_ipv6,root_passwd, view_num, zone_num, rrs_num, label, cname_num, acl_addr, rrs_limit_num, ip_limit_num, policy_num, qps_num, match_view, test_type)
    print("begaining init...")
    init = tools.envinit()
    if init != None:
        return init
    if acl_addr > 0:
        if test_type == "add":
            pass
        elif test_type == "auth":
            acl = tools.aclAdd()
            if acl != None:
                return acl
        elif test_type == "cache":
            acl = tools.aclAdd()
            if acl != None:
                return acl
        view = tools.viewAdd(["acl"])
        if view != None:
            return view
    else:
        view = tools.viewAdd([])
        if view != None:
            return view
    if test_type == "add":
        adddata = tools.addrrsAdd()
        files = tools.generateFile('ADD')
        if adddata != None:
            return adddata
    elif test_type == "cache":
        files = tools.generateFile('CACHE')
    elif test_type == "auth":
        zone = tools.zoneAdd()
        rrs = tools.rrsAdd()
        files = tools.generateFile('A')
        ErrorInfo = zone or rrs or files
        if ErrorInfo != None:
            return ErrorInfo
    if ip_limit_num > 0:
        iplimit = tools.iplimitAdd()
        if iplimit != None:
            return iplimit
        tools.checkFile(iplimit_end,'exist')
    if acl_addr > 0:
        for perf in range(len(match_view)):
            if int(match_view[perf]) == 0:
                run = tools.run('default')
                if run != None:
                    return run
                tools.suivey('add','A')
                print("A RRS test match add views")
                if qps_num > 0:
                    if client_ip != '' and server_ip != '':
                        dnsperf = tools.dnsperf('dnsperf_add.txt', qps_num)
                        tools.writeFile("ADD A delay result(add)", dnsperf)
                    if client_ipv6 != '' and server_ipv6 != '':
                        dnsperf = tools.dnsperf('dnsperf_add.txt', qps_num, 'v6')
                        tools.writeFile("ADD A delay result(add) ipv6", dnsperf)
                else:
                    if client_ip != '' and server_ip != '':
                        dnsperf = tools.dnsperf('dnsperf_add.txt')
                        tools.writeFile("ADD A result(add)", dnsperf)
                    if client_ipv6 != '' and server_ipv6 != '':
                        dnsperf = tools.dnsperf('dnsperf_add.txt', pro='v6')
                        tools.writeFile("ADD A result(add) ipv6", dnsperf)
                return ''
            elif int(match_view[perf]) ==  view_num + 1:
                run = tools.run('default')
                if run != None:
                    return run
                print("A RRS test match default views")
                if qps_num > 0:
                    if test_type == "cache":
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', qps_num, cache=True)
                            tools.writeFile("CACHE A delay result(default)", dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', qps_num, cache=True, pro='v6')
                            tools.writeFile("CACHE A delay result(default) ipv6", dnsperf)
                    else:
                        tools.suivey('default','A')
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf.txt', qps_num)
                            tools.writeFile("AUTH A delay result(default)", dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf.txt', qps_num, pro='v6')
                            tools.writeFile("AUTH A delay result(default) ipv6", dnsperf)
                else:
                    if test_type == "cache":
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', cache=True)
                            tools.writeFile("CACHE A result(default)", dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', cache=True, pro='v6')
                            tools.writeFile("CACHE A result(default) ipv6", dnsperf)
                    else:
                        tools.suivey('default','A')
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf.txt')
                            tools.writeFile("AUTH A result(default)", dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf.txt', pro='v6')
                            tools.writeFile("AUTH A result(default) ipv6", dnsperf)
            else:
                addviewacl = tools.viewEdit('view%d' % (view_num - int(match_view[perf])), "match_acl")
                if addviewacl != None:
                    return addviewacl
                run = tools.run('view%d' % (view_num - int(match_view[perf])))
                if run != None:
                    return run
                print("A RRS test match view%s views" % (view_num - int(match_view[perf])))
                if qps_num > 0:
                    if test_type == "cache":
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', qps_num, cache=True)
                            tools.writeFile("CACHE A delay result(view%d)" % (view_num - int(match_view[perf])), dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', qps_num, cache=True, pro='v6')
                            tools.writeFile("CACHE A delay result(view%d) ipv6" % (view_num - int(match_view[perf])), dnsperf)
                    else:
                        tools.suivey('view%d' % (view_num - int(match_view[perf])), 'A')
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf.txt', qps_num)
                            tools.writeFile("AUTH A delay result(view%d)" % (view_num - int(match_view[perf])), dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf.txt', qps_num, pro='v6')
                            tools.writeFile("AUTH A delay result(view%d) ipv6" % (view_num - int(match_view[perf])), dnsperf)
                else:
                    if test_type == "cache":
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', cache=True)
                            tools.writeFile("CACHE A result(view%d)" % (view_num - int(match_view[perf])), dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cache.txt', cache=True, pro='v6')
                            tools.writeFile("CACHE A result(view%d) ipv6" % (view_num - int(match_view[perf])), dnsperf)
                    else:
                        tools.suivey('view%d' % (view_num - int(match_view[perf])), 'A')
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf.txt')
                            tools.writeFile("AUTH A result(view%d)" % (view_num - int(match_view[perf])), dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf.txt', pro='v6')
                            tools.writeFile("AUTH A result(view%d) ipv6" % (view_num - int(match_view[perf])), dnsperf)
                delviewacl = tools.viewEdit('view%d' % (view_num - int(match_view[perf])), "acl")
                if delviewacl != None:
                    return delviewacl
        if cname_num != 0 and test_type != "cache":
            cnameadd = tools.cnameAdd()
            tools.generateFile('CNAME')
            if cnameadd != None:
                return cnameadd
            for cnamematch in range(len(match_view)):
                if int(match_view[cnamematch]) ==  view_num + 1:
                    tools.suivey('default', 'CNAME')
                    print("CNAME RRS test match default views")
                    if qps_num > 0:
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt', qps_num)
                            tools.writeFile("AUTH CNAME delay result(default)", dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt', qps_num, pro='v6')
                            tools.writeFile("AUTH CNAME delay result(default) ipv6", dnsperf)
                    else:
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt')
                            tools.writeFile("AUTH CNAME result(default)", dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt', pro='v6')
                            tools.writeFile("AUTH CNAME result(default) ipv6", dnsperf)
                else:
                    addviewacl = tools.viewEdit('view%d' % (view_num - int(match_view[cnamematch])), "match_acl")
                    if addviewacl != None:
                        return addviewacl
                    tools.suivey('view%d' % (view_num - int(match_view[cnamematch])), 'CNAME')
                    print("CNAME RRS test match view%s views" % match_view[cnamematch])
                    if qps_num > 0:
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt', qps_num)
                            tools.writeFile("AUTH CNAME delay result(view%d)" % (view_num - int(match_view[cnamematch])), dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt', qps_num, pro='v6')
                            tools.writeFile("AUTH CNAME delay result(view%d) ipv6" % (view_num - int(match_view[cnamematch])), dnsperf)
                    else:
                        if client_ip != '' and server_ip != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt')
                            tools.writeFile("AUTH CNAME result(view%d)" % (view_num - int(match_view[cnamematch])), dnsperf)
                        if client_ipv6 != '' and server_ipv6 != '':
                            dnsperf = tools.dnsperf('dnsperf_cname.txt', pro='v6')
                            tools.writeFile("AUTH CNAME result(view%d) ipv6" % (view_num - int(match_view[cnamematch])), dnsperf)
                    delviewacl = tools.viewEdit('view%d' % (view_num - int(match_view[cnamematch])), "acl")
                    if delviewacl != None:
                        return delviewacl
    else:
        run = tools.run('default')
        if run != None:
            return run
        if int(match_view[0]) == 0:
            tools.suivey('add','A')
            print("A RRS test match add views")
            if qps_num > 0:
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf_add.txt', qps_num)
                    tools.writeFile("ADD A delay result(add)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf_add.txt', qps_num, pro='v6')
                    tools.writeFile("ADD A delay result(add) ipv6", dnsperf)
            else:
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf_add.txt')
                    tools.writeFile("ADD A result(add)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf_add.txt', pro='v6')
                    tools.writeFile("ADD A result(add) ipv6", dnsperf)
            return ''
        print("A RRS test match default views")
        if qps_num > 0:
            if test_type == "cache":
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf_cache.txt', qps_num, cache=True)
                    tools.writeFile("CACHE A delay result(default)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf_cache.txt', qps_num, cache=True, pro='v6')
                    tools.writeFile("CACHE A delay result(default) ipv6", dnsperf)
            else:
                tools.suivey('default', 'A')
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf.txt', qps_num)
                    tools.writeFile("AUTH A delay result(default)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf.txt', qps_num, pro='v6')
                    tools.writeFile("AUTH A delay result(default) ipv6", dnsperf)
        else:
            if test_type == "cache":
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf_cache.txt', cache=True)
                    tools.writeFile("CACHE A result(default)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf_cache.txt', cache=True, pro='v6')
                    tools.writeFile("CACHE A result(default) ipv6", dnsperf)
            else:
                tools.suivey('default', 'A')
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf.txt')
                    tools.writeFile("AUTH A result(default)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf.txt', pro='v6')
                    tools.writeFile("AUTH A result(default) ipv6", dnsperf)
        if cname_num != 0:
            cnameadd = tools.cnameAdd()
            tools.generateFile('CNAME')
            if cnameadd != None:
                return cnameadd
            tools.suivey('default', 'CNAME')
            print("CNAME RRS test match default views")
            if qps_num > 0:
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf_cname.txt', qps_num)
                    tools.writeFile("AUTH CNAME delay result(default)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf_cname.txt', qps_num, pro='v6')
                    tools.writeFile("AUTH CNAME delay result(default) ipv6", dnsperf)
            else:
                if client_ip != '' and server_ip != '':
                    dnsperf = tools.dnsperf('dnsperf_cname.txt')
                    tools.writeFile("AUTH CNAME result(default)", dnsperf)
                if client_ipv6 != '' and server_ipv6 != '':
                    dnsperf = tools.dnsperf('dnsperf_cname.txt', pro='v6')
                    tools.writeFile("AUTH CNAME result(default)", dnsperf)
   

if __name__ == "__main__":
    try:
        res = main()
        if res != None:
            print(res)
    except KeyboardInterrupt:
        print("Test finished")
    print("Test finished")

