#!/usr/local/bin/python3
import bigsuds
import base64
import requests
import logging
import optparse
import time
import json
import datetime
import urllib3
import os
import sys
from logging import handlers
from logging.handlers import RotatingFileHandler
from subprocess import check_output

urllib3.disable_warnings()


class SoapTransformation(object):
    def __init__(self, hostname, username, password, port):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.conn()
        self.finnal_dict = {}
        self.datetime_now = ''
        self.pool_name_list = []
    # user = bigsuds.BIGIP(hostname="58.246.94.106", username="admin", password="admin", port="442")

    def write_log(self, content):
        logger = logging.getLogger(__name__)
        logger.setLevel(level = logging.INFO)
        if not logger.handlers:
            rHandler = RotatingFileHandler("synclog.txt",maxBytes = 10*1024*1024,backupCount = 20)
            rHandler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            rHandler.setFormatter(formatter)

            logger.addHandler(rHandler)
        logger.info(content)

    def conn(self):
        try:
            self.con = bigsuds.BIGIP(hostname=self.hostname, username=self.username, password=self.password, port=self.port)
        except Exception as e:
            self.write_log(e)
            os._exit(0)

    def get_datacenter(self):
        datacenterlist = self.con.GlobalLB.DataCenter.get_list()
        server_list = self.con.GlobalLB.DataCenter.get_server([datacenterlist])
        return server_list

    def get_server(self, vserver_name):
        vsaddress = self.con.GlobalLB.VirtualServerV2.get_address([vserver_name])
        return vsaddress

    def get_pool(self):
        self.write_log("Start reading the configuration of the pool...")
        pool_dict = {}
        pool_list = []
        tmp_list = []
        pool_list = self.con.GlobalLB.PoolV2.get_list_by_type(["GTM_QUERY_TYPE_A"])[0] + self.con.GlobalLB.PoolV2.get_list_by_type(["GTM_QUERY_TYPE_AAAA"])[0] + self.con.GlobalLB.PoolV2.get_list_by_type(["GTM_QUERY_TYPE_CNAME"])[0]
        for item in pool_list:
            tmp = {}
            member_list = []
            pool_name = item["pool_name"]
            temp = self.con.GlobalLB.PoolV2.get_member([item])
            if item["pool_type"] == "GTM_QUERY_TYPE_AAAA" or item["pool_type"] == "GTM_QUERY_TYPE_A":
                for sub_item in temp[0]:
                    member_list += self.get_server(sub_item)
                tmp["lb_method"] = self.con.GlobalLB.Pool.get_alternate_lb_method([pool_name])[0]
                tmp["preferred_method"] = self.con.GlobalLB.Pool.get_preferred_lb_method([pool_name])[0]
#                tmp["fall_back_ip"] = self.con.GlobalLB.Pool.get_fallback_ip([pool_name])[0]
                tmp["ttl"] = self.con.GlobalLB.Pool.get_ttl([pool_name])[0]
                tmp["max_back_num"] = self.con.GlobalLB.Pool.get_answers_to_return([pool_name])[0]
                tmp["pool_type"] = item["pool_type"]
                member_info = self.con.GlobalLB.PoolMember.get_ratio([pool_name],[member_list])[0]
                for mem in range(len(member_info)):
                    member_info[mem]["member"] = {temp[0][mem]["server"]:member_list[mem]}
                    member_info[mem]["member"]["status"] = self.con.GlobalLB.Server.get_object_status([temp[0][mem]["server"]])[0]["availability_status"]
                tmp["pool_member"] = member_info
            elif item["pool_type"] == "GTM_QUERY_TYPE_CNAME":
                for index in temp[0]:
                    tmp["pool_member"] = index["server"]
                    tmp["ttl"] = self.con.GlobalLB.Pool.get_ttl([pool_name])[0]
            pool_dict[item["pool_name"] + "_" + item["pool_type"].split("_")[-1]] = tmp
        return pool_dict

    def get_static(self):
        self.write_log("Start reading the configuration of the topology...")
        static_list = self.con.GlobalLB.Topology.get_list()
        order_list = self.con.GlobalLB.Topology.get_order(static_list)
        for item in range(len(static_list)):
            static_list[item]["order"] = order_list[item]
        return static_list

    def get_userZone(self):
        self.write_log("Start reading the configuration of the region...")
        zone_dict = {}
        userzonelist = self.con.GlobalLB.Region.get_list()
        for item in userzonelist:
            zone_dict[item["name"]] = self.con.GlobalLB.Region.get_region_item([item])[0]
        return zone_dict

    def get_rrs(self):
        self.write_log("Start reading the configuration of the wideip...")
        rrs_dict = {}
        for item in  self.con.GlobalLB.WideIP.get_list():
            tmp = {}
            wideippool_list = self.con.GlobalLB.WideIP.get_wideip_pool([item])
#            rrs_dict[item.split("/")[2]] = wideippool_list[0]
            tmp["pool"] = wideippool_list[0]
            tmp["lb_method"] = self.con.GlobalLB.WideIP.get_lb_method([item])
            rrs_dict[item.split("/")[2]] = tmp
        return rrs_dict

    def get_zone_content(self):
        self.write_log("Start reading the configuration of the zonerunner...")
        zone_rrs_dict = {}
        view_dict = {}
        for views in self.con.Management.View.get_list():
            zone_dict = {}
            for zones in self.con.Management.Zone.get_zone_name([views["view_name"]]):
                zone_dict[zones["zone_name"]] = self.con.Management.ResourceRecord.get_rrs([zones])[0]
            view_dict[views["view_name"]] = zone_dict
        return view_dict

    def write_file(self):
        self.write_log("start reading F5's config...")
        try:
            pool_msg = self.get_pool()
            static_msg = self.get_static()
            userzone_msg = self.get_userZone()
            wideip_msg = self.get_rrs()
            rrs_msg = self.get_zone_content()
        except Exception as e:
            self.write_log(e)
            os._exit(0)
        file_dict = {}
        file_path = 'backup_data/'
        file_dict["pool"] = pool_msg
        file_dict["static"] = static_msg
        file_dict["region"] = userzone_msg
        file_dict["wideip"] = wideip_msg
        file_dict["rrs"] = rrs_msg
        self.datetime_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(file_path + '%s' % self.datetime_now, 'w') as f:
            f.write(str(file_dict))

class ConfigManage(SoapTransformation):
    def __init__(self, hostname, username, password, port, server_ip, zuername, zpassword, file_name):
        super(ConfigManage, self).__init__(hostname, username, password, port)
        self.server_ip = server_ip
        self.zuername = zuername
        self.zpassword = zpassword
        self.file_name = file_name
        self.server_names = []

    def read_file(self):
        files = ''
        if self.file_name != None:
            files = self.file_name
        else:
            files = "backup_data/" + self.datetime_now
        try:
            with open('%s' % files, 'r') as f:
                self.data = eval(f.read())
        except Exception as e:
            self.write_log(e)
            os._exit(0)

    def name_replace(self, name):
        name = name.replace("-", "_")
        name = name.replace(".", "_")
        return name

    def inte_post_requests(self, url, data):
        r = requests.post(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("%s" % self.zuername, "%s" % self.zpassword),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        return response

    def inte_get_requests(self, url, data):
        r = requests.get(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("%s" % self.zuername, "%s" % self.zpassword),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        return response

    def inte_delete_requests(self, url, data):
        r = requests.delete(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("%s" % self.zuername, "%s" % self.zpassword),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        return response

    def inte_put_requests(self, url, data):
        r = requests.put(url, headers={"Content-type": "application/json"}, data=json.dumps(data), auth=("%s" % self.zuername, "%s" % self.zpassword),verify=False, params={"lang": "en"})
        response = json.loads(r.text)
        return response

    def inte_datacenter(self):
        url = 'https://%s:20120/dc' % self.server_ip
        data = {
            "name": "DC1",
            "devices": ["local.master"],
            "synserver": "local.master"
        }
        response = self.inte_post_requests(url, data)
        if "id" in response:
            if response["id"] == data["name"]:
                pass
        else:
            self.write_log("inte_datacenter:" + str(response))

    def inte_member(self, resource_content):
        url = 'https://%s:20120/dc/DC1/gmember' % self.server_ip
        data = {
            "resource_content": resource_content
        }
        response = self.inte_post_requests(url, data)
        if "resource_content" in response:
            pass
        else:
            self.write_log("inte_member:" + str(response))

    def inte_syncgroup(self, dc_name):
        url = 'https://%s:20120/syngroup' % self.server_ip
        data = {
            "name": "syncgroup1",
            # list
            "dcs": dc_name,
        }
        response = self.inte_post_requests(url, data)
        if "id" in response:
            if response["id"] == data["name"]:
                pass
        else:
            self.write_log("inte_syncgroup:" + str(response))

    def inte_region(self, region_name):
        url = 'https://%s:20120/region' % self.server_ip
        data = {
            "name": region_name,
        }
        response = self.inte_post_requests(url, data)
        if "id" in response:
            if response["id"] == data["name"]:
                pass
        else:
            self.write_log("inte_region:" + str(response))

    def inte_region_member(self, region_name, member_type, region_name_bak=None, ips=None, sip=None, eip=None):
        url = 'https://%s:20120/region/%s/member' % (self.server_ip, region_name)
        data = {"type": member_type}
        if member_type == "ip_subnet":
            data["data1"] = ips
        elif member_type == "is_range":
            data["data1"] = sip
            data["data2"] = eip
        elif member_type == "region":
            data["data1"] = region_name_bak
        response = self.inte_post_requests(url, data)
        if "id" in response:
            pass
        else:
            self.write_log("inte_region_member:" + str(response))

    def inte_sp_policy(self, stype, dtype, sdata, ddata, slogic="0", dlogic="0", priority=''):
        url = 'https://%s:20120/sp_policy' % self.server_ip
        data = {"src_type": stype, "dst_type": dtype, "src_logic": slogic, "dst_logic":dlogic, "priority": priority}
        if stype == "ip_subnet" or stype == "region":
            data["src_data1"] = sdata
        if dtype == "ip_subnet" or dtype == "region" or dtype == "gpool":
            data["dst_data1"] = ddata
        response = self.inte_post_requests(url, data)
        if "id" in response:
            pass
        else:
            self.write_log("inte_sp_policy:" + str(response))

    def inte_pool(self, content):
        url = 'https://%s:20120/gpool' % self.server_ip
        data = {
            "resource_content":content
        }
        response = self.inte_post_requests(url, data)
        if "resource_content" in response:
            pass
        else:
            self.write_log("inte_pool:" + str(response))

    def inte_zone_add(self, zone_name):
        url = 'https://%s:20120/views/ADD/dzone' % self.server_ip
        data = {
            "name": zone_name,
            "syngroup": "syncgroup1"
        }
        response = self.inte_post_requests(url, data)
        if "id" in response:
            if response["id"] == data["name"]:
                pass
        else:
            self.write_log("inte_zone_add:" + str(response))

    def inte_zonerrs(self, zones, algorithm, gpool_list, last_resort_pool=""):
        url = 'https://%s:20120/views/ADD/dzone/%s/gmap' % (self.server_ip, zones)
        data = {
            "name": '',
            "algorithm": algorithm,
            "last_resort_pool": last_resort_pool,
            "persist_enable": "no",
            "enable": "yes",
            "gpool_list": gpool_list
        }
        response = self.inte_post_requests(url, data)
        if "name" in response:
            if response["name"] == "":
                pass
        else:
            self.write_log("inte_zonerrs:" + str(response))

    def inte_zone_default(self, views, zone_name, zone_content):
        url = "https://%s:20120/views/%s/zones" % (self.server_ip, views)
        data = {
            "name": zone_name,
            "owners": ["local.master"],
            "server_type": "master",
            "default_ttl": 3600,
            "zone_content": zone_content
        }
        response = self.inte_post_requests(url, data)
        if "id" in response:
            if response["name"] == zone_name:
                pass
        else:
            self.write_log("inte_zone_default_rrs:" + str(response))

    def edit_server(self, status, ids):
        url = "https://%s:20120/dc/DC1/gmember" % self.server_ip
        data = {
            "linkid": "",
            "enable": status,
            "ids": ids
        }
        response = self.inte_put_requests(url, data)
        if "error" not in response and "ERROR" not in response:
            pass
        else:
            self.write_log("inte_edit_server:" + str(response))

    def inte_get_addzones(self):
        url = "https://%s:20120/views/ADD/dzone" % self.server_ip
        data = {"current_user":"admin"}
        response = self.inte_get_requests(url, data)
        if "resources" in response:
            pass
        else:
            self.write_log("inte_get_addzones:" + str(response))
        return response

    def inte_delete_addzones(self, ids):
        url = "https://%s:20120/views/ADD/dzone" % self.server_ip
        data = {
            "ids": ids,
            "current_user":"admin"
        }
        response = self.inte_delete_requests(url, data)
        if "result" in response:
            if response["result"] == "succeed":
                pass
        else:
            self.write_log("inte_delete_addzones:" + str(response))

    def inte_get_zones(self):
        url = "https://%s:20120/views/default/zones" % self.server_ip
        data = {"current_user":"admin"}
        response = self.inte_get_requests(url, data)
        if "resources" in response:
            pass
        else:
            self.write_log("inte_get_zones:" + str(response))
        return response

    def inte_delete_zones(self, ids):
        url = "https://%s:20120/views/default/zones" % self.server_ip
        data = {
            "ids": ids,
            "current_user":"admin"
        }
        response = self.inte_delete_requests(url, data)
        if "result" in response:
            if response["result"] == "succeed":
                pass
        else:
            self.write_log("inte_delete_zones:" + str(response))

    def inte_get_sp_policy(self):
        url = "https://%s:20120/sp_policy" % self.server_ip
        data = {"current_user":"admin"}
        response = self.inte_get_requests(url, data)
        if "resources" in response:
            pass
        else:
            self.write_log("inte_get_sp_policy:" + str(response))
        return response

    def inte_delete_sp_policy(self, ids):
        url = "https://%s:20120/sp_policy" % self.server_ip
        data = {
            "ids": ids,
            "current_user":"admin"
        }
        response = self.inte_delete_requests(url, data)
        if "result" in response:
            if response["result"] == "succeed":
                pass
        else:
            self.write_log("inte_delete_sp_policy:" + str(response))

    def inte_get_userzone(self):
        url = "https://%s:20120/region" % self.server_ip
        data = {"current_user":"admin"}
        response = self.inte_get_requests(url, data)
        if "resources" in response:
            pass
        else:
            self.write_log("inte_get_userzone:" + str(response))
        return response

    def inte_delete_userzone(self, ids):
        url = "https://%s:20120/region" % self.server_ip
        data = {
            "ids": ids,
            "current_user":"admin"
        }
        response = self.inte_delete_requests(url, data)
        if "result" in response:
            if response["result"] == "succeed":
                pass
        else:
            self.write_log("inte_delete_userzone:" + str(response))

    def inte_get_syncgroup(self):
        url = "https://%s:20120/syngroup" % self.server_ip
        data = {"current_user":"admin"}
        response = self.inte_get_requests(url, data)
        if "resources" in response:
            pass
        else:
            self.write_log("inte_get_syncgroup:" + str(response))
        return response

    def inte_delete_syncgroup(self, ids):
        url = "https://%s:20120/syngroup" % self.server_ip
        data = {
            "ids": ids,
            "current_user":"admin"
        }
        response = self.inte_delete_requests(url, data)
        if "result" in response:
            if response["result"] == "succeed":
                pass
        else:
            self.write_log("inte_delete_syncgroup:" + str(response))

    def inte_get_gpool(self):
        url = "https://%s:20120/gpool" % self.server_ip
        data = {"current_user":"admin"}
        response = self.inte_get_requests(url, data)
        if "resources" in response:
            pass
        else:
            self.write_log("inte_get_gpool:" + str(response))
        return response

    def inte_delete_gpool(self, ids):
        url = "https://%s:20120/gpool" % self.server_ip
        data = {
            "ids": ids,
            "current_user":"admin"
        }
        response = self.inte_delete_requests(url, data)
        if "result" in response:
            if response["result"] == "succeed":
                pass
        else:
            self.write_log("inte_delete_gpool:" + str(response))

    def inte_get_datacenter(self):
        url = "https://%s:20120/dc" % self.server_ip
        data = {"current_user":"admin"}
        response = self.inte_get_requests(url, data)
        if "resources" in response:
            pass
        else:
            self.write_log("inte_get_datacenter:" + str(response))
        return response

    def inte_delete_datacenter(self, ids):
        url = "https://%s:20120/dc" % self.server_ip
        data = {
            "ids": ids,
            "current_user":"admin"
        }
        response = self.inte_delete_requests(url, data)
        if "result" in response:
            if response["result"] == "succeed":
                pass
        else:
            self.write_log("inte_delete_datacenter:" + str(response))

    def add_datacenter(self):
        self.write_log("Start distributing configuration of the datacenter...")
        self.inte_datacenter()

    def add_gmember(self):
        self.write_log("Start distributing configuration of the gmember...")
        server_name = ''
        server_name_act = ''
        server_dict = {}
        content = []
        status = ''
        for index in self.data["pool"]:
            for sub_index in self.data["pool"][index]["pool_member"]:
                if "member" in sub_index:
                    server_name = [item for item in sub_index["member"].keys()][0]
                    server_name_act = server_name
                    server_name_act = self.name_replace(server_name_act)
                    if server_name_act not in server_dict:
                        self.server_names.append(server_name)
                        if sub_index["member"]["status"] == "AVAILABILITY_STATUS_RED":
                            status = "no"
                        else:
                            status = "yes"
                        content.append({"gmember_name":server_name_act.split("/")[2], "ip": sub_index["member"][server_name]["address"],
                                        "port": sub_index["member"][server_name]["port"],"linkid":"","enable":status})
                        server_dict[server_name_act] = {"address":sub_index["member"][server_name]["address"],"port":sub_index["member"][server_name]["port"]}
                    if len(content) == 200:
                        self.inte_member(content)
                        content = []
        self.inte_member(content)

    def add_syncgroup(self):
        self.write_log("Start distributing configuration of the syncgroup...")
        self.inte_syncgroup(["DC1"])

    def add_region(self):
        self.write_log("Start distributing configuration of the region...")
        region_list = []
        region_name = ""
        for item in self.data["region"]:
            region_name = self.name_replace(item)
            region_list.append(item)
            self.inte_region(region_name.split("/")[2])
        return region_list

    def add_region_member(self):
        regions = self.add_region()
        self.write_log("Start distributing configuration of the region member...")
        region_type = ''
        region_name = ''
        for item in regions:
            for sub_item in self.data["region"][item]:
                region_type = sub_item["type"]
                region_name = item.split("/")[2]
                region_name = region_name.replace("-", "_")
                if region_type == "REGION_TYPE_CIDR":
                    self.inte_region_member(region_name, "ip_subnet", ips=sub_item["content"])
                elif region_type == "REGION_TYPE_REGION":
                    self.inte_region_member(region_name, "region", region_name_bak=sub_item["content"].split("/")[2])

    def add_pool(self):
        self.write_log("Start distributing configuration of the pool...")
        pr_topplogy = ''
        lb_topplogy = ""
        content = []
        for item in self.data["pool"]:
            self.pool_name_list.append(item)
            gmember_list = []
            for sub_index in self.data["pool"][item]["pool_member"]:
                gpool = ''
                if "member" in sub_index:
                    servers = [i for i in sub_index["member"].keys()][0]
                    servers = self.name_replace(servers)
                    gmember_list.append({"dc_name": "DC1", "gmember_name": servers.split("/")[-1], "ratio": sub_index["ratio"]})
                else:
                    cnames = self.data["pool"][item]["pool_member"]
                gpool = item.split("/")[-1]
                gpool = self.name_replace(gpool)
            if "_CNAME" in item:
                content.append({"name":gpool, "ttl": self.data["pool"][item]["ttl"], "type":"CNAME", "cname": self.data["pool"][item]["pool_member"], "warning":"yes", "enable":"yes"})
            else:
                if self.data["pool"][item]["preferred_method"] == "LB_METHOD_ROUND_ROBIN":
                    pr_topplogy = "rr"
                    lb_topplogy = "none"
                elif self.data["pool"][item]["preferred_method"] == "LB_METHOD_RATIO":
                    pr_topplogy = "wrr"
                    lb_topplogy = "none"
                elif self.data["pool"][item]["preferred_method"] == "LB_METHOD_GLOBAL_AVAILABILITY":
                    pr_topplogy = "ga"
                    lb_topplogy = "none"
                elif self.data["pool"][item]["preferred_method"] == "LB_METHOD_TOPOLOGY":
                    pr_topplogy = "sp"
                    if self.data["pool"][item]["lb_method"] == "LB_METHOD_ROUND_ROBIN":
                        lb_topplogy = "rr"
                    elif self.data["pool"][item]["lb_method"] == "LB_METHOD_TOPOLOGY":
                        lb_topplogy = "sp"
                    elif self.data["pool"][item]["lb_method"] == "LB_METHOD_GLOBAL_AVAILABILITY":
                        lb_topplogy = "ga"
                content.append({"name":gpool, "ttl":self.data["pool"][item]["ttl"], "type":"A/AAAA", "max_addr_ret":self.data["pool"][item]["max_back_num"], "first_algorithm":pr_topplogy,"second_algorithm":lb_topplogy, "gmember_list":gmember_list, "enable":"yes", "hms":[], "warning":"yes"})
            if len(content) == 200:
                self.inte_pool(content)
                content = []
        self.inte_pool(content)

    def add_sp_policy(self):
        self.write_log("Start distributing configuration of the static proximity...")
        scontent = ''
        dcontent = ""
        content_tmp = ''
        for item in self.data["static"]:
            if item["ldns"]["type"] == "REGION_TYPE_CIDR":
                if item["server"]["type"] == "REGION_TYPE_CIDR":
                    self.inte_sp_policy("ip_subnet", "ip_subnet", item["ldns"]["content"], item["server"]["content"], item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
                elif item["server"]["type"] == "REGION_TYPE_REGION":
                    dcontent = item["server"]["content"]
                    dcontent = self.name_replace(dcontent)
                    self.inte_sp_policy("ip_subnet", "region", item["ldns"]["content"], dcontent.split("/")[-1], item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
                elif item["server"]["type"] == "REGION_TYPE_POOL":
                    dcontent = item["server"]["content"]
                    content_tmp = dcontent
                    dcontent = self.name_replace(dcontent)
                    if content_tmp + "_A" in self.pool_name_list:
                        self.inte_sp_policy("ip_subnet", "gpool", item["ldns"]["content"], dcontent.split("/")[-1] + "_A", item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
                    elif content_tmp + "_CNAME" in self.pool_name_list:
                        self.inte_sp_policy("ip_subnet", "gpool", item["ldns"]["content"], dcontent.split("/")[-1] + "_CNAME", item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
            elif item["ldns"]["type"] == "REGION_TYPE_REGION":
                scontent= item["ldns"]["content"]
                scontent = self.name_replace(scontent)
                if item["server"]["type"] == "REGION_TYPE_CIDR":
                    self.inte_sp_policy("region", "ip_subnet", scontent.split("/")[-1], item["server"]["content"], item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
                elif item["server"]["type"] == "REGION_TYPE_REGION":
                    dcontent = item["server"]["content"]
                    dcontent = self.name_replace(dcontent)
                    self.inte_sp_policy("region", "region", scontent.split("/")[-1], dcontent.split("/")[-1], item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
                elif item["server"]["type"] == "REGION_TYPE_POOL":
                    dcontent = item["server"]["content"]
                    content_tmp = dcontent
                    dcontent = self.name_replace(dcontent)
                    if content_tmp + "_A" in self.pool_name_list:
                        self.inte_sp_policy("region", "gpool", scontent.split("/")[-1], dcontent.split("/")[-1] + "_A", item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
                    elif content_tmp + "_AAAA" in self.pool_name_list:
                        self.inte_sp_policy("region", "gpool", scontent.split("/")[-1], dcontent.split("/")[-1] + "_AAAA", item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))
                    elif content_tmp + "_CNAME" in self.pool_name_list:
                        self.inte_sp_policy("region", "gpool", scontent.split("/")[-1], dcontent.split("/")[-1] + "_CNAME", item["ldns"]["negate"], item["server"]["negate"], str(item["order"]))

    def add_wideip(self):
        self.write_log("Start distributing configuration of the rrs(add)...")
        algorithm = ''
        for item in self.data["wideip"]:
            self.inte_zone_add(item)
            gpool_list = []
            for sub_item in self.data["wideip"][item]["pool"]:
                gpool_name = ""
                if self.data["wideip"][item]["lb_method"] == ["LB_METHOD_ROUND_ROBIN"]:
                    algorithm = "rr"
                elif self.data["wideip"][item]["lb_method"] == ["LB_METHOD_RATIO"]:
                    algorithm = "wrr"
                elif self.data["wideip"][item]["lb_method"] == ["LB_METHOD_GLOBAL_AVALABILITY"]:
                    algorithm = "ga"
                elif self.data["wideip"][item]["lb_method"] == ["LB_METHOD_TOPOLOGY"]:
                    algorithm = "sp"
                gpool_name = sub_item["pool_name"]
                if gpool_name + "_A" in self.pool_name_list:
                    gpool_name = gpool_name + "_A"
                    gpool_name = gpool_name.split("/")[-1]
                    gpool_name = self.name_replace(gpool_name)
                    gpool_list.append({"gpool_name": gpool_name,"ratio":sub_item["ratio"]})
                elif gpool_name + "_AAAA" in self.pool_name_list:
                    gpool_name = gpool_name + "_AAAA"
                    gpool_name = gpool_name.split("/")[-1]
                    gpool_name = self.name_replace(gpool_name)
                    gpool_list.append({"gpool_name": gpool_name,"ratio":sub_item["ratio"]})
                elif gpool_name + "_CNAME" in self.pool_name_list:
                    gpool_name = gpool_name + "_CNAME"
                    gpool_name = gpool_name.split("/")[-1]
                    gpool_name = self.name_replace(gpool_name)
                    gpool_list.append({"gpool_name": gpool_name,"ratio":sub_item["ratio"]})
            self.inte_zonerrs(item,  algorithm, gpool_list)

    def add_rrs_default(self):
        self.write_log("Start distributing configuration of the rrs(default)...")
        rrs_content = ""
        for item in self.data["rrs"]:
            for sub_item in self.data["rrs"][item]:
                rrs_content = '\n'.join(self.data["rrs"][item][sub_item])
                rrs_content = str(base64.b64encode(rrs_content.encode('utf-8')),'utf-8')
                self.inte_zone_default("default", sub_item, rrs_content)

    def addzone_init(self):
        ids = []
        addzone_list = self.inte_get_addzones()
        if addzone_list["resources"] != []:
            for item in addzone_list["resources"]:
                ids.append(item["name"])
            self.inte_delete_addzones(ids)

    def zone_init(self):
        ids = []
        zone_list = self.inte_get_zones()
        if zone_list["resources"] != []:
            for item in zone_list["resources"]:
                ids.append(item["name"])
            self.inte_delete_zones(ids)

    def sp_policy_init(self):
        ids = []
        policy_list = self.inte_get_sp_policy()
        if policy_list["resources"] != []:
            for item in policy_list["resources"]:
                ids.append(item["id"])
            self.inte_delete_sp_policy(ids)

    def userzone_init(self):
        ids = []
        userzone_list = self.inte_get_userzone()
        if userzone_list["resources"] != []:
            for item in userzone_list["resources"]:
                ids.append(item["name"])
            self.inte_delete_userzone(ids)

    def syncgroup_init(self):
        ids = []
        syncgroup_list = self.inte_get_syncgroup()
        if syncgroup_list["resources"] != []:
            for item in syncgroup_list["resources"]:
                ids.append(item["name"])
            self.inte_delete_syncgroup(ids)

    def gpool_init(self):
        ids = []
        gpool_list = self.inte_get_gpool()
        if gpool_list["resources"] != []:
            for item in gpool_list["resources"]:
                ids.append(item["name"])
            self.inte_delete_gpool(ids)

    def datacenter_init(self):
        ids = []
        datacenter_list = self.inte_get_datacenter()
        if datacenter_list["resources"] != []:
            for item in datacenter_list["resources"]:
                ids.append(item["name"])
            self.inte_delete_datacenter(ids)

    def env_init(self):
        self.write_log("Start initializing environment...")
        self.addzone_init()
        self.zone_init()
        self.sp_policy_init()
        self.userzone_init()
        self.syncgroup_init()
        self.gpool_init()
        self.datacenter_init()

    def execute(self):
        try:
            self.env_init()
            self.add_datacenter()
            self.add_gmember()
            self.add_syncgroup()
            self.add_region_member()
            self.add_pool()
            self.add_sp_policy()
            self.add_wideip()
            self.add_rrs_default()
            self.write_log("Configuration synchronization complete!")
        except Exception as e:
            self.write_log(e)
            os._exit(0)

def main():
    parser = optparse.OptionParser()
    parser.add_option("-s", "--hostname", dest = "hostname", help = "Hostname", metavar= "x.x.x.x")
    parser.add_option("-a", "--account", dest = "account", help = "F5's account", metavar = "default admin", default = "admin")
    parser.add_option("-p", "--passwd", dest = "passwd", help = "F5's password", metavar = "default admin", default = "admin")
    parser.add_option("-o", "--port", dest = "port", help = "F5's server port", metavar = "default 443", default = "443")
    parser.add_option("-z", "--server", dest = "server", help = "ZDNS's server IP", metavar = "x.x.x.x", default = "127.0.0.1")
    parser.add_option("-n", "--zaccount", dest = "zaccount", help = "ZDNS's account", metavar = "default admin", default = "admin")
    parser.add_option("-w", "--zpasswd", dest = "zpasswd", help = "ZDNS's password", metavar = "default admin", default = "admin")
    parser.add_option("-f", "--file", dest = "file", help = "Select a file to recovery", metavar = "ex: 2021-05-19 15:35:13", default = None)
    (options, args) = parser.parse_args()
    if options.server == None:
        parser.error("missing required arguments")
    if options.file == None:
        if options.hostname == None:
            parser.error("missing required arguments")
    if options.hostname != None and options.server != None:
        if len(options.hostname.split('.')) != 4 or len(options.server.split('.')) != 4:
            parser.error("invalid ip address")
    if options.file != None:
        if os.path.exists('%s' % options.file):
            pass
        else:
            parser.error("file is not exist")
    if os.path.exists('backup_data/'):
        pass
    else:
        os.system('mkdir backup_data/')
    config = ConfigManage(hostname=options.hostname, username=options.account, password=options.passwd, port=options.port, server_ip=options.server, zuername=options.zaccount, zpassword=options.zpasswd, file_name=options.file)
    if options.file != None:
        if len(os.popen("ps aux | grep soap_interface.py | grep -v grep | awk '{print $2}'").read().strip().split("\n")) != 1:
            parser.error("Synchronization process already exists")
        else:
            config.read_file()
            config.execute()
    else:
        if os.path.exists('backup_data/'):
            pass
        else:
            os.system('mkdir backup_data/')
        config.write_file()
        config.read_file()
        config.execute()

if __name__ == "__main__":
    main()
