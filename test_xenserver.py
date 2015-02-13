import urllib
import os
import sys
import xml.dom.minidom
import re
import base64
import hmac
import hashlib
import httplib
import time
import marvin
import json
import urllib
import urllib2
import logging
import time
import StringIO
import json
from fabric.api import env, local, run, execute, put, hide
from netaddr import *

from marvin.asyncJobMgr import asyncJobMgr
from marvin.codes import (FAILED, PASS, ADMIN, DOMAIN_ADMIN,
                          USER, SUCCESS, XEN_SERVER)
from marvin.dbConnection import DbConnection
from marvin.cloudstackAPI import *
from marvin.cloudstackAPI.cloudstackAPIClient import CloudStackAPIClient
from marvin.cloudstackException import CloudstackAPIException
from marvin.cloudstackException import GetDetailExceptionInfo
from marvin.cloudstackConnection import CSConnection
from marvin.configGenerator import ConfigManager
from marvin.lib.utils import (random_gen, validateList)


from CSUtils import *
from pprint import pprint

def ptest(mssge):
    print mssge,

def success():
    print "[OK]"

def failure(action):
    print "[FAIL]"
    if action:
        sys.exit(1)

class Communicate():

    def __init__(self, type = "vagrant"):
        if type == "vagrant":
            self._setup_vagrant()
        execute(self.copy_scripts)

    def _setup_vagrant(self):
        env.user = 'vagrant'
        env.hosts = ['127.0.0.1',] 
        vagConfig = local('vagrant ssh-config xenserver', capture=True)
        s = StringIO.StringIO(vagConfig)
        for line in s:
            if 'Port' in line:
                ssh_port = line.split()[1]
                env.port = ssh_port
            if 'IdentityFile' in line:
                env.key_filename = line.split()[1]
        env.shell = "/bin/bash -c"

    def copy_scripts(self):
        with hide('output','running','warnings'):
            put('testScripts', '/home/vagrant')

    def test_routers(self, obj):
        for router in obj:
            self.rip = router.linklocalip
            execute(self.get_cmdline, router)
            execute(self.test_router, router)

    def get_cmdline(self, router):
        with hide('output','running','warnings'):
            out = run("/bin/bash /home/vagrant/testScripts/get_cmdline.sh %s" % router.linklocalip)
        ptest("Fetching Command line from router")
        try:
            self.cmdline = json.loads(out)
        except ValueError:
            print "Cmdline json file from %s cannot be parsed" % router.name
            sys.exit(0)
            failure()
        else:
            success()

    def is_master(self):
        if "redundant_state" not in self.cmdline['config']:
            return False
        return self.cmdline['config']['redundant_state'] == "MASTER"

    def test_router(self, router):
        with hide('output','running','warnings'):
            out = run("/bin/bash /home/vagrant/testScripts/test_router.sh %s" % router.linklocalip)
        list = []
        up = False
        self.to = {}
        for line in out.split('\n'):
            vals = line.strip().lstrip().rstrip().split()
            if line[0].isdigit():
                up = "state UP" in line
       	    if vals[0] == "inet":
                dev = vals[-1]
                self.to[dev] = {}
                self.to[dev]['ip'] = IPNetwork(vals[1])
                self.to[dev]['network'] = IPNetwork(self.to[dev]['ip'])
                self.to[dev]['up'] = up
        for nic in router.nic:
            if nic.traffictype == "Public":
                self.compare_device("eth1", nic)
                self.check_redundant_public("eth1", nic)

    def compare_device(self, dev, nic):
        ptest("Checking device %s is present" % dev)
        if dev not in self.to:
            print "FAIL:  Device %s not found and should be there" % dev
            failure(True)
        success()

    def check_redundant_public(self, dev, nic):
        ptest("Checking Interface is in correct state (master/backup) %s" % dev)
        if self.is_master():
            if not self.to[dev]['up']:
                failure(True)
        else:
            if self.to[dev]['up']:
                failure(True)
        success()
        ipo = IPNetwork(nic.ipaddress + '/' + nic.netmask)
        ptest("Is IP and netmask correct")
        if ipo != self.to[dev]['ip']:
            failure(True)
        success()

class RedVPCRouter():

    templateName = "tiny Linux"
    hypervisor   = "XenServer"
    serviceOffering = "tinyOffering"

    def __init__(self):
        utils = CSUtils()  
        conn = utils.getConnection()
        self.apiclient = CloudStackAPIClient(conn)
        self.get_zone()
        self.vms  = []
        self.networks = []
        self.vpns = []

    def get_zone(self):
        cmd = listZones.listZonesCmd()
        ret = self.apiclient.listZones(cmd)

        if ret == None:
            print "No zones"
            sys.exit(1)

        for zone in ret:
            self.zone = zone

    def list_routers(self, rid = ''):
        cmd = listRouters.listRoutersCmd()
        ret = self.apiclient.listRouters(cmd)
        rtrs = []
        if ret is None:
            print "No routers found it has gone really wrong"
            sys.exit(1)
        for router in ret:
            if router.vpcid == rid:
                rtrs.append(router)
        return rtrs

    def list_vpc_offerings(self, name):
        cmd = listVPCOfferings.listVPCOfferingsCmd()
        ret = self.apiclient.listVPCOfferings(cmd)
        self.vpc_off = None
        for off in ret:
            if off.displaytext == "Redundant VPC offering":
                self.vpc_off = off
        if self.vpc_off == None:
            print "No VPC offering found with name %s" % name
            sys.exit(1)

    def list_network_offerings(self, name):
        cmd = listNetworkOfferings.listNetworkOfferingsCmd()
        ret = self.apiclient.listNetworkOfferings(cmd)
        for off in ret:
            if off.name == name:
                return off.id
        print "Cannot find network offering %s" % name
        sys.exit(1)

    def list_templates(self, name):
        cmd = listTemplates.listTemplatesCmd()
        cmd.templatefilter="all"
        cmd.name=name
        cmd.listAll=True
        cmd.zone=self.zone.id
        return self.apiclient.listTemplates(cmd)

    def list_instances(self):
        cmd = listVirtualMachines.listVirtualMachinesCmd()
        return self.apiclient.listVirtualMachines(cmd)

    def instance_exists(self, name):
        vms = self.list_instances()
        if vms == None:
            return False
        for vm in vms:
            if vm.name == name:
                return vm.id
        return False

    def getServiceOffering(self, name):
        cmd = listServiceOfferings.listServiceOfferingsCmd()
        ret = self.apiclient.listServiceOfferings(cmd)
        for t in ret:
            if t.name.startswith(name):
               return  t.id
        return False

    def list_vpc(self):
        cmd = listVPCs.listVPCsCmd()
        ret = self.apiclient.listVPCs(cmd)
        return ret

    def vpc_exists(self, name):
        vpcs = self.list_vpc()
        if vpcs == None:
            return False
        for vpc in vpcs:
            if vpc.name == name:
                return vpc
        return False

    def get_network(self, name):
        nets = self.list_networks()
        if nets == None:
            return None
        for net in nets:
            if net.name == name:
                return net
        return None

    def list_networks(self):
        cmd = listNetworks.listNetworksCmd()
        ret = self.apiclient.listNetworks(cmd)
        if ret == None:
            return None
        return ret

    def get_acl(self, traffictype, action):
        cmd = listNetworkACLs.listNetworkACLsCmd()
        ret = self.apiclient.listNetworkACLs(cmd)
        if ret == None:
            print "No Network ACLS found"
            sys.exit(1)
        for acl in ret:
            if acl.traffictype == traffictype and acl.action == action:
                return acl

    def create_network(self, vpc, name, gateway, netmask):
        print "Creating network %s (%s)" % (name,gateway)
        vid = self.vpc_exists(vpc).id
        netname = "%s-%s" % (vpc, name)
        if not vid:
            print "No vpc called %s" % vpc
            sys.exit(1)
        n = self.get_network(netname)
        if n is not None:
            self.networks.append(n.id)
            return
        cmd = createNetwork.createNetworkCmd()
        cmd.zoneid = self.zone.id
        cmd.name = netname
        cmd.displaytext = netname
        cmd.gateway = gateway
        cmd.netmask = netmask
        cmd.vpcid = vid
        cmd.aclid = self.get_acl("Egress", "Allow").aclid
        cmd.networkofferingid = self.list_network_offerings("DefaultIsolatedNetworkOfferingForVpcNetworks")
        ret = self.apiclient.createNetwork(cmd)
        self.networks.append(ret.id)

    def create_red_vpc(self, name, cidr):
        print "Creating Redundant VPC %s (%s)" % (name,cidr)
        vpc = red1.vpc_exists(name)
        if vpc:
            self.vpns.append(vpc.id)
            return vpc.id
        cmd = createVPC.createVPCCmd()
        cmd.name = name
        cmd.displaytext = name
        cmd.vpcofferingid = self.vpc_off.id
        cmd.zoneid = self.zone.id
        cmd.cidr = cidr
        #cmd.account = account
        #cmd.domainid = domainid
        #cmd.networkDomain = networkDomain
        ret = self.apiclient.createVPC(cmd)
        self.vpns.append(ret.id)
        return ret.id

    def create_instance(self, name, network):
        print "Creating virtual machine %s in %s" % (name,network)
        v = red1.instance_exists(name)
        if v:
            self.vms.append(v)
            return
        cmd = deployVirtualMachine.deployVirtualMachineCmd()
        cmd.name = name
        cmd.displayname = name
        cmd.zoneid = self.zone.id
        so = self.getServiceOffering(self.serviceOffering)
        if so == False:
            print "Cannot find service Offering %s" % self.serviceOffering
            sys.exit(1)
        cmd.serviceofferingid = so
        temp = self.list_templates(self.templateName)
        if temp is None:
            print "Cannot find template %s" % self.templateName
            sys.exit(1)
        neto = self.get_network(network)
        if neto is None:
            print "Cannot find network %s" % network
            sys.exit(1)
        cmd.networkids.append(neto.id)
        cmd.templateid = temp[0].id
        cmd.hypervisor = self.hypervisor
        ret = self.apiclient.deployVirtualMachine(cmd)
        self.vms.append(ret.id)

    def destroy_instance(self, id):
        print "Destroy virtual machine %s" % (id)
        cmd = destroyVirtualMachine.destroyVirtualMachineCmd()
        cmd.id = id
        cmd.expunge = True
        self.apiclient.destroyVirtualMachine(cmd)

    def destroy_network(self, id):
        print "Destroy network %s" % (id)
        cmd = deleteNetwork.deleteNetworkCmd()
        cmd.id = id
        cmd.expunge = True
        self.apiclient.deleteNetwork(cmd)

    def destroy_all(self):
        for id in self.vms:
            self.destroy_instance(id)
        for id in self.networks:
            self.destroy_network(id)

red1 = RedVPCRouter()
comm = Communicate()
#sys.exit()
red1.list_vpc_offerings("Redundant VPC offering")
vid = red1.create_red_vpc("red1", "172.16.0.0/16")
comm.test_routers(red1.list_routers(vid))
sys.exit()
red1.create_network("red1", "tier1", "172.16.1.1", "255.255.255.0")
#red1.create_network("red1", "tier2", "172.16.2.1", "255.255.255.0")
red1.create_instance('red1-tier1-vm1', "red1-tier1")
#red1.create_instance('red1-tier2-vm1', "red1-tier2")

#time.sleep(10)
#red1.destroy_all()
