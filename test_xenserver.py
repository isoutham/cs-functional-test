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
import fabric
from fabric.api import env, local, run, execute, put, hide, settings
from netaddr import *
from collections import OrderedDict

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

class MyLogger():

    def __init__(self):
        self.section = 0

    def start_section(self, name):
        print name
        self.section += 1

    def end_section(self):
        self.section -= 1

    def ptest(self, mssge):
        preamble = ''
        for i in range(0, self.section):
            preamble += '\t'

        print "%s%s" % (preamble, mssge),

    def extra(self, mssge):
        print "[%s]" % mssge,

    def success(self):
        print "[OK]"

    def skipped(self):
        print "[SKIPPED]"

    def failure(self, action = True):
        print "[FAIL]"
        if action:
            sys.exit(1)

class Communicate():

    def __init__(self, l, type = "vagrant"):
        if type == "vagrant":
            self._setup_vagrant()
        self.expect = {}
        execute(self.copy_scripts)
        self.log = l

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
        env.output_prefix = False
        fabric.state.output['running'] = False

    def copy_scripts(self):
        with hide('output','running','warnings'), settings(quiet=True):
            put('testScripts', '/home/vagrant')

    def test_routers(self, routers, instances):
        self.master_count = 0
        tiers = []
        for router in routers:
            self.rip = router.linklocalip
            execute(self.install, router)
            execute(self.get_cmdline, router)
            execute(self.test_router, router)
            if self.is_master():
                self.master_count += 1
            for instance in instances:
                tiers.append(instance.nic[0].ipaddress)
                tiers.append(instance.nic[0].ipaddress)
                execute(self.ping, router, [instance.nic[0].ipaddress] )
                execute(self.ping, router, [instance.name] )
                execute(self.ssh, router, [instance.name] )
            for instance in instances:
                execute(self.remping, router, instance.nic[0].ipaddress, list(OrderedDict.fromkeys(tiers)))
        if self.is_redundant():
            self.log.ptest("Check that there is only one master")
            if self.master_count != 1:
                self.log.failure()
            self.log.success()

    def remping(self, router, to, what):
        for address in what:
            self.log.ptest("Testing virtual machine ping from %s to %s" % (address, to))
            with hide('output','running','warnings'), settings(warn_only=True):
                out = run("/bin/bash /home/vagrant/testScripts/remping.sh %s %s %s" % (router.linklocalip, address, to))
                if address == to:
                    self.log.skipped()
                    continue
                if not "Returned 0" in out:
                    self.log.extra("Ping Failed")
                    self.what_to_expect('remping', False)
                else:
                    self.log.extra("Ping %s" % address)
                    self.what_to_expect('remping', True)

    def what_to_expect(self, test, passed):
        reply = True
        if test in self.expect:
            reply = self.expect[test] 
        if reply and passed:
            self.log.success()
        if reply and not passed:
            self.log.failure()
        if not reply and not passed:
            self.log.success()
        if reply and not passed:
            self.log.failure()

    def set_expect(self, test, what):
        self.expect[test] = what
        if what:
            str = "Setting test %s to expect success" % test
        else:
            str = "Setting test %s to expect failure" % test
        self.log.ptest(str)
        self.log.success()

    def ping(self, router, what):
        for address in what:
            self.log.ptest("Testing virtual machine ping")
            with hide('output','running','warnings'), settings(warn_only=True):
                out = run("/bin/bash /home/vagrant/testScripts/ping.sh %s %s" % (router.linklocalip, address))
                if not "Returned 0" in out:
                    self.log.extra("Ping Failed to %s" % address)
                    self.log.failure()
                self.log.extra("Ping %s" % address)
                self.log.success()

    def ssh(self, router, what, command='ls'):
        for address in what:
            self.log.ptest("Testing virtual machine ssh")
            with hide('output','running','warnings'), settings(warn_only=True):
                out = run("/bin/bash /home/vagrant/testScripts/ssh.sh %s %s %s" % (router.linklocalip, address, command))
                if not "Returned 0" in out:
                    self.log.extra("SSH Failed to %s" % address)
                    self.what_to_expect('ssh', False)
                else:
                    self.log.extra("SSH %s" % address)
                    self.what_to_expect('ssh', True)

    def install(self, router):
        with hide('output','running','warnings'), settings(warn_only=False):
            run("/bin/bash /home/vagrant/testScripts/install.sh %s" % router.linklocalip)

    def get_cmdline(self, router):
        with hide('output','running','warnings'), settings(warn_only=True):
            out = run("/bin/bash /home/vagrant/testScripts/get_cmdline.sh %s" % router.linklocalip)
        self.log.ptest("Fetching Command line from router")
        try:
            self.cmdline = json.loads(out)
        except ValueError:
            self.log.extra("Cmdline json file from %s cannot be parsed" % router.name)
            self.log.failure()
        else:
            self.log.success()

    def is_redundant(self):
        if "redundant_router" not in self.cmdline['config']:
            return False
        return self.cmdline['config']['redundant_router'] == "true"

    def is_master(self):
        if not self.is_redundant():
            return True
        if "redundant_state" not in self.cmdline['config']:
            return False
        return self.cmdline['config']['redundant_state'] == "MASTER"

    def test_router(self, router):
        with hide('output','running','warnings'), settings(warn_only=True):
            out = run("/bin/bash /home/vagrant/testScripts/test_router.sh %s" % router.linklocalip)
        list = []
        up = False
        mac = ''
        self.to = {}
        for line in out.split('\n'):
            vals = line.strip().lstrip().rstrip().split()
            if line[0].isdigit():
                up = "state UP" in line
       	    if vals[0] == "link/ether":
                mac = vals[1]
       	    if vals[0] == "inet":
                dev = vals[-1]
                if dev not in self.to:
                    self.to[dev] = {}
                    self.to[dev]['ip'] = []
                self.to[dev]['ip'].append( IPNetwork(vals[1]))
                self.to[dev]['network'] = IPNetwork(self.to[dev]['ip'][0])
                self.to[dev]['up'] = up
                self.to[dev]['mac'] = mac
        for nic in router.nic:
            device = self.get_device(nic)
            if nic.traffictype == "Public":
                self.compare_device(device, nic)
                self.check_redundant_public(device, nic)
            if nic.traffictype == "Guest":
                self.compare_device(device, nic)
                self.check_redundant_guest(device, nic)
                self.check_gateway_guest(device, nic)

    def get_device(self, nic):
        self.log.ptest("Finding device name for mac address %s" % nic.macaddress)
        for dev in self.to:
            if self.to[dev]['mac'] == nic.macaddress:
                self.log.success()
                return dev
        self.log.failure(True)

    def compare_device(self, dev, nic):
        self.log.ptest("Checking device %s is present" % dev)
        if dev not in self.to:
            self.log.extra("Device %s not found and should be there" % dev)
            self.log.failure(True)
        self.log.success()

    def check_gateway_guest(self, dev, nic):
        self.log.ptest("Checking gateway address on %s" % dev)
        if not self.is_redundant():
            self.log.success()
            return
        if self.is_master():
            self.log.extra("master")
            if self.ip_in_list(nic.gateway, nic.netmask, self.to[dev]['ip']):
               self.log.success() 
            else:
               self.log.failure(True)
        else:
            self.log.extra("slave")
            if not self.ip_in_list(nic.gateway, nic.netmask, self.to[dev]['ip']):
               self.log.success() 
            else:
               self.log.failure(True)

    def ip_in_list(self, ip, mask, list):
        ipo = IPNetwork(ip + '/' + mask)
        for ip in list:
            if str(ipo) == str(ip):
                return True
        return False

    def check_redundant_guest(self, dev, nic):
        self.log.ptest("Checking Interface is UP %s" % dev)
        if not self.to[dev]['up']:
             self.log.failure(True)
        self.log.success()

    def check_redundant_public(self, dev, nic):
        self.log.ptest("Checking Interface is in correct state (master/backup) %s" % dev)
        if not self.is_redundant():
            self.log.extra("Not redundanmt")
            if not self.to[dev]['up']:
                self.log.failure(True)
        if self.is_master():
            if not self.to[dev]['up']:
                self.log.failure(True)
        else:
            if self.to[dev]['up']:
                self.log.failure(True)
        self.log.success()
        self.log.ptest("Is IP and netmask correct")
        if self.ip_in_list(nic.gateway, nic.netmask, self.to[dev]['ip']):
            self.log.failure(True)
        self.log.success()

class RedVPCRouter():

    templateName = "tiny Linux"
    hypervisor   = "XenServer"
    serviceOffering = "tinyOffering"

    def __init__(self, l):
        self.log = l
        utils = CSUtils()  
        conn = utils.getConnection()
        self.apiclient = CloudStackAPIClient(conn)
        self.get_zone()
        self.vms  = []
        self.networks = []
        self.vpcs = []

    def get_zone(self):
        self.log.ptest("Getting Zone info")
        cmd = listZones.listZonesCmd()
        ret = self.apiclient.listZones(cmd)

        if ret == None:
            self.log.extra("No zones")
            self.log.failure()

        for zone in ret:
            self.zone = zone
        self.log.success()

    def list_routers(self, rid = ''):
        self.log.ptest("Finding routers")
        cmd = listRouters.listRoutersCmd()
        ret = self.apiclient.listRouters(cmd)
        rtrs = []
        if ret is None:
            self.log.extra("No routers found it has gone really wrong")
            self.log.failure()
        for router in ret:
            if router.vpcid == rid:
                rtrs.append(router)
        self.log.success()
        return rtrs

    def set_vpc_offerings(self, name):
        self.log.ptest("Getting VPC service offering")
        cmd = listVPCOfferings.listVPCOfferingsCmd()
        ret = self.apiclient.listVPCOfferings(cmd)
        self.vpc_off = None
        for off in ret:
            if off.displaytext == name:
                self.vpc_off = off
        if self.vpc_off == None:
            self.log.extra("No VPC offering found with name %s" % name)
            self.log.failure()
        self.log.success()

    def list_network_offerings(self, name):
        cmd = listNetworkOfferings.listNetworkOfferingsCmd()
        ret = self.apiclient.listNetworkOfferings(cmd)
        for off in ret:
            if off.name == name:
                return off.id
        self.log.extra("Cannot find network offering %s" % name)
        self.log.failure()

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
            self.log.extra("No Network ACLS found")
            self.log.failure()
        for acl in ret:
            if acl.traffictype == traffictype and acl.action == action:
                return acl

    def create_network(self, vpc, name, gateway, netmask):
        self.log.ptest("Creating network %s (%s)" % (name,gateway))
        vid = self.vpc_exists(vpc).id
        netname = "%s-%s" % (vpc, name)
        if not vid:
            print "No vpc called %s" % vpc,
            self.log.failure(True)
        n = self.get_network(netname)
        if n is not None:
            print "[Network %s already exists]" % netname,
            self.networks.append(n.id)
            self.log.success()
            return n
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
        self.log.success()
        return ret

    def create_vpc(self, name, cidr):
        self.log.ptest("Creating Redundant VPC %s (%s)" % (name,cidr))
        vpc = self.vpc_exists(name)
        if vpc:
            print "[Already exists]",
            self.log.success()
            self.vpcs.append(vpc.id)
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
        self.vpcs.append(ret.id)
        self.log.success()
        return ret.id

    def list_acls(self, name):
        cmd = listNetworkACLLists.listNetworkACLListsCmd()
        ret = self.apiclient.listNetworkACLLists(cmd)
        for acl in ret:
            if acl.name == name:
                return acl
        return None

    def create_acl_list(self, name, vid):
        self.log.ptest("Creating acl list %s" % name)
        acl = self.list_acls(name)
        if acl is None:
            cmd = createNetworkACLList.createNetworkACLListCmd()
            cmd.vpcid = vid
            cmd.name = name
            cmd.description = name
            acl = self.apiclient.createNetworkACLList(cmd)
            self.log.success()
        else:
            self.log.extra("exists")
            self.log.skipped()
        return acl

    def add_acl_rule(self, number, acl, port, direction):
        self.log.ptest("Adding %s rule for port %s" % (direction, port))
        cmd = listNetworkACLs.listNetworkACLsCmd()
        cmd.aclid = acl.id
        ret = self.apiclient.listNetworkACLs(cmd)
        if ret is not None:
            for rule in ret:
                if rule.number == number:
                    self.log.extra("Exists")
                    self.log.skipped()
                    return
        cmd = createNetworkACL.createNetworkACLCmd()
        cmd.aclid = acl.id
        cmd.startport = port
        cmd.endport = port
        cmd.cidrlist = ''
        cmd.number = number
        cmd.traffictype = direction
        cmd.protocol = 'tcp'
        self.apiclient.createNetworkACL(cmd)
        self.log.success()

    def replace_acl(self, acl, net):
        self.log.ptest("Setting acl on %s to %s" % (net.name, acl.name))
        cmd = replaceNetworkACLList.replaceNetworkACLListCmd()
        cmd.networkid = net.id
        cmd.aclid = acl.id
        self.apiclient.replaceNetworkACLList(cmd)
        self.log.success()

    def create_instance(self, name, network):
        self.log.ptest("Creating virtual machine %s in %s" % (name,network))
        v = self.instance_exists(name)
        if v:
            self.vms.append(v)
            print "[Already exists]",
            self.log.success()
            return
        cmd = deployVirtualMachine.deployVirtualMachineCmd()
        cmd.name = name
        cmd.displayname = name
        cmd.zoneid = self.zone.id
        so = self.getServiceOffering(self.serviceOffering)
        if so == False:
            print "[Cannot find service Offering %s]" % self.serviceOffering,
            self.log.failure()
        cmd.serviceofferingid = so
        temp = self.list_templates(self.templateName)
        if temp is None:
            print "[Cannot find template %s]" % self.templateName,
            self.log.failure()
        neto = self.get_network(network)
        if neto is None:
            print "[Cannot find network %s]" % network,
            self.log.failure()
        cmd.networkids.append(neto.id)
        cmd.templateid = temp[0].id
        cmd.hypervisor = self.hypervisor
        ret = self.apiclient.deployVirtualMachine(cmd)
        self.vms.append(ret.id)
        self.log.success()

    def instances_in_network(self, name):
        instances = []
        self.log.ptest("Getting virtual machines in %s" % name)
        for inst in self.list_instances():
            for nic in inst.nic:
                if nic.networkname.startswith(name):
                    instances.append(inst)
        self.log.extra("[Found %s]" % len(instances))
        self.log.success()
        return instances

    def destroy_instance(self, id):
        self.log.ptest("Destroy virtual machine %s" % (id))
        cmd = destroyVirtualMachine.destroyVirtualMachineCmd()
        cmd.id = id
        cmd.expunge = True
        self.apiclient.destroyVirtualMachine(cmd)
        self.log.success()

    def destroy_network(self, id):
        self.log.ptest("Destroy network %s" % (id))
        cmd = deleteNetwork.deleteNetworkCmd()
        cmd.id = id
        cmd.expunge = True
        self.apiclient.deleteNetwork(cmd)
        self.log.success()

    def destroy_vpc(self, id):
        self.log.ptest("Detroying VPC %s" % id)
        cmd = deleteVPC.deleteVPCCmd()
        cmd.id = id
        ret = self.apiclient.deleteVPC(cmd)
        self.log.success()

    def destroy_all_vpcs(self):
        for id in self.vpcs:
            self.destroy_vpc(id)

    def destroy_all(self):
        for id in self.vms:
            self.destroy_instance(id)
        for id in self.networks:
            self.destroy_network(id)
        self.vms = []
        self.networks = []



iterations = 1
offerings = [ "Default VPC offering", "Redundant VPC offering" ]
offerings = [ "Redundant VPC offering" ]
l = MyLogger()
comm = Communicate(l)

for vpc_off in offerings:
    def1 = RedVPCRouter(l)
    for iteration in range(0, iterations):
        l.start_section("Testing %s (iteration %s)" % (vpc_off, iteration))
        # Set the remping test to expect success
        comm.set_expect("remping", True)
        def1.set_vpc_offerings(vpc_off)
        vid = def1.create_vpc("def1", "192.168.0.0/16")
        comm.test_routers(def1.list_routers(vid), [])
   
        net1 = def1.create_network("def1", "tier1", "192.168.1.1", "255.255.255.0")
        acl = def1.list_acls('default_allow')
        def1.replace_acl(acl, net1)
        def1.create_instance('def1-tier1-vm1', "def1-tier1")
        #net2 = def1.get_network("def1-tier2")
        #if net2 is not None:
            #def1.replace_acl(acl, net2)
        comm.test_routers(def1.list_routers(vid), def1.instances_in_network("def1-tier1"))

        net2 = def1.create_network("def1", "tier2", "192.168.2.1", "255.255.255.0")
        def1.replace_acl(acl, net2)
        def1.create_instance('def1-tier2-vm1', "def1-tier2")
        comm.test_routers(def1.list_routers(vid), def1.instances_in_network("def1-tier"))
    
        # Set the remping test to expect failure as the new acl should block ping
        comm.set_expect("remping", False)
        acl1 = def1.create_acl_list("def1-acl1", vid)
        def1.add_acl_rule(1, acl1, '22', 'Ingress')
        def1.add_acl_rule(2, acl1, '22', 'Egress')
        def1.replace_acl(acl1, net1)
        def1.replace_acl(acl1, net2)
        comm.test_routers(def1.list_routers(vid), def1.instances_in_network("def1-tier"))

        # ssh should now also fail
        comm.set_expect("ssh", False)
        acl2 = def1.list_acls('default_deny')
        def1.replace_acl(acl2, net1)
        def1.replace_acl(acl2, net2)
        comm.test_routers(def1.list_routers(vid), def1.instances_in_network("def1-tier"))

        def1.destroy_all()
        l.end_section()
    def1.destroy_all_vpcs()

for iteration in range(0, 50):
    l.start_section("Soak test vm creation and destruction (iteration %s)" % (iteration))
    net1 = def1.create_network("def1", "tier1", "192.168.1.1", "255.255.255.0")
    acl = def1.list_acls('default_allow')
    def1.replace_acl(acl, net1)
    def1.create_instance('def1-tier1-vm1', "def1-tier1")
    l.end_section()

sys.exit()

