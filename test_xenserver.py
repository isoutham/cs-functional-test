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
import time
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
from optparse import OptionParser
import ConfigParser

IS_VPC = True
IS_ISOLATED = False


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

    def failure(self, action=True):
        print "[FAIL]"
        if action:
            sys.exit(1)


class Communicate():

    class Firewall():
        """
        Keep a record of firewall rules and their states for testing
        (iso network)
        """
        def __init__(self):
            self.firewall = []

        def update(self, ip, sport, eport, state):
            struct = {
                "sport": int(sport),
                "eport": int(eport),
                "ip": ip,
                "state": state
            }
            val = self.search(struct)
            if val is not None:
                self.firewall[val] = struct
            else:
                self.firewall.append(struct)

        def get(self):
            return self.firewall

        def search(self, struct):
            for idx, val in enumerate(self.firewall):
                if self.firewall[idx]['sport'] == struct['sport'] and \
                   self.firewall[idx]['eport'] == struct['eport'] and \
                   self.firewall[idx]['ip'] == struct['ip']:
                    return idx
            return None

        def get_port_string(self, rule):
            if rule['sport'] == rule['eport']:
                return str(rule['sport'])
            else:
                return "%s:%s" % (rule['sport'], rule['eport'])

    def __init__(self, l):
        cdir = os.path.dirname(__file__)
        if cdir == '':
            cdir = '.'
        conf = "%s/%s" % (cdir, "test_xenserver.conf")
        self.config = ConfigParser.ConfigParser({"type": "vagrant",
                                                 "port": "22",
                                                 "vaghost": "xenserver"
                                                 })
        try:
            self.config.read(conf)
        except TypeError:
            print "Could not parse configuration file %s" % config
            sys.exit(1)
        except IOError as e:
            print "Could not open configuration file %s (%s %s)" % (conf, e.errno, e.strerror)
            sys.exit(1)
        else:
            type = self.config.get("General", "type")

        if type == "vagrant":
            self._setup_vagrant()

        if type == "ssh":
            self._setup_ssh()

        self.expect = {}
        self.firewall = []
        execute(self.copy_scripts)
        self.log = l
        self.fw = self.Firewall()

    def _setup_ssh(self):
        try:
            env.user = self.config.get("General", "user")
            env.hosts = self.config.get("General", "host")
            env.port = self.config.get("General", "port")
            env.key_filename = self.config.get("General", "identity")
        except ConfigParser.NoOptionError as e:
            print "Could not parse configuration file (%s)" % e
            sys.exit()
        else:
            env.shell = "/bin/bash -c"
            env.output_prefix = False
            fabric.state.output['running'] = False

    def _setup_vagrant(self):
        vagrant_host = self.config.get("General", "vaghost")
        env.user = 'vagrant'
        env.hosts = ['127.0.0.1']
        vagConfig = local('vagrant ssh-config %s' % vagrant_host, capture=True)
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
        with hide('output', 'running', 'warnings'), settings(quiet=True):
            put('testScripts', '/home/vagrant')

    def test_routers(self, routers, instances):
        self.master_count = 0
        tiers = []
        for router in routers:
            self.rip = router.linklocalip
            execute(self.install, router)
            execute(self.get_cmdline, router)
            execute(self.test_router, router)
            if router.nic[0].type == "Isolated":
                execute(self.check_isolated_acls, router)
            if self.is_master():
                self.master_count += 1
            for instance in instances:
                tiers.append(instance.nic[0].ipaddress)
                tiers.append(instance.nic[0].ipaddress)
                execute(self.ping, router, [instance.nic[0].ipaddress])
                execute(self.ping, router, [instance.name])
                execute(self.ssh, router, [instance.name])
            for instance in instances:
                execute(self.remping, router, instance.nic[0].ipaddress,
                        list(OrderedDict.fromkeys(tiers)))
        if self.is_redundant():
            self.log.ptest("Check that there is only one master")
            if self.master_count != 1:
                self.log.failure()
            self.log.success()

    def check_isolated_acls(self, router):
        for rule in self.fw.get():
            search = self.fw.get_port_string(rule)
            for port in range(int(rule['sport']), int(rule['eport'] + 1)):
                self.log.ptest(
                    "Testing Isolated network acl on router %s (port %s)"
                    % (router.linklocalip, port)
                )
                with hide(
                        'output', 'running', 'warnings'), settings(warn_only=True):
                    out = run(
                        "/bin/bash /home/vagrant/testScripts/iso_firewall.sh %s %s %s %s %s"
                        % (router.linklocalip, rule['ip'], port, rule['state'], search)
                    )
                    if "Returned 0" not in out:
                        self.log.failure()
                    else:
                        self.log.success()

    def remping(self, router, to, what):
        for address in what:
            self.log.ptest("Testing virtual machine ping from %s to %s" % (address, to))
            with hide('output', 'running', 'warnings'), settings(warn_only=True):
                out = run("/bin/bash /home/vagrant/testScripts/remping.sh %s %s %s" % (router.linklocalip, address, to))
                if address == to:
                    self.log.skipped()
                    continue
                if "Returned 0" not in out:
                    self.log.extra("Ping Failed")
                    self.what_to_expect('remping', False)
                else:
                    self.log.extra("Ping %s" % address)
                    self.what_to_expect('remping', True)

    def update_firewall(self, ip, sport, eport, state):
        self.fw.update(ip, sport, eport, state)

    def fw(self):
        return self.fw

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
            with hide('output', 'running', 'warnings'), settings(warn_only=True):
                out = run("/bin/bash /home/vagrant/testScripts/ping.sh %s %s" % (router.linklocalip, address))
                if "Returned 0" not in out:
                    self.log.extra("Ping Failed to %s" % address)
                    self.log.failure()
                self.log.extra("Ping %s" % address)
                self.log.success()

    def ssh(self, router, what, command='ls'):
        for address in what:
            self.log.ptest("Testing virtual machine ssh")
            with hide('output', 'running', 'warnings'), settings(warn_only=True):
                out = run("/bin/bash /home/vagrant/testScripts/ssh.sh %s %s %s" % (router.linklocalip, address, command))
                if "Returned 0" not in out:
                    self.log.extra("SSH Failed to %s" % address)
                    self.what_to_expect('ssh', False)
                else:
                    self.log.extra("SSH %s" % address)
                    self.what_to_expect('ssh', True)

    def install(self, router):
        with hide('output', 'running', 'warnings'), settings(warn_only=False):
            run("/bin/bash /home/vagrant/testScripts/install.sh %s" % router.linklocalip)

    def get_cmdline(self, router):
        with hide('output', 'running', 'warnings'), settings(warn_only=True):
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
        with hide('output', 'running', 'warnings'), settings(warn_only=True):
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
                self.to[dev]['ip'].append(IPNetwork(vals[1]))
                self.to[dev]['network'] = IPNetwork(self.to[dev]['ip'][0])
                self.to[dev]['up'] = up
                self.to[dev]['mac'] = mac
        for nic in router.nic:
            if nic is None:
                continue
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

    def get_gateway(self, nic):
        if nic.gateway is not None:
            return nic.gateway
        else:
            if self.is_redundant():
                return self.cmdline['config']['guestgw']
            else:
                return nic.ipaddress

    def check_gateway_guest(self, dev, nic):
        self.log.ptest("Checking gateway address on %s" % dev)
        gateway = self.get_gateway(nic)
        if not self.is_redundant():
            self.log.success()
            return
        if self.is_master():
            self.log.extra("master")
            if self.ip_in_list(gateway, nic.netmask, self.to[dev]['ip']):
                self.log.success()
            else:
                self.log.failure(True)
        else:
            self.log.extra("slave")
            if not self.ip_in_list(gateway, nic.netmask, self.to[dev]['ip']):
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
        if not self.ip_in_list(nic.ipaddress, nic.netmask, self.to[dev]['ip']):
            self.log.failure(True)
        self.log.success()


class RedVPCRouter():

    templateName = "tiny Linux"
    hypervisor = "XenServer"
    serviceOffering = "tinyOffering"

    def __init__(self, l, options):
        self.options = options
        self.log = l
        utils = CSUtils()
        conn = utils.getConnection()
        self.apiclient = CloudStackAPIClient(conn)
        self.get_zone()
        self.vms = []
        self.networks = []
        self.vpcs = []
        self.isolated = []

    def add_comm(self, comm):
        self.comm = comm

    def get_zone(self):
        self.log.ptest("Getting Zone info")
        cmd = listZones.listZonesCmd()
        ret = self.apiclient.listZones(cmd)

        if ret is None:
            self.log.extra("No zones")
            self.log.failure()

        for zone in ret:
            self.zone = zone
        self.log.success()

    def list_routers(self, rid='', is_vpc=IS_VPC):
        self.log.ptest("Finding routers")
        cmd = listRouters.listRoutersCmd()
        ret = self.apiclient.listRouters(cmd)
        rtrs = []
        if ret is None:
            self.log.extra("No routers found it has gone really wrong")
            self.log.failure()
        for router in ret:
            if is_vpc:
                if router.vpcid == rid:
                    rtrs.append(router)
            else:
                if router.networkdomain == rid:
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
        if self.vpc_off is None:
            self.log.extra("No VPC offering found with name %s" % name)
            self.log.failure()
        self.log.success()

    def list_network_offerings(self, name):
        cmd = listNetworkOfferings.listNetworkOfferingsCmd()
        ret = self.apiclient.listNetworkOfferings(cmd)
        for off in ret:
            if off.name == name:
                return off
        return None

    def set_isolated_offerings(self, name):
        self.log.ptest("Getting Isolated service offering")
        cmd = listNetworkOfferings.listNetworkOfferingsCmd()
        ret = self.apiclient.listNetworkOfferings(cmd)
        self.isolated_off = None
        for off in ret:
            if off.name == name:
                self.isolated_off = off
        if self.isolated_off is None:
            self.log.extra("No Isolated offering found with name %s" % name)
            self.log.failure()
        self.log.success()

    def list_templates(self, name):
        cmd = listTemplates.listTemplatesCmd()
        cmd.templatefilter = "all"
        cmd.name = name
        cmd.listAll = True
        cmd.zone = self.zone.id
        return self.apiclient.listTemplates(cmd)

    def list_instances(self):
        cmd = listVirtualMachines.listVirtualMachinesCmd()
        return self.apiclient.listVirtualMachines(cmd)

    def instance_exists(self, name):
        vms = self.list_instances()
        if vms is None:
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
                return t.id
        return False

    def list_vpc(self):
        cmd = listVPCs.listVPCsCmd()
        ret = self.apiclient.listVPCs(cmd)
        return ret

    def vpc_exists(self, name):
        vpcs = self.list_vpc()
        if vpcs is None:
            return False
        for vpc in vpcs:
            if vpc.name == name:
                return vpc
        return False

    def get_network(self, name):
        nets = self.list_networks()
        if nets is None:
            return None
        for net in nets:
            if net.name == name:
                return net
        return None

    def list_networks(self):
        cmd = listNetworks.listNetworksCmd()
        ret = self.apiclient.listNetworks(cmd)
        if ret is None:
            return None
        return ret

    def list_ips(self, net):
        self.ips = []
        cmd = listPublicIpAddresses.listPublicIpAddressesCmd()
        cmd.listAll = True
        ret = self.apiclient.listPublicIpAddresses(cmd)
        self.log.ptest("Getting public ips for network %s" % net)
        for ip in ret:
            if hasattr(ip, "associatednetworkname") and ip.associatednetworkname == net:
                self.ips.append(ip)
        if len(self.ips) > 0:
            self.log.success()
        else:
            self.log.extra("No public IP")
            self.log.failure()

    def get_acl(self, traffictype, action):
        cmd = listNetworkACLs.listNetworkACLsCmd()
        ret = self.apiclient.listNetworkACLs(cmd)
        if ret is None:
            self.log.extra("No Network ACLS found")
            self.log.failure()
        for acl in ret:
            if acl.traffictype == traffictype and acl.action == action:
                return acl

    def create_network(self, vpc, name, gateway, netmask):
        self.log.ptest("Creating network %s (%s)" % (name, gateway))
        vid = self.vpc_exists(vpc).id
        netname = "%s-%s" % (vpc, name)
        if not vid:
            self.log.extra("No vpc called %s" % vpc)
            self.log.failure(True)
        n = self.get_network(netname)
        if n is not None:
            self.log.extra("Network %s already exists" % netname)
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
        cmd.networkofferingid = self.list_network_offerings("DefaultIsolatedNetworkOfferingForVpcNetworks").id
        ret = self.apiclient.createNetwork(cmd)
        self.networks.append(ret.id)
        time.sleep(20)
        self.log.success()
        return ret

    def create_isolated_network(self, name, gw, mask):
        self.log.ptest("Creating Isolated Network %s (%s/%s)" % (name, gw, mask))
        cmd = listNetworks.listNetworksCmd()
        networks = self.apiclient.listNetworks(cmd)
        if networks is not None:
            for net in networks:
                if net.name == name:
                    self.networks.append(net.id)
                    self.log.extra("Exists")
                    self.log.success()
                    return
        cmd = createNetwork.createNetworkCmd()
        cmd.zoneid = self.zone.id
        cmd.name = name
        cmd.displaytext = name
        cmd.networkofferingid = self.isolated_off.id
        cmd.gateway = gw
        cmd.netmask = mask
        cmd.networkdomain = "%s.local" % name
        ret = self.apiclient.createNetwork(cmd)
        self.networks.append(ret.id)
        self.log.success()
        return ret.id

    def create_vpc(self, name, cidr):
        self.log.ptest("Creating Redundant VPC %s (%s)" % (name, cidr))
        vpc = self.vpc_exists(name)
        if vpc:
            self.log.extra("Already exists")
            self.log.success()
            self.vpcs.append(vpc.id)
            return vpc.id
        cmd = createVPC.createVPCCmd()
        cmd.name = name
        cmd.displaytext = name
        cmd.vpcofferingid = self.vpc_off.id
        cmd.zoneid = self.zone.id
        cmd.cidr = cidr
        # cmd.account = account
        # cmd.domainid = domainid
        # cmd.networkDomain = networkDomain
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
        self.log.ptest("Creating virtual machine %s in %s" % (name, network))
        v = self.instance_exists(name)
        if v:
            self.vms.append(v)
            self.log.extra("Already exists")
            self.log.success()
            return
        cmd = deployVirtualMachine.deployVirtualMachineCmd()
        cmd.name = name
        cmd.displayname = name
        cmd.zoneid = self.zone.id
        so = self.getServiceOffering(self.serviceOffering)
        if so is False:
            self.log.extra("Cannot find service Offering %s]" % self.serviceOffering)
            self.log.failure()
        cmd.serviceofferingid = so
        temp = self.list_templates(self.templateName)
        if temp is None:
            self.log.extra("Cannot find template %s" % self.templateName)
            self.log.failure()
        neto = self.get_network(network)
        if neto is None:
            self.log.extra("Cannot find network %s" % network)
            self.log.failure()
        cmd.networkids.append(neto.id)
        cmd.templateid = temp[0].id
        cmd.hypervisor = self.hypervisor
        ret = self.apiclient.deployVirtualMachine(cmd)
        self.vms.append(ret.id)
        time.sleep(20)
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
        if self.options.no_destroy:
            return
        self.log.ptest("Destroy virtual machine %s" % (id))
        cmd = destroyVirtualMachine.destroyVirtualMachineCmd()
        cmd.id = id
        cmd.expunge = True
        self.apiclient.destroyVirtualMachine(cmd)
        time.sleep(20)
        self.log.success()

    def destroy_network(self, id):
        if self.options.no_destroy:
            return
        self.log.ptest("Destroy network %s" % (id))
        cmd = deleteNetwork.deleteNetworkCmd()
        cmd.id = id
        cmd.expunge = True
        self.apiclient.deleteNetwork(cmd)
        time.sleep(20)
        self.log.success()

    def destroy_vpc(self, id):
        if self.options.no_destroy:
            return
        self.log.ptest("Detroying VPC %s" % id)
        cmd = deleteVPC.deleteVPCCmd()
        cmd.id = id
        ret = self.apiclient.deleteVPC(cmd)
        time.sleep(20)
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

    def list_firewall_rules(self, index, sport, eport):
        cmd = listFirewallRules.listFirewallRulesCmd()
        ret = self.apiclient.listFirewallRules(cmd)
        if ret is None:
            return ret
        for rule in ret:
            if rule.startport == str(sport) and rule.endport == str(eport) and self.ips[index].id == rule.ipaddressid:
                return rule
        return None

    def delete_firewall_rule(self, index, sport, eport):
        self.log.ptest("Deleting Firewall rule %s %s %s" % (self.ips[index].ipaddress, sport, eport))
        self.comm.update_firewall(self.ips[index].ipaddress, sport, eport, False)
        rule = self.list_firewall_rules(index, sport, eport)
        if rule is None:
            self.log.extra("Not There")
            self.log.success()
            return
        cmd = deleteFirewallRule.deleteFirewallRuleCmd()
        cmd.id = rule.id
        self.apiclient.deleteFirewallRule(cmd)
        self.log.success()

    def add_firewall_rule(self, index, sport, eport):
        self.log.ptest("Adding Firewall rule %s %s %s" % (self.ips[index].ipaddress, sport, eport))
        self.comm.update_firewall(self.ips[index].ipaddress, sport, eport, True)
        if self.list_firewall_rules(index, sport, eport) is not None:
            self.log.extra("Exists")
            self.log.success()
            return
        cmd = createFirewallRule.createFirewallRuleCmd()
        cmd.cidrlist = "0.0.0.0/0"
        cmd.protocol = "tcp"
        cmd.startport = sport
        cmd.endport = eport
        cmd.ipaddressid = self.ips[index].id
        self.apiclient.createFirewallRule(cmd)
        self.log.success()

    def enable_offering(self, off):
        self.log.ptest("Enabling network offering %s" % off.name)
        if off.state == "Enabled":
            self.log.extra("Already Enabled")
            self.log.success()
            return
        cmd = updateNetworkOffering.updateNetworkOfferingCmd()
        cmd.id = off.id
        cmd.state = "Enabled"
        self.apiclient.updateNetworkOffering(cmd)
        self.log.success()

    def add_redundant_service_offering(self, name="isored1"):
        self.log.ptest("Adding redundant isolated network offering (%s)" % name)
        off = self.list_network_offerings(name)
        if off is not None:
            self.log.extra("Exists")
            self.log.success()
            self.enable_offering(off)
            return off
        cmd = createNetworkOffering.createNetworkOfferingCmd()
        cmd.name = name
        cmd.displaytext = name
        cmd.ispersistent = "true"
        cmd.guestiptype = "Isolated"
        cmd.supportedservices = "Vpn,Dhcp,Dns,Firewall,Lb,SourceNat,StaticNat,PortForwarding"
        cmd.servicecapabilitylist = []
        cmd.servicecapabilitylist.append({
            "service": "SourceNat",
            "capabilitytype": "RedundantRouter",
            "capabilityvalue": "true"
            })
        cmd.servicecapabilitylist.append({
            "service": "SourceNat",
            "capabilitytype": "SupportedSourceNatTypes",
            "capabilityvalue": "peraccount"
            })
        cmd.servicecapabilitylist.append({
            "service": "lb",
            "capabilitytype": "SupportedLbIsolation",
            "capabilityvalue": "dedicated"
            })
        cmd.serviceproviderlist = []
        cmd.serviceproviderlist.append({"service": "Vpn", "provider": "VirtualRouter"})
        cmd.serviceproviderlist.append({"service": "Dhcp", "provider": "VirtualRouter"})
        cmd.serviceproviderlist.append({"service": "Dns", "provider": "VirtualRouter"})
        cmd.serviceproviderlist.append({"service": "Firewall", "provider": "VirtualRouter"})
        cmd.serviceproviderlist.append({"service": "Lb", "provider": "VirtualRouter"})
        cmd.serviceproviderlist.append({"service": "SourceNat", "provider": "VirtualRouter"})
        cmd.serviceproviderlist.append({"service": "StaticNat", "provider": "VirtualRouter"})
        cmd.serviceproviderlist.append({"service": "PortForwarding", "provider": "VirtualRouter"})
        cmd.traffictype = "GUEST"
        off = self.apiclient.createNetworkOffering(cmd)
        self.log.success()
        self.enable_offering(off)
        return off


class TestSets():

    ITERATIONS = 1

    def __init__(self, options):
        self.options = options

    def test_isolated(self):
        """
        Test isolated networks, single and redundant
        """
        iterations = self.ITERATIONS
        iso_offerings = ["DefaultIsolatedNetworkOfferingWithSourceNatService"]
        l = MyLogger()
        comm = Communicate(l)

        iso1 = RedVPCRouter(l, self.options)
        iso_offerings.append(iso1.add_redundant_service_offering().name)
        for off in iso_offerings:
            iso1.set_isolated_offerings(off)
            net1 = iso1.create_isolated_network("iso1", "172.16.1.1", "255.255.255.0")
            iso1.create_instance('iso1-vm1', "iso1")
            iso1.list_ips("iso1")
            iso1.add_comm(comm)
            # Create fw rule for public ip 0
            iso1.add_firewall_rule(0, 19, 19)
            comm.test_routers(iso1.list_routers("iso1.local", IS_ISOLATED), iso1.instances_in_network("iso1"))
            iso1.add_firewall_rule(0, 20, 22)
            iso1.add_firewall_rule(0, 23, 23)
            comm.test_routers(iso1.list_routers("iso1.local", IS_ISOLATED), [])
            iso1.delete_firewall_rule(0, 23, 23)
            comm.test_routers(iso1.list_routers("iso1.local", IS_ISOLATED), [])
            iso1.delete_firewall_rule(0, 20, 22)
            comm.test_routers(iso1.list_routers("iso1.local", IS_ISOLATED), [])
            iso1.create_instance('iso1-vm2', "iso1")
            comm.test_routers(iso1.list_routers("iso1.local", IS_ISOLATED), iso1.instances_in_network("iso1"))
            iso1.destroy_all()

    def test_vpc(self):

        offerings = ["Default VPC offering", "Redundant VPC offering"]
        offerings = ["Redundant VPC offering"]
        iterations = self.ITERATIONS
        l = MyLogger()
        comm = Communicate(l)

        for vpc_off in offerings:
            def1 = RedVPCRouter(l, self.options)
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
                # net2 = def1.get_network("def1-tier2")
                # if net2 is not None:
                # def1.replace_acl(acl, net2)
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

parser = OptionParser()
parser.add_option("-v", "--vpc",
                  action="store_true", default=False, dest="vpc",
                  help="Perform vpc tests")
parser.add_option("-i", "--isolated",
                  action="store_true", default=False, dest="isolated",
                  help="Perform isolated tests")
parser.add_option("-d", "--no-destroy",
                  action="store_true", default=False, dest="no_destroy",
                  help="Do not destroy environment on exit")

(options, args) = parser.parse_args()
if options.vpc:
    TestSets(options).test_vpc()

if options.isolated:
    TestSets(options).test_isolated()

sys.exit()
