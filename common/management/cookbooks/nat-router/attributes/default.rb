#
# Cookbook Name:: nat-router
# Attributes:: default
#

default['iptables']['enable_forwarding'] = '1'
default['iptables']['wan'] = 'eth0'
default['iptables']['lans'] = ['eth1']