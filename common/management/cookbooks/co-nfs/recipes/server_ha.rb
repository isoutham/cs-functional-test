#
# Cookbook Name:: co-nfs
# Recipe:: server_ha 
#
# Copyright 2013, Matthieu Serrepuy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include_recipe "co-nfs"
include_recipe "co-corosync"
include_recipe "co-pacemaker"
include_recipe "co-open-iscsi"

# Install server components for Debian
case node["platform"]
when "debian","ubuntu"
  package "nfs-kernel-server"
  package "lvm2"
end

# Disable nfs-server service
service node['nfs']['service']['server'] do
  action [ :stop, :disable ]
end

# Configure nfs-server components
template node['nfs']['config']['server_template'] do
  mode 0644
  #notifies :restart, resources(:service => node['nfs']['service']['server'])
end

# Configure pacemaker component for nfs server
template "/etc/corosync/pacemaker4chef.conf" do
  mode 0644
  source "pacemaker4chef.conf.erb"
  #notifies :restart, resources(:service => node['nfs']['service']['server'])
end
